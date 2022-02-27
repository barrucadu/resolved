pub mod protocol;
pub mod resolver;
pub mod settings;

use bytes::BytesMut;
use std::env;
use std::io;
use std::process;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::protocol::{ConsumableBuffer, Message};
use crate::resolver::{resolve, ResolvedRecord};
use crate::settings::Settings;

async fn resolve_and_build_response(settings: &Settings, query: Message) -> Message {
    let mut response = query.make_response();
    response.header.recursion_available = true;
    response.header.is_authoritative = true;

    for question in &query.questions {
        for rr in resolve(
            query.header.recursion_desired,
            &settings.upstream_nameservers,
            settings,
            &(),
            question,
        )
        .await
        {
            match rr {
                ResolvedRecord::Authoritative { mut rrs } => response.answers.append(&mut rrs),
                ResolvedRecord::NonAuthoritative { mut rrs, authority } => {
                    response.answers.append(&mut rrs);
                    if let Some(rr) = authority {
                        response.authority.push(rr);
                    }
                    response.header.is_authoritative = false;
                }
            }
        }
    }

    response.questions = query.questions;
    response.header.qdcount = query.header.qdcount;

    // TODO: remove use of unwrap
    response.header.qdcount = response.questions.len().try_into().unwrap();
    response.header.ancount = response.answers.len().try_into().unwrap();
    response.header.nscount = response.authority.len().try_into().unwrap();
    response.header.arcount = response.additional.len().try_into().unwrap();

    // I'm not sure if this is right, but it's what pi-hole does for
    // queries which it can't answer.
    //
    // I think, by the text of RFC 1034, the AUTHORITY section of the
    // response should include an NS record for something which can
    // help.
    if response.answers.is_empty() {
        response.header.rcode = protocol::Rcode::ServerFailure;
        response.header.is_authoritative = false;
    }

    response
}

async fn handle_raw_message<'a>(
    settings: &Settings,
    mut buf: ConsumableBuffer<'a>,
) -> Option<Message> {
    let res = Message::parse(&mut buf);
    println!("{:?}", res);

    match res {
        Ok(msg) => {
            if msg.header.is_response {
                Some(Message::make_format_error_response(msg.header.id))
            } else if msg.header.opcode == protocol::Opcode::Standard {
                Some(resolve_and_build_response(settings, msg).await)
            } else {
                let mut response = msg.make_response();
                response.header.rcode = protocol::Rcode::NotImplemented;
                Some(response)
            }
        }
        Err(err) => err.id().map(Message::make_format_error_response),
    }
}

enum TcpError {
    TooShort {
        id: Option<u16>,
        expected: usize,
        actual: usize,
    },
    IO {
        id: Option<u16>,
        error: io::Error,
    },
}

async fn read_tcp_bytes(stream: &mut TcpStream) -> Result<BytesMut, TcpError> {
    match stream.read_u16().await {
        Ok(size) => {
            let expected = size as usize;
            let mut bytes = BytesMut::with_capacity(expected);
            while bytes.len() < expected {
                match stream.read_buf(&mut bytes).await {
                    Ok(0) if bytes.len() < expected => {
                        let id = if bytes.len() >= 2 {
                            Some(u16::from_be_bytes([bytes[0], bytes[1]]))
                        } else {
                            None
                        };
                        return Err(TcpError::TooShort {
                            id,
                            expected,
                            actual: bytes.len(),
                        });
                    }
                    Err(err) => {
                        let id = if bytes.len() >= 2 {
                            Some(u16::from_be_bytes([bytes[0], bytes[1]]))
                        } else {
                            None
                        };
                        return Err(TcpError::IO { id, error: err });
                    }
                    _ => (),
                }
            }
            Ok(bytes)
        }
        Err(err) => Err(TcpError::IO {
            id: None,
            error: err,
        }),
    }
}

async fn listen_tcp(settings: Settings, socket: TcpListener) {
    loop {
        match socket.accept().await {
            Ok((mut stream, peer)) => {
                println!("[{:?}] tcp request ok", peer);
                let settings = settings.clone();
                tokio::spawn(async move {
                    let response = match read_tcp_bytes(&mut stream).await {
                        Ok(bytes) => {
                            handle_raw_message(&settings, ConsumableBuffer::new(bytes.as_ref()))
                                .await
                        }
                        Err(TcpError::TooShort {
                            id,
                            expected,
                            actual,
                        }) => {
                            println!(
                                "[{:?}] tcp read error \"expected {:?} octets but got {:?}\"",
                                peer, expected, actual
                            );
                            id.map(Message::make_format_error_response)
                        }
                        Err(TcpError::IO { id, error }) => {
                            println!("[{:?}] tcp read error \"{:?}\"", peer, error);
                            id.map(Message::make_format_error_response)
                        }
                    };
                    if let Some(message) = response {
                        if let Err(err) = stream
                            .write_all(message.serialise_for_tcp().as_slice())
                            .await
                        {
                            println!("[{:?}] tcp send error \"{:?}\"", peer, err);
                        }
                    };
                });
            }
            Err(err) => println!("tcp request error \"{:?}\"", err),
        }
    }
}

async fn listen_udp(settings: Settings, socket: UdpSocket) {
    let (tx, mut rx) = mpsc::channel(32);
    let mut buf = vec![0u8; 512];

    loop {
        tokio::select! {
            Ok((size, peer)) = socket.recv_from(&mut buf) => {
                println!("[{:?}] udp request ok", peer);
                let bytes = BytesMut::from(&buf[..size]);
                let reply = tx.clone();
                let settings = settings.clone();
                tokio::spawn(async move {
                    if let Some(response_message) = handle_raw_message(&settings, ConsumableBuffer::new(bytes.as_ref())).await {
                        match reply.send((response_message, peer)).await {
                            Ok(_) => (),
                            Err(err) => println!("[{:?}] udp reply error \"{:?}\"", peer, err),
                        }
                    }
                });
            }

            Some((response_message, peer)) = rx.recv() => if let Err(err) = socket
                .send_to(response_message.serialise_for_udp().as_slice(), peer)
                .await
            {
                println!("[{:?}] udp send error \"{:?}\"", peer, err);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let settings = if let Some(fname) = env::args().nth(1) {
        match Settings::new(&fname) {
            Ok(s) => {
                println!("read config file");
                s
            }
            Err(err) => {
                eprintln!("error reading config file: {:?}", err);
                process::exit(1);
            }
        }
    } else {
        println!("starting with default config");
        Settings::default()
    };

    let udp = match UdpSocket::bind("127.0.0.1:53").await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error binding bind UDP socket: {:?}", err);
            process::exit(1);
        }
    };

    let tcp = match TcpListener::bind("127.0.0.1:53").await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error binding bind TCP socket: {:?}", err);
            process::exit(1);
        }
    };

    let tcp_settings = settings.clone();
    let udp_settings = settings;
    tokio::spawn(async move { listen_tcp(tcp_settings, tcp).await });
    listen_udp(udp_settings, udp).await;
}
