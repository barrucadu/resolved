pub mod protocol;

use bytes::BytesMut;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::protocol::{ConsumableBuffer, Message, ProtocolError};

fn handle_raw_message(mut buf: ConsumableBuffer) -> Option<Message> {
    let res = Message::parse(&mut buf);
    println!("{:?}", res);

    match res {
        Ok(msg) => {
            let mut response = Message::make_response(msg);
            response.header.rcode = protocol::Rcode::NotImplemented;
            Some(response)
        }
        Err(ProtocolError::HeaderTooShort(id))
        | Err(ProtocolError::QuestionTooShort(id))
        | Err(ProtocolError::ResourceRecordTooShort(id))
        | Err(ProtocolError::DomainTooShort(id))
        | Err(ProtocolError::DomainTooLong(id))
        | Err(ProtocolError::DomainLabelInvalid(id))
        | Err(ProtocolError::UnknownQueryType(id))
        | Err(ProtocolError::UnknownQueryClass(id))
        | Err(ProtocolError::UnknownRecordType(id))
        | Err(ProtocolError::UnknownRecordClass(id)) => {
            Some(Message::make_format_error_response(id))
        }
        Err(ProtocolError::CompletelyBusted) => None,
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

async fn listen_tcp(socket: TcpListener) {
    loop {
        match socket.accept().await {
            Ok((mut stream, peer)) => {
                println!("[{:?}] tcp request ok", peer);
                tokio::spawn(async move {
                    let response = match read_tcp_bytes(&mut stream).await {
                        Ok(bytes) => handle_raw_message(ConsumableBuffer::new(bytes.as_ref())),
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

async fn listen_udp(socket: UdpSocket) {
    let (tx, mut rx) = mpsc::channel(32);
    let mut buf = vec![0u8; 512];

    loop {
        tokio::select! {
            Ok((size, peer)) = socket.recv_from(&mut buf) => {
                println!("[{:?}] udp request ok", peer);
                let bytes = BytesMut::from(&buf[..size]);
                let reply = tx.clone();
                tokio::spawn(async move {
                    if let Some(response_message) = handle_raw_message(ConsumableBuffer::new(bytes.as_ref())) {
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
    let udp = UdpSocket::bind("127.0.0.1:53")
        .await
        .expect("could not bind UDP socket");
    let tcp = TcpListener::bind("127.0.0.1:53")
        .await
        .expect("could not bind TCP socket");

    tokio::spawn(async move { listen_tcp(tcp).await });

    listen_udp(udp).await;
}
