use bytes::BytesMut;
use std::env;
use std::process;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::sleep;

use resolved::net_util::{read_tcp_bytes, send_tcp_bytes, send_udp_bytes_to, TcpError};
use resolved::protocol::wire_types::{Message, Opcode, Rcode};
use resolved::resolver::cache::SharedCache;
use resolved::resolver::{resolve, ResolvedRecord};
use resolved::settings::Settings;

async fn resolve_and_build_response(
    settings: &Settings,
    cache: &SharedCache,
    query: Message,
) -> Message {
    let mut response = query.make_response();
    response.header.is_authoritative = true;

    for question in &query.questions {
        if let Some(rr) = resolve(
            query.header.recursion_desired,
            &settings.root_hints,
            settings,
            cache,
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

    // I'm not sure if this is right, but it's what pi-hole does for
    // queries which it can't answer.
    //
    // I think, by the text of RFC 1034, the AUTHORITY section of the
    // response should include an NS record for something which can
    // help.
    if response.answers.is_empty() {
        response.header.rcode = Rcode::ServerFailure;
        response.header.is_authoritative = false;
    }

    println!(".");

    response
}

async fn handle_raw_message<'a>(
    settings: &Settings,
    cache: &SharedCache,
    buf: &[u8],
) -> Option<Message> {
    let res = Message::from_octets(buf);
    println!("{:?}", res);

    match res {
        Ok(msg) => {
            if msg.header.is_response {
                Some(Message::make_format_error_response(msg.header.id))
            } else if msg.header.opcode == Opcode::Standard {
                Some(resolve_and_build_response(settings, cache, msg).await)
            } else {
                let mut response = msg.make_response();
                response.header.rcode = Rcode::NotImplemented;
                Some(response)
            }
        }
        Err(err) => err.id().map(Message::make_format_error_response),
    }
}

async fn listen_tcp(settings: Settings, cache: SharedCache, socket: TcpListener) {
    loop {
        match socket.accept().await {
            Ok((mut stream, peer)) => {
                println!("[{:?}] tcp request ok", peer);
                let settings = settings.clone();
                let cache = cache.clone();
                tokio::spawn(async move {
                    let response = match read_tcp_bytes(&mut stream).await {
                        Ok(bytes) => handle_raw_message(&settings, &cache, bytes.as_ref()).await,
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
                        if let Err(err) =
                            send_tcp_bytes(&mut stream, &mut message.to_octets()).await
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

async fn listen_udp(settings: Settings, cache: SharedCache, socket: UdpSocket) {
    let (tx, mut rx) = mpsc::channel(32);
    let mut buf = vec![0u8; 512];

    loop {
        tokio::select! {
            Ok((size, peer)) = socket.recv_from(&mut buf) => {
                println!("[{:?}] udp request ok", peer);
                let bytes = BytesMut::from(&buf[..size]);
                let reply = tx.clone();
                let settings = settings.clone();
                let cache = cache.clone();
                tokio::spawn(async move {
                    if let Some(response_message) = handle_raw_message(&settings, &cache, bytes.as_ref()).await {
                        match reply.send((response_message, peer)).await {
                            Ok(_) => (),
                            Err(err) => println!("[{:?}] udp reply error \"{:?}\"", peer, err),
                        }
                    }
                });
            }

            Some((response_message, peer)) = rx.recv() => if let Err(err) = send_udp_bytes_to(&socket, peer, &mut response_message.to_octets()).await
            {
                println!("[{:?}] udp send error \"{:?}\"", peer, err);
            }
        }
    }
}

/// Delete expired cache entries every 5 minutes.
///
/// Always removes all expired entries, and then if the cache is still
/// too big prunes it down to size.
async fn prune_cache_task(cache: SharedCache) {
    loop {
        sleep(Duration::from_secs(60 * 5)).await;

        let expired = cache.remove_expired();
        let pruned = cache.prune();

        println!(
            "[CACHE] expired {:?} and pruned {:?} entries",
            expired, pruned
        );
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

    let cache = SharedCache::new();

    tokio::spawn(listen_tcp(settings.clone(), cache.clone(), tcp));
    tokio::spawn(listen_udp(settings.clone(), cache.clone(), udp));

    prune_cache_task(cache).await;
}
