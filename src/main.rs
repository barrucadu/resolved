use bytes::BytesMut;
use std::env;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::sleep;

use resolved::hosts::types::Hosts;
use resolved::net_util::{read_tcp_bytes, send_tcp_bytes, send_udp_bytes_to, TcpError};
use resolved::protocol::wire_types::*;
use resolved::resolver::cache::SharedCache;
use resolved::resolver::{resolve, ResolvedRecord};
use resolved::settings::Settings;
use resolved::zones::{Zone, Zones};

async fn resolve_and_build_response(zones: &Zones, cache: &SharedCache, query: Message) -> Message {
    let mut response = query.make_response();
    response.header.is_authoritative = true;

    if query.questions.iter().any(|q| q.is_unknown()) {
        response.header.rcode = Rcode::Refused;
        response.header.is_authoritative = false;
        println!(".");
        return response;
    }

    for question in &query.questions {
        if let Some(rr) = resolve(query.header.recursion_desired, zones, cache, question).await {
            match rr {
                ResolvedRecord::Authoritative {
                    mut rrs,
                    mut authority_rrs,
                } => {
                    response.answers.append(&mut rrs);
                    response.authority.append(&mut authority_rrs);
                }
                ResolvedRecord::AuthoritativeNameError { mut authority_rrs } => {
                    response.authority.append(&mut authority_rrs);
                    if query.questions.len() == 1 {
                        response.header.rcode = Rcode::NameError;
                    }
                }
                ResolvedRecord::NonAuthoritative { mut rrs } => {
                    response.answers.append(&mut rrs);
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
    if response.answers.is_empty() && response.header.rcode != Rcode::NameError {
        response.header.rcode = Rcode::ServerFailure;
        response.header.is_authoritative = false;
    }

    println!(".");

    response
}

async fn handle_raw_message<'a>(zones: &Zones, cache: &SharedCache, buf: &[u8]) -> Option<Message> {
    let res = Message::from_octets(buf);
    println!("{:?}", res);

    match res {
        Ok(msg) => {
            if msg.header.is_response {
                Some(Message::make_format_error_response(msg.header.id))
            } else if msg.header.opcode == Opcode::Standard {
                Some(resolve_and_build_response(zones, cache, msg).await)
            } else {
                let mut response = msg.make_response();
                response.header.rcode = Rcode::NotImplemented;
                Some(response)
            }
        }
        Err(err) => err.id().map(Message::make_format_error_response),
    }
}

async fn listen_tcp(zones: Zones, cache: SharedCache, socket: TcpListener) {
    loop {
        match socket.accept().await {
            Ok((mut stream, peer)) => {
                println!("[{:?}] tcp request ok", peer);
                let zones = zones.clone();
                let cache = cache.clone();
                tokio::spawn(async move {
                    let response = match read_tcp_bytes(&mut stream).await {
                        Ok(bytes) => handle_raw_message(&zones, &cache, bytes.as_ref()).await,
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
                        match message.clone().to_octets() {
                            Ok(mut serialised) => {
                                if let Err(err) = send_tcp_bytes(&mut stream, &mut serialised).await
                                {
                                    println!("[{:?}] tcp send error \"{:?}\"", peer, err);
                                }
                            }
                            Err(err) => {
                                println!(
                                    "[INTERNAL ERROR] could not serialise message {:?} \"{:?}\"",
                                    message, err
                                );
                            }
                        };
                    };
                });
            }
            Err(err) => println!("tcp request error \"{:?}\"", err),
        }
    }
}

async fn listen_udp(zones: Zones, cache: SharedCache, socket: UdpSocket) {
    let (tx, mut rx) = mpsc::channel(32);
    let mut buf = vec![0u8; 512];

    loop {
        tokio::select! {
            Ok((size, peer)) = socket.recv_from(&mut buf) => {
                println!("[{:?}] udp request ok", peer);
                let bytes = BytesMut::from(&buf[..size]);
                let reply = tx.clone();
                let zones = zones.clone();
                let cache = cache.clone();
                tokio::spawn(async move {
                    if let Some(response_message) = handle_raw_message(&zones, &cache, bytes.as_ref()).await {
                        match reply.send((response_message, peer)).await {
                            Ok(_) => (),
                            Err(err) => println!("[{:?}] udp reply error \"{:?}\"", peer, err),
                        }
                    }
                });
            }

            Some((message, peer)) = rx.recv() => match message.clone().to_octets() {
                Ok(mut serialised) =>  if let Err(err) = send_udp_bytes_to(&socket, peer, &mut serialised).await
                {
                    println!("[{:?}] udp send error \"{:?}\"", peer, err);
                }
                Err(err) => {
                    println!(
                        "[INTERNAL ERROR] could not serialise message {:?} \"{:?}\"",
                        message, err
                    );
                }
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
    let (settings, settings_path) = if let Some(fname) = env::args().nth(1) {
        match Settings::new(&fname) {
            Ok(s) => {
                let mut path = Path::new(&fname)
                    .canonicalize()
                    .expect("could not get absolute path to configuration file");
                path.pop();

                println!("read config file");
                (s, path)
            }
            Err(err) => {
                eprintln!("error reading config file: {:?}", err);
                process::exit(1);
            }
        }
    } else {
        println!("starting with default config");
        let path = std::env::current_dir().expect("could not get current working directory");
        (Settings::default(), path)
    };

    let mut root_zone = Zone::default();
    for record in &settings.static_records {
        // this is very repetitive, but will go away when the zone
        // file parser comes and the current `settings::Record` type
        // gets removed.
        if let Some(address) = &record.record_a {
            if record.domain.include_subdomains {
                root_zone.insert_wildcard(
                    &record.domain.name.domain,
                    RecordTypeWithData::A { address: *address },
                    300,
                );
            } else {
                root_zone.insert(
                    &record.domain.name.domain,
                    RecordTypeWithData::A { address: *address },
                    300,
                );
            }
        }
        if let Some(cname) = &record.record_cname {
            if record.domain.include_subdomains {
                root_zone.insert_wildcard(
                    &record.domain.name.domain,
                    RecordTypeWithData::CNAME {
                        cname: cname.domain.clone(),
                    },
                    300,
                );
            } else {
                root_zone.insert(
                    &record.domain.name.domain,
                    RecordTypeWithData::CNAME {
                        cname: cname.domain.clone(),
                    },
                    300,
                );
            }
        }
        if let Some(ns) = &record.record_ns {
            if record.domain.include_subdomains {
                root_zone.insert_wildcard(
                    &record.domain.name.domain,
                    RecordTypeWithData::NS {
                        nsdname: ns.domain.clone(),
                    },
                    300,
                );
            } else {
                root_zone.insert(
                    &record.domain.name.domain,
                    RecordTypeWithData::NS {
                        nsdname: ns.domain.clone(),
                    },
                    300,
                );
            }
        }
    }
    let mut combined_hosts = Hosts::default();
    for path_str in &settings.hosts_files.clone() {
        let path = Path::new(path_str);
        let absolute_path = if path.is_relative() {
            Path::new(&settings_path).join(path)
        } else {
            path.to_path_buf()
        };

        match Hosts::from_file(absolute_path).await {
            Ok(hosts) => combined_hosts.merge(hosts),
            Err(err) => {
                eprintln!("error reading hosts file \"{:?}\": {:?}", path, err);
                process::exit(1);
            }
        }
    }
    root_zone.merge(combined_hosts.into()).unwrap();

    let mut zones = Zones::new();
    zones.insert(root_zone);

    let interface = settings.interface.unwrap_or(Ipv4Addr::UNSPECIFIED);
    println!("binding to {:?}", interface);

    let udp = match UdpSocket::bind((interface, 53)).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error binding bind UDP socket: {:?}", err);
            process::exit(1);
        }
    };

    let tcp = match TcpListener::bind((interface, 53)).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error binding bind TCP socket: {:?}", err);
            process::exit(1);
        }
    };

    let cache = SharedCache::new();

    tokio::spawn(listen_tcp(zones.clone(), cache.clone(), tcp));
    tokio::spawn(listen_udp(zones.clone(), cache.clone(), udp));

    prune_cache_task(cache).await;
}
