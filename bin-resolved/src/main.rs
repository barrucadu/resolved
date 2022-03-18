use bytes::BytesMut;
use clap::Parser;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::sleep;

use dns_types::hosts::types::Hosts;
use dns_types::protocol::types::*;
use dns_types::zones::types::*;

use resolved::fs_util::*;
use resolved::net_util::*;
use resolved::resolver::cache::SharedCache;
use resolved::resolver::{resolve, ResolvedRecord};

async fn resolve_and_build_response(
    zones_lock: Arc<RwLock<Zones>>,
    cache: &SharedCache,
    query: Message,
) -> Message {
    // lock zones here, rather than where they're used in
    // `resolve_nonrecursive`, so that this whole request sees a
    // consistent version of the zones even if they get updated in the
    // middle of processing.
    let zones = zones_lock.read().await;

    let mut response = query.make_response();
    response.header.is_authoritative = true;

    if query.questions.iter().any(|q| q.is_unknown()) {
        response.header.rcode = Rcode::Refused;
        response.header.is_authoritative = false;
        println!(".");
        return response;
    }

    for question in &query.questions {
        if let Some(rr) = resolve(query.header.recursion_desired, &zones, cache, question).await {
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

async fn handle_raw_message<'a>(
    zones_lock: Arc<RwLock<Zones>>,
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
                Some(resolve_and_build_response(zones_lock, cache, msg).await)
            } else {
                let mut response = msg.make_response();
                response.header.rcode = Rcode::NotImplemented;
                Some(response)
            }
        }
        Err(err) => err.id().map(Message::make_format_error_response),
    }
}

async fn listen_tcp(zones_lock: Arc<RwLock<Zones>>, cache: SharedCache, socket: TcpListener) {
    loop {
        match socket.accept().await {
            Ok((mut stream, peer)) => {
                println!("[{:?}] tcp request ok", peer);
                let zones_lock = zones_lock.clone();
                let cache = cache.clone();
                tokio::spawn(async move {
                    let response = match read_tcp_bytes(&mut stream).await {
                        Ok(bytes) => handle_raw_message(zones_lock, &cache, bytes.as_ref()).await,
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

async fn listen_udp(zones_lock: Arc<RwLock<Zones>>, cache: SharedCache, socket: UdpSocket) {
    let (tx, mut rx) = mpsc::channel(32);
    let mut buf = vec![0u8; 512];

    loop {
        tokio::select! {
            Ok((size, peer)) = socket.recv_from(&mut buf) => {
                println!("[{:?}] udp request ok", peer);
                let bytes = BytesMut::from(&buf[..size]);
                let reply = tx.clone();
                let zones_lock = zones_lock.clone();
                let cache = cache.clone();
                tokio::spawn(async move {
                    if let Some(response_message) = handle_raw_message(zones_lock, &cache, bytes.as_ref()).await {
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

/// Load the hosts and zones from the configuration, generating the
/// `Zones` parameter for the resolver.
async fn load_zone_configuration(args: &Args) -> Option<Zones> {
    let mut is_error = false;
    let mut hosts_file_paths = args.hosts_file.clone();
    let mut zone_file_paths = args.zone_file.clone();

    for path in args.zones_dir.iter() {
        match get_files_from_dir(path).await {
            Ok(mut paths) => zone_file_paths.append(&mut paths),
            Err(err) => {
                eprintln!("error reading zone directory \"{:?}\": {:?}", path, err);
                is_error = true;
            }
        }
    }
    for path in args.hosts_dir.iter() {
        match get_files_from_dir(path).await {
            Ok(mut paths) => hosts_file_paths.append(&mut paths),
            Err(err) => {
                eprintln!("error reading hosts directory \"{:?}\": {:?}", path, err);
                is_error = true;
            }
        }
    }

    let mut combined_zones = Zones::new();
    for path in zone_file_paths.iter() {
        match zone_from_file(Path::new(path)).await {
            Ok(Ok(zone)) => combined_zones.insert_merge(zone),
            Ok(Err(err)) => {
                eprintln!("error parsing zone file \"{:?}\": {:?}", path, err);
                is_error = true;
            }
            Err(err) => {
                eprintln!("error reading zone file \"{:?}\": {:?}", path, err);
                is_error = true;
            }
        }
    }

    let mut combined_hosts = Hosts::default();
    for path in hosts_file_paths.iter() {
        match hosts_from_file(Path::new(path)).await {
            Ok(Ok(hosts)) => combined_hosts.merge(hosts),
            Ok(Err(err)) => {
                eprintln!("error parsing hosts file \"{:?}\": {:?}", path, err);
                is_error = true;
            }
            Err(err) => {
                eprintln!("error reading hosts file \"{:?}\": {:?}", path, err);
                is_error = true;
            }
        }
    }

    if is_error {
        None
    } else {
        combined_zones.insert_merge(combined_hosts.into());
        Some(combined_zones)
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

/// Reload hosts and zones, and replace the value in the `RwLock`.
async fn reload_task(zones_lock: Arc<RwLock<Zones>>, args: Args) {
    let mut stream = match signal(SignalKind::user_defined1()) {
        Ok(s) => s,
        Err(err) => panic!("could not subscribe to SIGUSR1: {:?}", err),
    };

    loop {
        stream.recv().await;

        println!("[USR1] reloading zones...");
        if let Some(zones) = load_zone_configuration(&args).await {
            let mut lock = zones_lock.write().await;
            *lock = zones;
            println!("[USR1] reloaded zones");
        } else {
            println!("[USR1] could not reload zones");
        }
    }
}

// the doc comments for this struct turn into the CLI help text
#[derive(Debug, Parser)]
/// A simple DNS server for home networks.
///
/// resolved supports:
///
/// - Recursive and non-recursive resolution
///
/// - Caching
///
/// - Hosts files
///
/// - Zone files
///
/// It does not support querying upstream nameservers over IPv6: I
/// don't have IPv6 at home, so this code doesn't support it yet.
///
/// It is not intended to be a fully-featured internet-facing
/// nameserver, but just enough to get DNS ad-blocking and nice
/// hostnames working in your LAN.
struct Args {
    /// Interface to listen on
    #[clap(short, long, default_value_t = Ipv4Addr::UNSPECIFIED)]
    interface: Ipv4Addr,

    /// How many records to hold in the cache
    #[clap(short = 's', long, default_value_t = 512)]
    cache_size: usize,

    /// Path to a hosts file, can be specified more than once
    #[clap(short = 'a', long)]
    hosts_file: Vec<PathBuf>,

    /// Path to a directory to read hosts files from, can be specified more than once
    #[clap(short = 'A', long)]
    hosts_dir: Vec<PathBuf>,

    /// Path to a zone file, can be specified more than once
    #[clap(short = 'z', long)]
    zone_file: Vec<PathBuf>,

    /// Path to a directory to read zone files from, can be specified more than once
    #[clap(short = 'Z', long)]
    zones_dir: Vec<PathBuf>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let zones = match load_zone_configuration(&args).await {
        Some(zs) => zs,
        None => process::exit(1),
    };

    println!("binding to {:?}", args.interface);

    let udp = match UdpSocket::bind((args.interface, 53)).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error binding bind UDP socket: {:?}", err);
            process::exit(1);
        }
    };

    let tcp = match TcpListener::bind((args.interface, 53)).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error binding bind TCP socket: {:?}", err);
            process::exit(1);
        }
    };

    let zones_lock = Arc::new(RwLock::new(zones));
    let cache = SharedCache::with_desired_size(std::cmp::max(1, args.cache_size));

    tokio::spawn(listen_tcp(zones_lock.clone(), cache.clone(), tcp));
    tokio::spawn(listen_udp(zones_lock.clone(), cache.clone(), udp));
    tokio::spawn(reload_task(zones_lock.clone(), args));

    prune_cache_task(cache).await;
}
