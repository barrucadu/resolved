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

use dns_resolver::cache::SharedCache;
use dns_resolver::resolve;
use dns_resolver::util::net::*;
use dns_resolver::util::types::ResolvedRecord;
use dns_types::hosts::types::Hosts;
use dns_types::protocol::types::*;
use dns_types::zones::types::*;
use resolved::fs_util::*;
use resolved::metrics::*;

fn prune_cache_and_update_metrics(cache: &SharedCache) {
    let (overflow, current_size, expired, pruned) = cache.prune();

    CACHE_SIZE.set(current_size.try_into().unwrap_or(i64::MAX));
    CACHE_EXPIRED_TOTAL.inc_by(expired.try_into().unwrap_or(u64::MAX));
    CACHE_PRUNED_TOTAL.inc_by(pruned.try_into().unwrap_or(u64::MAX));

    if overflow {
        CACHE_OVERFLOW_COUNT.inc();
    }

    println!(
        "[CACHE] expired {:?} and pruned {:?} entries",
        expired, pruned
    );
}

async fn resolve_and_build_response(args: ListenArgs, query: Message) -> Message {
    // lock zones here, rather than where they're used in
    // `resolve_nonrecursive`, so that this whole request sees a
    // consistent version of the zones even if they get updated in the
    // middle of processing.
    let zones = args.zones_lock.read().await;

    let mut response = query.make_response();
    response.header.is_authoritative = true;
    response.header.recursion_available = !args.authoritative_only;

    let mut is_refused = false;

    for question in &query.questions {
        let question_labels: &[&str] = &[
            &query.header.recursion_desired.to_string(),
            &question.qtype.to_string(),
            &question.qclass.to_string(),
        ];
        DNS_QUESTIONS_TOTAL.with_label_values(question_labels).inc();
        let question_timer = DNS_QUESTION_PROCESSING_TIME_SECONDS
            .with_label_values(question_labels)
            .start_timer();

        if question.is_unknown() {
            is_refused = true;
            question_timer.observe_duration();
            continue;
        }

        let (metrics, answer) = resolve(
            query.header.recursion_desired && response.header.recursion_available,
            args.forward_address,
            &zones,
            &args.cache,
            question,
        )
        .await;

        DNS_RESOLVER_AUTHORITATIVE_HIT_TOTAL.inc_by(metrics.authoritative_hits);
        DNS_RESOLVER_OVERRIDE_HIT_TOTAL.inc_by(metrics.override_hits);
        DNS_RESOLVER_BLOCKED_TOTAL.inc_by(metrics.blocked);
        DNS_RESOLVER_CACHE_HIT_TOTAL.inc_by(metrics.cache_hits);
        DNS_RESOLVER_CACHE_MISS_TOTAL.inc_by(metrics.cache_misses);
        DNS_RESOLVER_NAMESERVER_HIT_TOTAL.inc_by(metrics.nameserver_hits);
        DNS_RESOLVER_NAMESERVER_MISS_TOTAL.inc_by(metrics.nameserver_misses);

        if let Some(rr) = answer {
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
        question_timer.observe_duration();
    }

    prune_cache_and_update_metrics(&args.cache);

    if is_refused {
        response.header.rcode = Rcode::Refused;
        response.header.is_authoritative = false;
    } else if response.answers.is_empty() && response.header.rcode != Rcode::NameError {
        response.header.rcode = Rcode::ServerFailure;
        response.header.is_authoritative = false;
    }

    println!(".");

    response
}

async fn handle_raw_message<'a>(args: ListenArgs, buf: &[u8]) -> Option<Message> {
    let res = Message::from_octets(buf);
    println!("{:?}", res);

    match res {
        Ok(msg) => {
            if msg.header.is_response {
                Some(Message::make_format_error_response(msg.header.id))
            } else if msg.header.opcode == Opcode::Standard {
                Some(resolve_and_build_response(args, msg).await)
            } else {
                let mut response = msg.make_response();
                response.header.rcode = Rcode::NotImplemented;
                Some(response)
            }
        }
        Err(err) => err.id().map(Message::make_format_error_response),
    }
}

async fn listen_tcp_task(args: ListenArgs, socket: TcpListener) {
    loop {
        match socket.accept().await {
            Ok((mut stream, peer)) => {
                println!("[{:?}] tcp request ok", peer);
                DNS_REQUESTS_TOTAL.with_label_values(&["tcp"]).inc();
                let args = args.clone();
                tokio::spawn(async move {
                    let response_timer = DNS_RESPONSE_TIME_SECONDS
                        .with_label_values(&["tcp"])
                        .start_timer();
                    let response = match read_tcp_bytes(&mut stream).await {
                        Ok(bytes) => handle_raw_message(args, bytes.as_ref()).await,
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
                                DNS_RESPONSES_TOTAL
                                    .with_label_values(&[
                                        &message.header.is_authoritative.to_string(),
                                        "false",
                                        &message.header.recursion_desired.to_string(),
                                        &message.header.recursion_available.to_string(),
                                        &message.header.rcode.to_string(),
                                    ])
                                    .inc();

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
                    response_timer.observe_duration();
                });
            }
            Err(err) => println!("tcp request error \"{:?}\"", err),
        }
    }
}

async fn listen_udp_task(args: ListenArgs, socket: UdpSocket) {
    let (tx, mut rx) = mpsc::channel(32);
    let mut buf = vec![0u8; 512];

    loop {
        tokio::select! {
            Ok((size, peer)) = socket.recv_from(&mut buf) => {
                println!("[{:?}] udp request ok", peer);
                DNS_REQUESTS_TOTAL.with_label_values(&["udp"]).inc();
                let bytes = BytesMut::from(&buf[..size]);
                let reply = tx.clone();
                let args = args.clone();
                tokio::spawn(async move {
                    let response_timer = DNS_RESPONSE_TIME_SECONDS
                        .with_label_values(&["udp"])
                        .start_timer();
                    if let Some(response_message) = handle_raw_message(args, bytes.as_ref()).await {
                        match reply.send((response_message, peer, response_timer)).await {
                            Ok(_) => (),
                            Err(err) => println!("[{:?}] udp reply error \"{:?}\"", peer, err),
                        }
                    }
                });
            }

            Some((message, peer, response_timer)) = rx.recv() => {
                match message.clone().to_octets() {
                    Ok(mut serialised) => {
                        DNS_RESPONSES_TOTAL.with_label_values(&[
                            &message.header.is_authoritative.to_string(),
                            &(serialised.len() > 512).to_string(),
                            &message.header.recursion_desired.to_string(),
                            &message.header.recursion_available.to_string(),
                            &message.header.rcode.to_string(),
                        ]).inc();
                        if let Err(err) = send_udp_bytes_to(&socket, peer, &mut serialised).await
                        {
                            println!("[{:?}] udp send error \"{:?}\"", peer, err);
                        }
                    }
                    Err(err) => {
                        println!(
                            "[INTERNAL ERROR] could not serialise message {:?} \"{:?}\"",
                            message, err
                        );
                    }
                };
                response_timer.observe_duration();
            }
        }
    }
}

/// Arguments for `listen_udp` and `listen_tcp` and the resolvers.
#[derive(Debug, Clone)]
struct ListenArgs {
    authoritative_only: bool,
    forward_address: Option<Ipv4Addr>,
    zones_lock: Arc<RwLock<Zones>>,
    cache: SharedCache,
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
        prune_cache_and_update_metrics(&cache);
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
///
/// Prometheus metrics are served at
/// "http://{metrics_interface}:{metrics_port}/metrics"
#[derive(Clone)]
struct Args {
    /// Interface to listen on
    #[clap(short, long, default_value_t = Ipv4Addr::UNSPECIFIED)]
    interface: Ipv4Addr,

    /// Interface to listen on to serve Prometheus metrics
    #[clap(long, default_value_t = Ipv4Addr::LOCALHOST)]
    metrics_interface: Ipv4Addr,

    /// Port to listen on to serve Prometheus metrics
    #[clap(long, default_value_t = 9420)]
    metrics_port: u16,

    /// Only answer queries for which this server is authoritative: do
    /// not perform recursive or forwarding resolution
    #[clap(long)]
    authoritative_only: bool,

    /// Act as a forwarding resolver, not a recursive resolver:
    /// forward queries which can't be answered from local state to
    /// this nameserver and cache the result
    #[clap(short, long)]
    forward_address: Option<Ipv4Addr>,

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

    let listen_args = ListenArgs {
        authoritative_only: args.authoritative_only,
        forward_address: args.forward_address,
        zones_lock: Arc::new(RwLock::new(zones)),
        cache: SharedCache::with_desired_size(std::cmp::max(1, args.cache_size)),
    };

    tokio::spawn(listen_tcp_task(listen_args.clone(), tcp));
    tokio::spawn(listen_udp_task(listen_args.clone(), udp));
    tokio::spawn(reload_task(listen_args.zones_lock.clone(), args.clone()));
    tokio::spawn(prune_cache_task(listen_args.cache));

    if let Err(err) =
        serve_prometheus_endpoint_task(args.metrics_interface, args.metrics_port).await
    {
        eprintln!("error starting metrics endpoint: {:?}", err);
        process::exit(1);
    }
}
