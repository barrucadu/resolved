use clap::Parser;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process;

use dns_resolver::cache::SharedCache;
use dns_resolver::resolve;
use dns_resolver::util::fs::load_zone_configuration;
use dns_resolver::util::types::ResolvedRecord;
use dns_types::protocol::types::{
    DomainName, QueryClass, QueryType, Question, RecordClass, RecordType, ResourceRecord,
};
use dns_types::zones::types::Zone;

fn print_section(heading: &str, rrs: &[ResourceRecord]) {
    if rrs.is_empty() {
        return;
    }

    println!("\n;; {heading}");
    for rr in rrs {
        let rdata = Zone::default().serialise_rdata(&rr.rtype_with_data);
        println!(
            "{}\t{}\t{}\t{}\t{}",
            rr.name,
            rr.ttl,
            rr.rclass,
            rr.rtype_with_data.rtype(),
            rdata
        );
    }
}

// the doc comments for this struct turn into the CLI help text
#[derive(Parser)]
/// DNS recursive lookup utility
///
/// It does not support querying upstream nameservers over IPv6: I
/// don't have IPv6 at home, so this code doesn't support it yet.
struct Args {
    /// Domain name to resolve
    #[clap(value_parser)]
    domain: DomainName,

    /// Query type to resolve
    #[clap(default_value_t = QueryType::Record(RecordType::A), value_parser)]
    qtype: QueryType,

    /// Only answer queries for which this configuration is authoritative: do
    /// not perform recursive or forwarding resolution
    #[clap(long, action(clap::ArgAction::SetTrue))]
    authoritative_only: bool,

    /// Act as a forwarding resolver, not a recursive resolver: forward queries
    /// which can't be answered from local state to this nameserver
    #[clap(short, long, value_parser)]
    forward_address: Option<Ipv4Addr>,

    /// Path to a hosts file, can be specified more than once
    #[clap(short = 'a', long, value_parser)]
    hosts_file: Vec<PathBuf>,

    /// Path to a directory to read hosts files from, can be specified more than
    /// once
    #[clap(short = 'A', long, value_parser)]
    hosts_dir: Vec<PathBuf>,

    /// Path to a zone file, can be specified more than once
    #[clap(short = 'z', long, value_parser)]
    zone_file: Vec<PathBuf>,

    /// Path to a directory to read zone files from, can be specified more than
    /// once
    #[clap(short = 'Z', long, value_parser)]
    zones_dir: Vec<PathBuf>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let question = Question {
        name: args.domain,
        qtype: args.qtype,
        qclass: QueryClass::Record(RecordClass::IN),
    };

    let zones = match load_zone_configuration(
        &args.hosts_file,
        &args.hosts_dir,
        &args.zone_file,
        &args.zones_dir,
    )
    .await
    {
        Some(zs) => zs,
        None => {
            eprintln!("could not load configuration");
            process::exit(1);
        }
    };

    println!(";; QUESTION");
    println!("{}\t{}\t{}", question.name, question.qclass, question.qtype);

    // TODO: log upstream queries as they happen
    let (_, response) = resolve(
        !args.authoritative_only,
        args.forward_address,
        &zones,
        &SharedCache::new(),
        &question,
    )
    .await;

    match response {
        Ok(response) => match response {
            ResolvedRecord::Authoritative { rrs, authority_rrs } => {
                print_section("ANSWER", &rrs);
                print_section("AUTHORITY", &authority_rrs);
            }
            ResolvedRecord::AuthoritativeNameError { authority_rrs } => {
                println!("\n;; ANSWER");
                println!("; name does not exist");
                print_section("AUTHORITY", &authority_rrs);
            }
            ResolvedRecord::NonAuthoritative { rrs } => {
                print_section("ANSWER", &rrs);
            }
        },
        Err(err) => {
            println!("\n;; ANSWER");
            println!("; {err}");
            process::exit(1);
        }
    }
}
