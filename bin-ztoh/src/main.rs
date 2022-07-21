use clap::Parser;
use std::io::{stdin, Read};
use std::process;

use dns_types::hosts::types::Hosts;
use dns_types::zones::types::Zone;

// the doc comments for this struct turn into the CLI help text
#[derive(Parser)]
/// Read a zone file from stdin, convert it to a hosts file, and
/// output it in a normalised form to stdout.
///
/// Hosts files can only contain non-wildcard A and AAAA records, so
/// this conversion is lossy.
///
/// Part of resolved.
struct Args {
    /// Return an error if the zone file contains any records which
    /// cannot be represented in a hosts file.
    #[clap(long)]
    strict: bool,
}

fn main() {
    let args = Args::parse();

    let mut buf = String::new();
    if let Err(err) = stdin().read_to_string(&mut buf) {
        eprintln!("error reading zone file from stdin: {:?}", err);
        process::exit(1);
    }

    match Zone::deserialise(&buf) {
        Ok(zone) => {
            let try_hosts = if args.strict {
                Hosts::try_from(zone)
            } else {
                Ok(Hosts::from_zone_lossy(&zone))
            };
            match try_hosts {
                Ok(hosts) => print!("{}", hosts.serialise()),
                Err(err) => {
                    eprintln!("error converting zone file to hosts file: {:?}", err);
                    process::exit(1);
                }
            }
        }
        Err(err) => {
            eprintln!("error parsing zone file from stdin: {:?}", err);
            process::exit(1);
        }
    }
}
