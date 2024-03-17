use clap::Parser;
use std::io::{stdin, Read};
use std::process;

use dns_types::hosts::types::Hosts;
use dns_types::zones::types::Zone;

// the doc comments for this struct turn into the CLI help text
#[derive(Parser)]
/// Read a hosts file from stdin, convert it to a zone file, and
/// output it in a normalised form to stdout.
///
/// Part of resolved.
struct Args {}

fn main() {
    Args::parse();

    let mut buf = String::new();
    if let Err(err) = stdin().read_to_string(&mut buf) {
        eprintln!("error reading hosts file from stdin: {err:?}");
        process::exit(1);
    }

    match Hosts::deserialise(&buf) {
        Ok(hosts) => print!("{}", Zone::from(hosts).serialise()),
        Err(err) => {
            eprintln!("error parsing hosts file from stdin: {err:?}");
            process::exit(1);
        }
    }
}
