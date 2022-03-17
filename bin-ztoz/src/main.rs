use clap::Parser;
use std::io::{stdin, Read};
use std::process;

use dns_types::zones::types::Zone;

// the doc comments for this struct turn into the CLI help text
#[derive(Parser)]
/// Read a zone file from stdin, output it in a normalised form to
/// stdout.
///
/// Part of resolved.
struct Args {}

fn main() {
    Args::parse();

    let mut buf = String::new();
    if let Err(err) = stdin().read_to_string(&mut buf) {
        eprintln!("error reading zone file from stdin: {:?}", err);
        process::exit(1);
    }

    match Zone::deserialise(&buf) {
        Ok(zone) => print!("{}", zone.serialise()),
        Err(err) => {
            eprintln!("error parsing zone file from stdin: {:?}", err);
            process::exit(1);
        }
    }
}
