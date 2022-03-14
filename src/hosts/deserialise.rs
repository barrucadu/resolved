use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use tokio::fs::read_to_string;

use crate::hosts::types::*;
use crate::protocol::types::*;

impl Hosts {
    /// Read a hosts file, for example /etc/hosts.
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        match read_to_string(path).await {
            Ok(data) => Self::deserialise(&data),
            Err(error) => Err(Error::IO { error }),
        }
    }

    /// Parse a string of hosts data
    pub fn deserialise(data: &str) -> Result<Self, Error> {
        let mut entries = HashMap::new();
        for line in data.lines() {
            if let Some((address, new_names)) = parse_line(line)? {
                for name in new_names {
                    entries.insert(name, address);
                }
            }
        }
        Ok(Self { entries })
    }
}

/// Parse a single line.
fn parse_line(line: &str) -> Result<Option<(Ipv4Addr, HashSet<DomainName>)>, Error> {
    let mut state = State::SkipToAddress;
    let mut address = Ipv4Addr::LOCALHOST;
    let mut new_names = HashSet::new();

    for (i, octet) in line.chars().enumerate() {
        state = match (&state, octet) {
            (_, '#') => break,

            (State::SkipToAddress, ' ') => state,
            (State::SkipToAddress, _) => State::ReadingAddress { start: i },

            (State::ReadingAddress { start }, ' ') => {
                let addr_str = &line[*start..i];
                match Ipv4Addr::from_str(addr_str) {
                    Ok(addr) => address = addr,
                    Err(_) => {
                        return Err(Error::CouldNotParseAddress {
                            address: addr_str.into(),
                        })
                    }
                }
                State::SkipToName
            }
            // skip ipv6 addresses, rather than raising a parser
            // error, for greater compatibility with existing
            // blocklists.
            (State::ReadingAddress { .. }, ':') => return Ok(None),
            (State::ReadingAddress { .. }, _) => state,

            (State::SkipToName, ' ') => state,
            (State::SkipToName, _) => State::ReadingName { start: i },

            (State::ReadingName { start }, ' ') => {
                let name_str = &line[*start..i];
                match DomainName::from_dotted_string(name_str) {
                    Some(name) => {
                        new_names.insert(name);
                    }
                    None => {
                        return Err(Error::CouldNotParseName {
                            name: name_str.into(),
                        })
                    }
                }
                State::SkipToName
            }
            (State::ReadingName { .. }, _) => state,
        }
    }

    if let State::ReadingName { start } = state {
        let name_str = &line[start..];
        match DomainName::from_dotted_string(name_str) {
            Some(name) => {
                new_names.insert(name);
            }
            None => {
                return Err(Error::CouldNotParseName {
                    name: name_str.into(),
                })
            }
        }
    }

    if new_names.is_empty() {
        Ok(None)
    } else {
        Ok(Some((address, new_names)))
    }
}

/// An error that can occur reading a hosts file.
#[derive(Debug)]
pub enum Error {
    IO { error: std::io::Error },
    CouldNotParseAddress { address: String },
    CouldNotParseName { name: String },
}

/// States for the line parser
enum State {
    SkipToAddress,
    ReadingAddress { start: usize },
    SkipToName,
    ReadingName { start: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::protocol::types::test_util::*;
    use crate::zones::types::*;

    #[test]
    fn update_does_all_ipv4() {
        let hosts_data = "# hark, a comment!\n\
                          1.2.3.4 one two three four\n\
                          0.0.0.0 blocked\n
                          \n\
                          127.0.0.1 localhost\n\
                          ::1 also-localhost";

        let hosts = Hosts::deserialise(hosts_data).unwrap();

        let expected_records = &[
            ("one", Ipv4Addr::new(1, 2, 3, 4)),
            ("two", Ipv4Addr::new(1, 2, 3, 4)),
            ("three", Ipv4Addr::new(1, 2, 3, 4)),
            ("four", Ipv4Addr::new(1, 2, 3, 4)),
            ("blocked", Ipv4Addr::new(0, 0, 0, 0)),
            ("localhost", Ipv4Addr::new(127, 0, 0, 1)),
        ];

        for (name, addr) in expected_records {
            assert_eq!(
                Some(ZoneResult::Answer {
                    rrs: vec![a_record(name, *addr)]
                }),
                Zone::from(hosts.clone()).resolve(&domain(name), QueryType::Wildcard)
            );
        }
    }

    #[test]
    fn parse_line_parses_ipv4_with_names() {
        if let Ok(parsed) = parse_line("1.2.3.4 foo bar") {
            assert_eq!(
                Some((
                    Ipv4Addr::new(1, 2, 3, 4),
                    [domain("foo"), domain("bar")].into_iter().collect()
                )),
                parsed
            );
        } else {
            panic!("unexpected parse failure")
        }
    }

    #[test]
    fn parse_line_parses_ipv4_without_names() {
        if let Ok(parsed) = parse_line("1.2.3.4") {
            assert_eq!(None, parsed)
        } else {
            panic!("unexpected parse failure")
        }
    }

    #[test]
    fn parse_line_ignores_ipv6() {
        if let Ok(parsed) = parse_line("::1 localhost") {
            assert_eq!(None, parsed)
        } else {
            panic!("unexpected parse failure")
        }
    }
}
