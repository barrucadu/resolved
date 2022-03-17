use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
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
        let mut hosts = Self::new();
        for line in data.lines() {
            if let Some((address, new_names)) = parse_line(line)? {
                for name in new_names {
                    match address {
                        IpAddr::V4(ip) => {
                            hosts.v4.insert(name, ip);
                        }
                        IpAddr::V6(ip) => {
                            hosts.v6.insert(name, ip);
                        }
                    }
                }
            }
        }
        Ok(hosts)
    }
}

/// Parse a single line.
fn parse_line(line: &str) -> Result<Option<(IpAddr, HashSet<DomainName>)>, Error> {
    let mut state = State::SkipToAddress;
    let mut address = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut new_names = HashSet::new();

    for (i, octet) in line.chars().enumerate() {
        if !octet.is_ascii() {
            return Err(Error::ExpectedAscii);
        }

        state = match (&state, octet) {
            (_, '#') => break,

            (State::SkipToAddress, c) if c.is_whitespace() => state,
            (State::SkipToAddress, _) => State::ReadingAddress { start: i },

            (State::ReadingAddress { start }, c) if c.is_whitespace() => {
                let addr_str = &line[*start..i];
                match IpAddr::from_str(addr_str) {
                    Ok(addr) => address = addr,
                    Err(_) => {
                        return Err(Error::CouldNotParseAddress {
                            address: addr_str.into(),
                        })
                    }
                }
                State::SkipToName
            }
            (State::ReadingAddress { .. }, _) => state,

            (State::SkipToName, c) if c.is_whitespace() => state,
            (State::SkipToName, _) => State::ReadingName { start: i },

            (State::ReadingName { start }, c) if c.is_whitespace() => {
                let name_str = &line[*start..i];
                match DomainName::from_relative_dotted_string(&DomainName::root_domain(), name_str)
                {
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
        match DomainName::from_relative_dotted_string(&DomainName::root_domain(), name_str) {
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
    ExpectedAscii,
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
    use std::net::Ipv6Addr;

    use super::*;

    use crate::protocol::types::test_util::*;
    use crate::zones::types::*;

    #[test]
    fn parses_all() {
        let hosts_data = "# hark, a comment!\n\
                          1.2.3.4 one two three four\n\
                          0.0.0.0 blocked\n
                          \n\
                          127.0.0.1 localhost.\n\
                          ::1 localhost";

        let hosts = Hosts::deserialise(hosts_data).unwrap();

        let expected_a_records = &[
            ("one.", Ipv4Addr::new(1, 2, 3, 4)),
            ("two.", Ipv4Addr::new(1, 2, 3, 4)),
            ("three.", Ipv4Addr::new(1, 2, 3, 4)),
            ("four.", Ipv4Addr::new(1, 2, 3, 4)),
            ("blocked.", Ipv4Addr::new(0, 0, 0, 0)),
            ("localhost.", Ipv4Addr::new(127, 0, 0, 1)),
        ];

        let expected_aaaa_records = &[("localhost.", Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))];

        for (name, addr) in expected_a_records {
            assert_eq!(
                Some(ZoneResult::Answer {
                    rrs: vec![a_record(name, *addr)]
                }),
                Zone::from(hosts.clone()).resolve(&domain(name), QueryType::Record(RecordType::A))
            );
        }

        for (name, addr) in expected_aaaa_records {
            assert_eq!(
                Some(ZoneResult::Answer {
                    rrs: vec![aaaa_record(name, *addr)]
                }),
                Zone::from(hosts.clone())
                    .resolve(&domain(name), QueryType::Record(RecordType::AAAA))
            );
        }
    }

    #[test]
    fn parse_line_parses_ipv4_with_names() {
        if let Ok(parsed) = parse_line("1.2.3.4 foo bar") {
            assert_eq!(
                Some((
                    IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                    [domain("foo."), domain("bar.")].into_iter().collect()
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
    fn parse_line_parses_ipv6_with_names() {
        if let Ok(parsed) = parse_line("::1:2:3 foo bar") {
            assert_eq!(
                Some((
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 1, 2, 3)),
                    [domain("foo."), domain("bar.")].into_iter().collect()
                )),
                parsed
            );
        } else {
            panic!("unexpected parse failure")
        }
    }

    #[test]
    fn parse_line_parses_ipv6_without_names() {
        if let Ok(parsed) = parse_line("::1") {
            assert_eq!(None, parsed);
        } else {
            panic!("unexpected parse failure")
        }
    }
}
