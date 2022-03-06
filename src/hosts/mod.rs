use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use tokio::fs::read_to_string;

use crate::protocol::wire_types::DomainName;
use crate::settings::*;

/// Read a hosts file, for example /etc/hosts, and add all the entries
/// to the local zone.
///
/// Prior entries, including those already in the local zone, take
/// precedence over later entries.
pub async fn update_static_zone_from_hosts_file<P: AsRef<Path>>(
    local_zone: &mut Settings,
    path: P,
) -> Result<(), Error> {
    match read_to_string(path).await {
        Ok(data) => update_static_zone_from_hosts_data(local_zone, &data),
        Err(error) => Err(Error::IO { error }),
    }
}

/// Like `update_static_zone_from_hosts_file` but also takes a set of
/// names the local zone currently defines, to avoid the need to
/// re-examine it.  This also mutates the names set to add any
/// newly-defined names.
///
/// Prior entries, including those in the names set but NOT including
/// those in the local zone, take precedence over later entries: if a
/// name is in the local zone but NOT in the name set, and it occurs
/// in the hosts file, it WILL be replaced!
pub async fn update_static_zone_from_hosts_file_excluding_precedent_names<P: AsRef<Path>>(
    local_zone: &mut Settings,
    names: &mut HashSet<DomainName>,
    path: P,
) -> Result<(), Error> {
    match read_to_string(path).await {
        Ok(data) => {
            update_static_zone_from_hosts_data_excluding_precedent_names(local_zone, names, &data)
        }
        Err(error) => Err(Error::IO { error }),
    }
}

/// Parse a string of hosts data and add all the entries to the local
/// zone.
///
/// Prior entries, including those already in the local zone, take
/// precedence over later entries.
pub fn update_static_zone_from_hosts_data(
    local_zone: &mut Settings,
    data: &str,
) -> Result<(), Error> {
    update_static_zone_from_hosts_data_excluding_precedent_names(
        local_zone,
        &mut get_names_from_local_zone(local_zone),
        data,
    )
}

/// Like `update_static_zone_from_hosts_data` but also takes a set of
/// names the local zone currently defines, to avoid the need to
/// re-examine it.  This also mutates the names set to add any
/// newly-defined names.
///
/// Prior entries, including those in the names set but NOT including
/// those in the local zone, take precedence over later entries: if a
/// name is in the local zone but NOT in the name set, and it occurs
/// in the hosts file, it WILL be replaced!
pub fn update_static_zone_from_hosts_data_excluding_precedent_names(
    local_zone: &mut Settings,
    names: &mut HashSet<DomainName>,
    data: &str,
) -> Result<(), Error> {
    for line in data.lines() {
        if let Some((address, new_names)) = parse_line_excluding_precedent_names(names, line)? {
            for name in new_names {
                names.insert(name.clone());
                local_zone.static_records.push(Record {
                    domain: DomainWithOptionalSubdomains {
                        name: Name { domain: name },
                        include_subdomains: false,
                    },
                    record_a: Some(address),
                    record_cname: None,
                });
            }
        }
    }

    Ok(())
}

/// Parse a single line, excluding names we already know about.
pub fn parse_line_excluding_precedent_names(
    names: &HashSet<DomainName>,
    line: &str,
) -> Result<Option<(Ipv4Addr, HashSet<DomainName>)>, Error> {
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
                        if !names.contains(&name) {
                            new_names.insert(name);
                        }
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
                if !names.contains(&name) {
                    new_names.insert(name);
                }
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

/// Get names from the local zone.
pub fn get_names_from_local_zone(local_zone: &Settings) -> HashSet<DomainName> {
    let mut names = HashSet::with_capacity(local_zone.static_records.len());
    for record in &local_zone.static_records {
        names.insert(record.domain.name.domain.clone());
    }
    names
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

    use crate::protocol::wire_types::test_util::*;

    #[test]
    fn update_does_all_ipv4_excluding_precedent_names() {
        let hosts_data = "# hark, a comment!\n\
                          1.2.3.4 one two three four\n\
                          0.0.0.0 blocked\n
                          \n\
                          127.0.0.1 localhost\n\
                          ::1 also-localhost";

        let mut local_zone = local_zone(&[
            (domain("one"), Ipv4Addr::new(1, 1, 1, 1)),
            (domain("four"), Ipv4Addr::new(4, 5, 6, 7)),
        ]);

        assert!(update_static_zone_from_hosts_data(&mut local_zone, hosts_data).is_ok());

        let mut expected_records = vec![
            record(domain("one"), Ipv4Addr::new(1, 1, 1, 1)),
            record(domain("two"), Ipv4Addr::new(1, 2, 3, 4)),
            record(domain("three"), Ipv4Addr::new(1, 2, 3, 4)),
            record(domain("four"), Ipv4Addr::new(4, 5, 6, 7)),
            record(domain("blocked"), Ipv4Addr::new(0, 0, 0, 0)),
            record(domain("localhost"), Ipv4Addr::new(127, 0, 0, 1)),
        ];

        expected_records.sort();
        local_zone.static_records.sort();

        assert_eq!(expected_records, local_zone.static_records);
    }

    #[test]
    fn parse_line_parses_ipv4_with_names() {
        if let Ok(parsed) = parse_line_excluding_precedent_names(&HashSet::new(), "1.2.3.4 foo bar")
        {
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
        if let Ok(parsed) = parse_line_excluding_precedent_names(&HashSet::new(), "1.2.3.4") {
            assert_eq!(None, parsed)
        } else {
            panic!("unexpected parse failure")
        }
    }

    #[test]
    fn parse_line_ignores_ipv6() {
        if let Ok(parsed) = parse_line_excluding_precedent_names(&HashSet::new(), "::1 localhost") {
            assert_eq!(None, parsed)
        } else {
            panic!("unexpected parse failure")
        }
    }

    #[test]
    fn parse_line_excludes_precedent_names() {
        let precedent_names = [domain("one"), domain("two")].into_iter().collect();

        if let Ok(parsed) =
            parse_line_excluding_precedent_names(&precedent_names, "1.2.3.4 one two three four")
        {
            assert_eq!(
                Some((
                    Ipv4Addr::new(1, 2, 3, 4),
                    [domain("three"), domain("four")].into_iter().collect()
                )),
                parsed
            );
        } else {
            panic!("unexpected parse failure")
        }
    }

    fn local_zone(records: &[(DomainName, Ipv4Addr)]) -> Settings {
        Settings {
            root_hints: Vec::new(),
            hosts_files: Vec::new(),
            static_records: records
                .iter()
                .map(|(name, address)| record(name.clone(), *address))
                .collect(),
        }
    }

    fn record(name: DomainName, address: Ipv4Addr) -> Record {
        Record {
            domain: DomainWithOptionalSubdomains {
                name: Name { domain: name },
                include_subdomains: false,
            },
            record_a: Some(address),
            record_cname: None,
        }
    }
}
