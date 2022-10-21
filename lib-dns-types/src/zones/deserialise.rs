use std::iter::Peekable;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::protocol::types::*;
use crate::zones::types::*;

impl Zone {
    /// Parse a string of zone data
    ///
    /// This implementation does not support `$INCLUDE` entries or
    /// non-`IN` record classes.  These will raise an error.
    ///
    /// # Errors
    ///
    /// If the string cannot be parsed.
    pub fn deserialise(data: &str) -> Result<Self, Error> {
        let mut rrs = Vec::new();
        let mut wildcard_rrs = Vec::new();
        let mut apex_and_soa = None;
        let mut origin = None;
        let mut previous_domain = None;
        let mut previous_ttl = None;
        let mut stream = data.chars().peekable();
        while let Some(entry) = parse_entry(&origin, &previous_domain, previous_ttl, &mut stream)? {
            match entry {
                Entry::Origin { name } => origin = Some(name),
                Entry::Include { path, origin } => {
                    return Err(Error::IncludeNotSupported { path, origin })
                }
                Entry::RR { rr } => {
                    previous_domain = Some(MaybeWildcard::Normal {
                        name: rr.name.clone(),
                    });
                    previous_ttl = Some(rr.ttl);

                    if let RecordTypeWithData::SOA {
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum,
                    } = rr.rtype_with_data
                    {
                        if apex_and_soa.is_some() {
                            return Err(Error::MultipleSOA);
                        }
                        apex_and_soa = Some((
                            rr.name,
                            SOA {
                                mname,
                                rname,
                                serial,
                                refresh,
                                retry,
                                expire,
                                minimum,
                            },
                        ));
                    } else {
                        rrs.push(rr);
                    }
                }
                Entry::WildcardRR { rr } => {
                    previous_domain = Some(MaybeWildcard::Wildcard {
                        name: rr.name.clone(),
                    });
                    previous_ttl = Some(rr.ttl);

                    if rr.rtype_with_data.rtype() == RecordType::SOA {
                        return Err(Error::WildcardSOA);
                    }
                    wildcard_rrs.push(rr);
                }
            }
        }

        let mut zone = if let Some((apex, soa)) = apex_and_soa {
            Zone::new(apex, Some(soa))
        } else {
            Zone::default()
        };

        for rr in rrs {
            if !rr.name.is_subdomain_of(zone.get_apex()) {
                return Err(Error::NotSubdomainOfApex {
                    apex: zone.get_apex().clone(),
                    name: rr.name,
                });
            }
            zone.insert(&rr.name, rr.rtype_with_data, rr.ttl);
        }

        for rr in wildcard_rrs {
            if !rr.name.is_subdomain_of(zone.get_apex()) {
                return Err(Error::NotSubdomainOfApex {
                    apex: zone.get_apex().clone(),
                    name: rr.name,
                });
            }
            zone.insert_wildcard(&rr.name, rr.rtype_with_data, rr.ttl);
        }

        Ok(zone)
    }
}

/// Parse a single entry, skipping comments and whitespace.  Entries
/// are of the form:
///
/// ```text
/// $ORIGIN <domain-name>
/// $INCLUDE <file-name> [<domain-name>]
/// <rr>
/// ```
///
/// Where `<rr>` is one of these forms:
///
/// ```text
/// <domain-name> <ttl>   <class> <type> <rdata>
/// <domain-name> <class> <ttl>   <type> <rdata>
/// <domain-name> <ttl>           <type> <rdata>
/// <domain-name>         <class> <type> <rdata>
/// <domain-name>                 <type> <rdata>
///               <ttl>   <class> <type> <rdata>
///               <class> <ttl>   <type> <rdata>
///               <ttl>           <type> <rdata>
///                       <class> <type> <rdata>
///                               <type> <rdata>
/// ```
///
/// This is annoyingly flexible:
///
/// - If the `<domain-name>`, `<ttl>`, or `<class>` are missing, the
/// previous is used (so it is an error to omit it in the first RR).
///
/// - But since this implementation only supports `IN`-class records,
/// if the class is missing in the first RR, `IN` is used.
///
/// - The `<domain-name>` can be an absolute domain, given as a dotted
/// string ending in a `.`; or a relative domain, given as a dotted
/// string not ending in a `.`, in which case the origin is prepended;
/// or `@`, in which case it is the origin.
///
/// The `<rdata>` format depends on the record type.
///
/// Some special characters are:
///
/// - `@` - the current origin
/// - `;` - the rest of the line is a comment
/// - `" ... "` - a string (used for rdata)
/// - `( ... )` - a group of data which crosses a newline
/// - `\X` - quotes a character, where `X` is a non-digit
/// - `\DDD` - an octet, given as a decimal number
///
/// Returns `None` if the stream is empty.
///
/// # Errors
///
/// If the string cannot be parsed.
fn parse_entry<I: Iterator<Item = char>>(
    origin: &Option<DomainName>,
    previous_domain: &Option<MaybeWildcard>,
    previous_ttl: Option<u32>,
    stream: &mut Peekable<I>,
) -> Result<Option<Entry>, Error> {
    loop {
        let tokens = tokenise_entry(stream)?;
        if tokens.is_empty() {
            if stream.peek().is_none() {
                return Ok(None);
            }
        } else if tokens[0].0 == "$ORIGIN" {
            return Ok(Some(parse_origin(origin, tokens)?));
        } else if tokens[0].0 == "$INCLUDE" {
            return Ok(Some(parse_include(origin, tokens)?));
        } else {
            return Ok(Some(parse_rr(
                origin,
                previous_domain,
                previous_ttl,
                tokens,
            )?));
        }
    }
}

/// ```text
/// $ORIGIN <domain-name>
/// ```
///
/// # Errors
///
/// If the string cannot be parsed.
fn parse_origin(
    origin: &Option<DomainName>,
    tokens: Vec<(String, Vec<u8>)>,
) -> Result<Entry, Error> {
    if tokens.len() != 2 {
        return Err(Error::WrongLen { tokens });
    }

    if tokens[0].0 != "$ORIGIN" {
        return Err(Error::Unexpected {
            expected: "$ORIGIN".to_string(),
            tokens,
        });
    }

    let name = parse_domain(origin, &tokens[1].0)?;
    Ok(Entry::Origin { name })
}

/// ```text
/// $INCLUDE <file-name> [<domain-name>]
/// ```
///
/// # Errors
///
/// If the string cannot be parsed.
fn parse_include(
    origin: &Option<DomainName>,
    tokens: Vec<(String, Vec<u8>)>,
) -> Result<Entry, Error> {
    if tokens.len() != 2 && tokens.len() != 3 {
        return Err(Error::WrongLen { tokens });
    }

    if tokens[0].0 != "$INCLUDE" {
        return Err(Error::Unexpected {
            expected: "$INCLUDE".to_string(),
            tokens,
        });
    }

    let path = tokens[1].0.clone();
    let name = if tokens.len() == 3 {
        Some(parse_domain(origin, &tokens[2].0)?)
    } else {
        None
    };
    Ok(Entry::Include { path, origin: name })
}

/// ```text
/// <domain-name> <ttl>   <class> <type> <rdata>
/// <domain-name> <class> <ttl>   <type> <rdata>
/// <domain-name> <ttl>           <type> <rdata>
/// <domain-name>         <class> <type> <rdata>
/// <domain-name>                 <type> <rdata>
///               <ttl>   <class> <type> <rdata>
///               <class> <ttl>   <type> <rdata>
///               <ttl>           <type> <rdata>
///                       <class> <type> <rdata>
///                               <type> <rdata>
/// ```
///
/// # Errors
///
/// If the string cannot be parsed.
fn parse_rr(
    origin: &Option<DomainName>,
    previous_domain: &Option<MaybeWildcard>,
    previous_ttl: Option<u32>,
    tokens: Vec<(String, Vec<u8>)>,
) -> Result<Entry, Error> {
    if tokens.is_empty() {
        return Err(Error::WrongLen { tokens });
    }

    if tokens.len() >= 4 {
        if let Some(rtype_with_data) = try_parse_rtype_with_data(origin, &tokens[3..]) {
            // <domain-name> <ttl>   <class> <type> <rdata>
            // <domain-name> <class> <ttl>   <type> <rdata>
            let wname = parse_domain_or_wildcard(origin, &tokens[0].0)?;
            let ttl = if tokens[2].0 == "IN" {
                parse_u32(&tokens[1].0)?
            } else if tokens[1].0 == "IN" {
                parse_u32(&tokens[2].0)?
            } else {
                return Err(Error::Unexpected {
                    expected: "IN".to_string(),
                    tokens,
                });
            };

            return Ok(to_rr(wname, rtype_with_data, ttl));
        }
    }

    if tokens.len() >= 3 {
        if let Some(rtype_with_data) = try_parse_rtype_with_data(origin, &tokens[2..]) {
            // <domain-name> <ttl>           <type> <rdata>
            // <domain-name>         <class> <type> <rdata>
            //               <ttl>   <class> <type> <rdata>
            //               <class> <ttl>   <type> <rdata>
            return if tokens[1].0 == "IN" {
                if tokens[0].0.chars().all(|c| c.is_ascii_digit()) {
                    let ttl = parse_u32(&tokens[0].0)?;
                    if let Some(wname) = previous_domain {
                        Ok(to_rr(wname.clone(), rtype_with_data, ttl))
                    } else {
                        Err(Error::MissingDomainName { tokens })
                    }
                } else {
                    let wname = parse_domain_or_wildcard(origin, &tokens[0].0)?;
                    if let Some(ttl) = previous_ttl {
                        Ok(to_rr(wname, rtype_with_data, ttl))
                    } else if rtype_with_data.rtype() == RecordType::SOA {
                        Ok(to_rr(wname, rtype_with_data, 0))
                    } else {
                        Err(Error::MissingTTL { tokens })
                    }
                }
            } else if tokens[0].0 == "IN" {
                let ttl = parse_u32(&tokens[1].0)?;
                if let Some(wname) = previous_domain {
                    Ok(to_rr(wname.clone(), rtype_with_data, ttl))
                } else {
                    Err(Error::MissingDomainName { tokens })
                }
            } else {
                let wname = parse_domain_or_wildcard(origin, &tokens[0].0)?;
                let ttl = parse_u32(&tokens[1].0)?;
                Ok(to_rr(wname, rtype_with_data, ttl))
            };
        }
    }

    if tokens.len() >= 2 {
        if let Some(rtype_with_data) = try_parse_rtype_with_data(origin, &tokens[1..]) {
            // <domain-name>                 <type> <rdata>
            //               <ttl>           <type> <rdata>
            //                       <class> <type> <rdata>
            return if tokens[0].0 == "IN" {
                if let Some(wname) = previous_domain {
                    if let Some(ttl) = previous_ttl {
                        Ok(to_rr(wname.clone(), rtype_with_data, ttl))
                    } else if rtype_with_data.rtype() == RecordType::SOA {
                        Ok(to_rr(wname.clone(), rtype_with_data, 0))
                    } else {
                        Err(Error::MissingTTL { tokens })
                    }
                } else {
                    Err(Error::MissingDomainName { tokens })
                }
            } else if tokens[0].0.chars().all(|c| c.is_ascii_digit()) {
                let ttl = parse_u32(&tokens[0].0)?;
                if let Some(wname) = previous_domain {
                    Ok(to_rr(wname.clone(), rtype_with_data, ttl))
                } else {
                    Err(Error::MissingDomainName { tokens })
                }
            } else {
                let wname = parse_domain_or_wildcard(origin, &tokens[0].0)?;
                if let Some(ttl) = previous_ttl {
                    Ok(to_rr(wname, rtype_with_data, ttl))
                } else if rtype_with_data.rtype() == RecordType::SOA {
                    Ok(to_rr(wname, rtype_with_data, 0))
                } else {
                    Err(Error::MissingTTL { tokens })
                }
            };
        }
    }

    if !tokens.is_empty() {
        if let Some(rtype_with_data) = try_parse_rtype_with_data(origin, &tokens[0..]) {
            //                               <type> <rdata>
            return if let Some(wname) = previous_domain {
                if let Some(ttl) = previous_ttl {
                    Ok(to_rr(wname.clone(), rtype_with_data, ttl))
                } else if rtype_with_data.rtype() == RecordType::SOA {
                    Ok(to_rr(wname.clone(), rtype_with_data, 0))
                } else {
                    Err(Error::MissingTTL { tokens })
                }
            } else {
                Err(Error::MissingDomainName { tokens })
            };
        }
    }

    Err(Error::MissingType { tokens })
}

/// Try to parse a record type with data.  Returns `None` if there is
/// no parse, since this does not necessarily indicate a fatal error.
fn try_parse_rtype_with_data(
    origin: &Option<DomainName>,
    tokens: &[(String, Vec<u8>)],
) -> Option<RecordTypeWithData> {
    if tokens.is_empty() {
        return None;
    }

    match RecordType::from_str(tokens[0].0.as_str()) {
        Ok(RecordType::A) if tokens.len() == 2 => match Ipv4Addr::from_str(&tokens[1].0) {
            Ok(address) => Some(RecordTypeWithData::A { address }),
            _ => None,
        },
        Ok(RecordType::NS) if tokens.len() == 2 => match parse_domain(origin, &tokens[1].0) {
            Ok(nsdname) => Some(RecordTypeWithData::NS { nsdname }),
            _ => None,
        },
        Ok(RecordType::MD) if tokens.len() == 2 => match parse_domain(origin, &tokens[1].0) {
            Ok(madname) => Some(RecordTypeWithData::MD { madname }),
            _ => None,
        },
        Ok(RecordType::MF) if tokens.len() == 2 => match parse_domain(origin, &tokens[1].0) {
            Ok(madname) => Some(RecordTypeWithData::MF { madname }),
            _ => None,
        },
        Ok(RecordType::CNAME) if tokens.len() == 2 => match parse_domain(origin, &tokens[1].0) {
            Ok(cname) => Some(RecordTypeWithData::CNAME { cname }),
            _ => None,
        },
        Ok(RecordType::SOA) if tokens.len() == 8 => match (
            parse_domain(origin, &tokens[1].0),
            parse_domain(origin, &tokens[2].0),
            u32::from_str(&tokens[3].0),
            u32::from_str(&tokens[4].0),
            u32::from_str(&tokens[5].0),
            u32::from_str(&tokens[6].0),
            u32::from_str(&tokens[7].0),
        ) {
            (Ok(mname), Ok(rname), Ok(serial), Ok(refresh), Ok(retry), Ok(expire), Ok(minimum)) => {
                Some(RecordTypeWithData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            _ => None,
        },
        Ok(RecordType::MB) if tokens.len() == 2 => match parse_domain(origin, &tokens[1].0) {
            Ok(madname) => Some(RecordTypeWithData::MB { madname }),
            _ => None,
        },
        Ok(RecordType::MG) if tokens.len() == 2 => match parse_domain(origin, &tokens[1].0) {
            Ok(mdmname) => Some(RecordTypeWithData::MG { mdmname }),
            _ => None,
        },
        Ok(RecordType::MR) if tokens.len() == 2 => match parse_domain(origin, &tokens[1].0) {
            Ok(newname) => Some(RecordTypeWithData::MR { newname }),
            _ => None,
        },
        Ok(RecordType::NULL) if tokens.len() == 2 => Some(RecordTypeWithData::NULL {
            octets: tokens[1].1.clone(),
        }),
        Ok(RecordType::WKS) if tokens.len() == 2 => Some(RecordTypeWithData::WKS {
            octets: tokens[1].1.clone(),
        }),
        Ok(RecordType::PTR) if tokens.len() == 2 => match parse_domain(origin, &tokens[1].0) {
            Ok(ptrdname) => Some(RecordTypeWithData::PTR { ptrdname }),
            _ => None,
        },
        Ok(RecordType::HINFO) if tokens.len() == 2 => Some(RecordTypeWithData::HINFO {
            octets: tokens[1].1.clone(),
        }),
        Ok(RecordType::MINFO) if tokens.len() == 3 => match (
            parse_domain(origin, &tokens[1].0),
            parse_domain(origin, &tokens[2].0),
        ) {
            (Ok(rmailbx), Ok(emailbx)) => Some(RecordTypeWithData::MINFO { rmailbx, emailbx }),
            _ => None,
        },
        Ok(RecordType::MX) if tokens.len() == 3 => {
            match (
                u16::from_str(&tokens[1].0),
                parse_domain(origin, &tokens[2].0),
            ) {
                (Ok(preference), Ok(exchange)) => Some(RecordTypeWithData::MX {
                    preference,
                    exchange,
                }),
                _ => None,
            }
        }
        Ok(RecordType::TXT) if tokens.len() == 2 => Some(RecordTypeWithData::TXT {
            octets: tokens[1].1.clone(),
        }),
        Ok(RecordType::AAAA) if tokens.len() == 2 => match Ipv6Addr::from_str(&tokens[1].0) {
            Ok(address) => Some(RecordTypeWithData::AAAA { address }),
            _ => None,
        },
        Ok(RecordType::SRV) if tokens.len() == 5 => match (
            u16::from_str(&tokens[1].0),
            u16::from_str(&tokens[2].0),
            u16::from_str(&tokens[3].0),
            parse_domain(origin, &tokens[4].0),
        ) {
            (Ok(priority), Ok(weight), Ok(port), Ok(target)) => Some(RecordTypeWithData::SRV {
                priority,
                weight,
                port,
                target,
            }),
            _ => None,
        },
        _ => None,
    }
}

/// Parse a regular or wildcard domain name.
///
/// # Errors
///
/// If the string cannot be parsed.
fn parse_domain_or_wildcard(
    origin: &Option<DomainName>,
    dotted_string: &str,
) -> Result<MaybeWildcard, Error> {
    let dotted_string_vec = dotted_string.chars().collect::<Vec<char>>();

    if dotted_string_vec.is_empty() {
        return Err(Error::ExpectedDomainName {
            dotted_string: dotted_string.to_string(),
        });
    }

    if dotted_string == "*" {
        if let Some(name) = origin {
            Ok(MaybeWildcard::Wildcard { name: name.clone() })
        } else {
            Err(Error::ExpectedOrigin)
        }
    } else if dotted_string_vec.len() >= 2
        && dotted_string_vec[0] == '*'
        && dotted_string_vec[1] == '.'
    {
        let name = if dotted_string_vec.len() == 2 {
            DomainName::root_domain()
        } else {
            parse_domain(origin, &dotted_string_vec[2..].iter().collect::<String>())?
        };
        Ok(MaybeWildcard::Wildcard { name })
    } else {
        let name = parse_domain(origin, dotted_string)?;
        Ok(MaybeWildcard::Normal { name })
    }
}

/// Parse a domain name, appending the origin if it's not absolute.
///
/// # Errors
///
/// If the string cannot be parsed.
fn parse_domain(origin: &Option<DomainName>, dotted_string: &str) -> Result<DomainName, Error> {
    let dotted_string_vec = dotted_string.chars().collect::<Vec<char>>();

    if dotted_string_vec.is_empty() {
        return Err(Error::ExpectedDomainName {
            dotted_string: dotted_string.to_string(),
        });
    }

    if !dotted_string_vec.iter().all(char::is_ascii) {
        return Err(Error::ExpectedDomainName {
            dotted_string: dotted_string.to_string(),
        });
    }

    if dotted_string == "@" {
        if let Some(name) = origin {
            Ok(name.clone())
        } else {
            Err(Error::ExpectedOrigin)
        }
    } else if dotted_string_vec[dotted_string_vec.len() - 1] == '.' {
        if let Some(domain) = DomainName::from_dotted_string(dotted_string) {
            Ok(domain)
        } else {
            Err(Error::ExpectedDomainName {
                dotted_string: dotted_string.to_string(),
            })
        }
    } else if let Some(name) = origin {
        if let Some(domain) = DomainName::from_relative_dotted_string(name, dotted_string) {
            Ok(domain)
        } else {
            Err(Error::ExpectedDomainName {
                dotted_string: dotted_string.to_string(),
            })
        }
    } else {
        Err(Error::ExpectedOrigin)
    }
}

/// Parse a decimal number into a u32.
///
/// # Errors
///
/// If the string cannot be parsed.
fn parse_u32(digits: &str) -> Result<u32, Error> {
    if let Ok(val) = u32::from_str(digits) {
        Ok(val)
    } else {
        Err(Error::ExpectedU32 {
            digits: digits.to_string(),
        })
    }
}

/// Helper for `parse_rr`
fn to_rr(wname: MaybeWildcard, rtype_with_data: RecordTypeWithData, ttl: u32) -> Entry {
    let ttl = if let RecordTypeWithData::SOA { minimum, .. } = rtype_with_data {
        minimum
    } else {
        ttl
    };

    match wname {
        MaybeWildcard::Normal { name } => Entry::RR {
            rr: ResourceRecord {
                name,
                rtype_with_data,
                rclass: RecordClass::IN,
                ttl,
            },
        },
        MaybeWildcard::Wildcard { name } => Entry::WildcardRR {
            rr: ResourceRecord {
                name,
                rtype_with_data,
                rclass: RecordClass::IN,
                ttl,
            },
        },
    }
}

/// Split an entry into tokens: split on whitespace, taking quoting
/// into account, and if there are parentheses or quotes continue to
/// the matched delimiter.
///
/// # Errors
///
/// If the string cannot be parsed.
fn tokenise_entry<I: Iterator<Item = char>>(
    stream: &mut Peekable<I>,
) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let mut tokens = Vec::new();
    let mut token_string = String::new();
    let mut token_octets = Vec::new();
    let mut state = State::Initial;
    let mut line_continuation = false;

    while let Some(c) = stream.next() {
        state = match (state, c) {
            (State::Initial, '\n') => {
                if line_continuation {
                    State::Initial
                } else {
                    break;
                }
            }
            (State::Initial, ';') => State::SkipToEndOfComment,
            (State::Initial, '(') => {
                if line_continuation {
                    return Err(Error::TokeniserUnexpected { unexpected: '(' });
                }
                line_continuation = true;
                State::Initial
            }
            (State::Initial, ')') => {
                if line_continuation {
                    line_continuation = false;
                    State::Initial
                } else {
                    return Err(Error::TokeniserUnexpected { unexpected: ')' });
                }
            }
            (State::Initial, '"') => State::QuotedString,
            (State::Initial, '\\') => {
                let octet = tokenise_escape(stream)?;
                token_string.push(octet as char);
                token_octets.push(octet);
                State::UnquotedString
            }
            (State::Initial, c) => {
                if c.is_whitespace() {
                    State::Initial
                } else if c.is_ascii() {
                    token_string.push(c);
                    token_octets.push(c as u8);
                    State::UnquotedString
                } else {
                    return Err(Error::TokeniserUnexpected { unexpected: c });
                }
            }

            (State::UnquotedString, '\n') => {
                if !token_string.is_empty() {
                    tokens.push((token_string, token_octets));
                    token_string = String::new();
                    token_octets = Vec::new();
                }
                if line_continuation {
                    State::Initial
                } else {
                    break;
                }
            }
            (State::UnquotedString, ';') => {
                if !token_string.is_empty() {
                    tokens.push((token_string, token_octets));
                    token_string = String::new();
                    token_octets = Vec::new();
                }
                State::SkipToEndOfComment
            }
            (State::UnquotedString, '\\') => {
                let octet = tokenise_escape(stream)?;
                token_string.push(octet as char);
                token_octets.push(octet);
                State::UnquotedString
            }
            (State::UnquotedString, c) => {
                if c.is_whitespace() {
                    if !token_string.is_empty() {
                        tokens.push((token_string, token_octets));
                        token_string = String::new();
                        token_octets = Vec::new();
                    }
                    State::Initial
                } else if c.is_ascii() {
                    token_string.push(c);
                    token_octets.push(c as u8);
                    State::UnquotedString
                } else {
                    return Err(Error::TokeniserUnexpected { unexpected: c });
                }
            }

            (State::SkipToEndOfComment, '\n') => {
                if line_continuation {
                    State::Initial
                } else {
                    break;
                }
            }
            (State::SkipToEndOfComment, _) => State::SkipToEndOfComment,

            (State::QuotedString, '"') => {
                tokens.push((token_string, token_octets));
                token_string = String::new();
                token_octets = Vec::new();
                State::Initial
            }
            (State::QuotedString, '\\') => {
                let octet = tokenise_escape(stream)?;
                token_string.push(octet as char);
                token_octets.push(octet);
                State::QuotedString
            }
            (State::QuotedString, c) => {
                if c.is_ascii() {
                    token_string.push(c);
                    token_octets.push(c as u8);
                } else {
                    return Err(Error::TokeniserUnexpected { unexpected: c });
                }
                State::QuotedString
            }
        }
    }

    if !token_string.is_empty() {
        tokens.push((token_string, token_octets));
    }

    Ok(tokens)
}

/// Tokenise an escape sequence
///
/// # Errors
///
/// If the string cannot be parsed.
fn tokenise_escape<I: Iterator<Item = char>>(stream: &mut I) -> Result<u8, Error> {
    if let Some(c1) = stream.next() {
        match c1.to_digit(10) {
            Some(d1) => {
                if let Some(c2) = stream.next() {
                    match c2.to_digit(10) {
                        Some(d2) => {
                            if let Some(c3) = stream.next() {
                                match c3.to_digit(10) {
                                    Some(d3) => match u8::try_from(d1 * 100 + d2 * 10 + d3) {
                                        Ok(num) => Ok(num),
                                        _ => Err(Error::TokeniserUnexpectedEscape {
                                            unexpected: vec![c1, c2, c3],
                                        }),
                                    },
                                    _ => Err(Error::TokeniserUnexpectedEscape {
                                        unexpected: vec![c1, c2, c3],
                                    }),
                                }
                            } else {
                                Err(Error::TokeniserUnexpectedEscape {
                                    unexpected: vec![c1, c2],
                                })
                            }
                        }
                        _ => Err(Error::TokeniserUnexpectedEscape {
                            unexpected: vec![c1, c2],
                        }),
                    }
                } else {
                    Err(Error::TokeniserUnexpectedEscape {
                        unexpected: vec![c1],
                    })
                }
            }
            _ => {
                if c1.is_ascii() {
                    Ok(c1 as u8)
                } else {
                    Err(Error::TokeniserUnexpected { unexpected: c1 })
                }
            }
        }
    } else {
        Err(Error::TokeniserUnexpectedEscape {
            unexpected: Vec::new(),
        })
    }
}

/// States the tokeniser can be in
enum State {
    Initial,
    SkipToEndOfComment,
    UnquotedString,
    QuotedString,
}

/// A regular or wildcard domain
#[derive(Debug, Clone, PartialEq, Eq)]
enum MaybeWildcard {
    Normal { name: DomainName },
    Wildcard { name: DomainName },
}

/// An entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Origin {
        name: DomainName,
    },
    Include {
        path: String,
        origin: Option<DomainName>,
    },
    RR {
        rr: ResourceRecord,
    },
    WildcardRR {
        rr: ResourceRecord,
    },
}

/// An error that can occur reading a zone file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TokeniserUnexpected {
        unexpected: char,
    },
    TokeniserUnexpectedEscape {
        unexpected: Vec<char>,
    },
    IncludeNotSupported {
        path: String,
        origin: Option<DomainName>,
    },
    MultipleSOA,
    WildcardSOA,
    NotSubdomainOfApex {
        apex: DomainName,
        name: DomainName,
    },
    Unexpected {
        expected: String,
        tokens: Vec<(String, Vec<u8>)>,
    },
    ExpectedU32 {
        digits: String,
    },
    ExpectedOrigin,
    ExpectedDomainName {
        dotted_string: String,
    },
    WrongLen {
        tokens: Vec<(String, Vec<u8>)>,
    },
    MissingType {
        tokens: Vec<(String, Vec<u8>)>,
    },
    MissingTTL {
        tokens: Vec<(String, Vec<u8>)>,
    },
    MissingDomainName {
        tokens: Vec<(String, Vec<u8>)>,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::TokeniserUnexpected { unexpected } => write!(f, "unexpected '{unexpected:?}'"),
            Error::TokeniserUnexpectedEscape { unexpected } => {
                write!(f, "unexpected escape '{unexpected:?}'")
            }
            Error::IncludeNotSupported { .. } => write!(f, "'$INCLUDE' directive not supported"),
            Error::MultipleSOA => write!(f, "multiple SOA records, expected one or zero"),
            Error::WildcardSOA => write!(f, "wildcard SOA record not allowed"),
            Error::NotSubdomainOfApex { apex, name } => {
                write!(
                    f,
                    "domain name '{name}' not a subdomain of the apex '{apex}'"
                )
            }
            Error::Unexpected { expected, .. } => write!(f, "expected '{expected:?}'"),
            Error::ExpectedU32 { digits } => write!(f, "expected u32, got '{digits:?}'"),
            Error::ExpectedOrigin => write!(f, "relative domain name used without origin"),
            Error::ExpectedDomainName { dotted_string } => {
                write!(f, "could not parse domain name '{dotted_string}'")
            }
            Error::WrongLen { .. } => write!(f, "zone file incomplete"),
            Error::MissingType { .. } => write!(f, "missing type in record definition"),
            Error::MissingTTL { .. } => write!(f, "missing TTL in record definition"),
            Error::MissingDomainName { .. } => {
                write!(f, "missing domain name in record definition")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::types::test_util::*;

    use super::*;

    #[test]
    fn parse_zone() {
        let zone_data = "$ORIGIN lan.\n\
                         \n\
                         @    IN    SOA    nyarlathotep.lan. barrucadu.nyarlathotep.lan. 1 30 30 30 30\n\
                         \n\
                         nyarlathotep      300    IN    A        10.0.0.3\n\
                         *.nyarlathotep    300    IN    CNAME    nyarlathotep.lan.";
        let zone = Zone::deserialise(zone_data).unwrap();

        let soa_record = ResourceRecord {
            name: domain("lan."),
            rtype_with_data: RecordTypeWithData::SOA {
                mname: domain("nyarlathotep.lan."),
                rname: domain("barrucadu.nyarlathotep.lan."),
                serial: 1,
                refresh: 30,
                retry: 30,
                expire: 30,
                minimum: 30,
            },
            rclass: RecordClass::IN,
            ttl: 30,
        };

        let mut expected_all_records = vec![
            soa_record,
            a_record("nyarlathotep.lan.", Ipv4Addr::new(10, 0, 0, 3)),
        ];
        expected_all_records.sort();

        let expected_all_wildcard_records =
            vec![cname_record("nyarlathotep.lan.", "nyarlathotep.lan.")];

        let mut actual_all_records = Vec::with_capacity(expected_all_records.capacity());
        for (name, zrs) in &zone.all_records() {
            for zr in zrs {
                actual_all_records.push(zr.to_rr(name));
            }
        }
        actual_all_records.sort();

        let mut actual_all_wildcard_records =
            Vec::with_capacity(expected_all_wildcard_records.capacity());
        for (name, zrs) in &zone.all_wildcard_records() {
            for zr in zrs {
                actual_all_wildcard_records.push(zr.to_rr(name));
            }
        }
        actual_all_wildcard_records.sort();

        assert_eq!(expected_all_records, actual_all_records);
        assert_eq!(expected_all_wildcard_records, actual_all_wildcard_records);
    }

    #[test]
    fn parse_rr_origin() {
        let tokens = tokenise_str("* IN 300 A 10.0.0.2");

        assert!(matches!(
            parse_rr(&None, &None, None, tokens.clone()),
            Err(Error::ExpectedOrigin)
        ));

        if let Ok(parsed) = parse_rr(&Some(domain("example.com.")), &None, None, tokens) {
            assert_eq!(
                Entry::WildcardRR {
                    rr: ResourceRecord {
                        name: domain("example.com."),
                        rtype_with_data: RecordTypeWithData::A {
                            address: Ipv4Addr::new(10, 0, 0, 2)
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_previous_domain() {
        let tokens = tokenise_str("IN 300 A 10.0.0.2");

        assert!(matches!(
            parse_rr(&None, &None, None, tokens.clone()),
            Err(Error::MissingDomainName { .. })
        ));

        if let Ok(parsed) = parse_rr(
            &None,
            &Some(MaybeWildcard::Normal {
                name: domain("example.com."),
            }),
            None,
            tokens,
        ) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("example.com."),
                        rtype_with_data: RecordTypeWithData::A {
                            address: Ipv4Addr::new(10, 0, 0, 2)
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_previous_ttl() {
        let tokens = tokenise_str("nyarlathotep.lan. IN A 10.0.0.2");

        assert!(matches!(
            parse_rr(&None, &None, None, tokens.clone()),
            Err(Error::MissingTTL { .. })
        ));

        if let Ok(parsed) = parse_rr(&None, &None, Some(42), tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::A {
                            address: Ipv4Addr::new(10, 0, 0, 2)
                        },
                        rclass: RecordClass::IN,
                        ttl: 42
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_a() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 A 10.0.0.2");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::A {
                            address: Ipv4Addr::new(10, 0, 0, 2)
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_ns() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 NS ns1.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::NS {
                            nsdname: domain("ns1.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_md() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 MD madname.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::MD {
                            madname: domain("madname.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mf() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 MF madname.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::MF {
                            madname: domain("madname.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_cname() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 CNAME cname.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::CNAME {
                            cname: domain("cname.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_soa() {
        let tokens =
            tokenise_str("nyarlathotep.lan. IN 300 SOA mname.lan. rname.lan. 100 200 300 400 500");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::SOA {
                            mname: domain("mname.lan."),
                            rname: domain("rname.lan."),
                            serial: 100,
                            refresh: 200,
                            retry: 300,
                            expire: 400,
                            minimum: 500,
                        },
                        rclass: RecordClass::IN,
                        ttl: 500
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mb() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 MB madname.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::MB {
                            madname: domain("madname.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mg() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 MG mdmname.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::MG {
                            mdmname: domain("mdmname.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mr() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 MR newname.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::MR {
                            newname: domain("newname.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_null() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 NULL 123");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::NULL {
                            octets: vec![b'1', b'2', b'3'],
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_wks() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 WKS 123");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::WKS {
                            octets: vec![b'1', b'2', b'3'],
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_ptr() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 PTR ptrdname.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::PTR {
                            ptrdname: domain("ptrdname.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_hinfo() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 HINFO 123");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::HINFO {
                            octets: vec![b'1', b'2', b'3'],
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_minfo() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 MINFO rmailbx.lan. emailbx.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::MINFO {
                            rmailbx: domain("rmailbx.lan."),
                            emailbx: domain("emailbx.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mx() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 MX 42 exchange.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::MX {
                            preference: 42,
                            exchange: domain("exchange.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_txt() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 TXT 123");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::TXT {
                            octets: vec![b'1', b'2', b'3'],
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_aaaa() {
        let tokens = tokenise_str("nyarlathotep.lan. IN 300 AAAA ::1:2:3");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::AAAA {
                            address: Ipv6Addr::new(0, 0, 0, 0, 0, 1, 2, 3)
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_srv() {
        let tokens =
            tokenise_str("_service._tcp.nyarlathotep.lan. IN 300 SRV 0 0 8080 game-server.lan.");
        if let Ok(parsed) = parse_rr(&None, &None, None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("_service._tcp.nyarlathotep.lan."),
                        rtype_with_data: RecordTypeWithData::SRV {
                            priority: 0,
                            weight: 0,
                            port: 8080,
                            target: domain("game-server.lan."),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            );
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_domain_or_wildcard_origin() {
        assert!(matches!(
            parse_domain_or_wildcard(&None, "@"),
            Err(Error::ExpectedOrigin)
        ));

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com.")), "@") {
            assert_eq!(
                MaybeWildcard::Normal {
                    name: domain("example.com.")
                },
                name
            );
        } else {
            panic!("expected parse");
        }
    }

    #[test]
    fn parse_domain_or_wildcard_wildcard_origin() {
        assert!(matches!(
            parse_domain_or_wildcard(&None, "*.@"),
            Err(Error::ExpectedOrigin)
        ));

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com.")), "*.@") {
            assert_eq!(
                MaybeWildcard::Wildcard {
                    name: domain("example.com.")
                },
                name
            );
        } else {
            panic!("expected parse");
        }
    }

    #[test]
    fn parse_domain_or_wildcard_relative() {
        assert!(matches!(
            parse_domain_or_wildcard(&None, "www"),
            Err(Error::ExpectedOrigin)
        ));

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com.")), "www") {
            assert_eq!(
                MaybeWildcard::Normal {
                    name: domain("www.example.com.")
                },
                name
            );
        } else {
            panic!("expected parse");
        }
    }

    #[test]
    fn parse_domain_or_wildcard_wildcard_relative() {
        assert!(matches!(
            parse_domain_or_wildcard(&None, "*"),
            Err(Error::ExpectedOrigin)
        ));

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com.")), "*") {
            assert_eq!(
                MaybeWildcard::Wildcard {
                    name: domain("example.com.")
                },
                name
            );
        } else {
            panic!("expected parse");
        }
    }

    #[test]
    fn parse_domain_or_wildcard_absolute() {
        if let Ok(name) = parse_domain_or_wildcard(&None, "www.example.com.") {
            assert_eq!(
                MaybeWildcard::Normal {
                    name: domain("www.example.com.")
                },
                name
            );
        } else {
            panic!("expected parse");
        }

        if let Ok(name) =
            parse_domain_or_wildcard(&Some(domain("example.com.")), "www.example.com.")
        {
            assert_eq!(
                MaybeWildcard::Normal {
                    name: domain("www.example.com.")
                },
                name
            );
        } else {
            panic!("expected parse");
        }
    }

    #[test]
    fn parse_domain_or_wildcard_wildcard_absolute() {
        if let Ok(name) = parse_domain_or_wildcard(&None, "*.example.com.") {
            assert_eq!(
                MaybeWildcard::Wildcard {
                    name: domain("example.com.")
                },
                name
            );
        } else {
            panic!("expected parse");
        }

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com.")), "*.example.com.")
        {
            assert_eq!(
                MaybeWildcard::Wildcard {
                    name: domain("example.com.")
                },
                name
            );
        } else {
            panic!("expected parse");
        }
    }

    #[test]
    fn parse_domain_or_wildcard_wildcard_root() {
        if let Ok(name) = parse_domain_or_wildcard(&None, "*.") {
            assert_eq!(
                MaybeWildcard::Wildcard {
                    name: DomainName::root_domain()
                },
                name
            );
        } else {
            panic!("expected parse");
        }
    }

    #[test]
    fn tokenise_entry_single() {
        let mut stream = "a b c \" quoted string 1 \" \"quoted string 2\" \\\" unquoted! \\("
            .chars()
            .peekable();
        if let Ok(tokens) = tokenise_entry(&mut stream) {
            assert_eq!(8, tokens.len());
            assert_eq!("a".to_string(), tokens[0].0);
            assert_eq!("b".to_string(), tokens[1].0);
            assert_eq!("c".to_string(), tokens[2].0);
            assert_eq!(" quoted string 1 ".to_string(), tokens[3].0);
            assert_eq!("quoted string 2".to_string(), tokens[4].0);
            assert_eq!("\"".to_string(), tokens[5].0);
            assert_eq!("unquoted!".to_string(), tokens[6].0);
            assert_eq!("(".to_string(), tokens[7].0);
            assert_eq!(None, stream.next());
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_entry_multi() {
        let mut stream = "entry one\nentry two".chars().peekable();
        if let Ok(tokens1) = tokenise_entry(&mut stream) {
            assert_eq!(2, tokens1.len());
            assert_eq!("entry".to_string(), tokens1[0].0);
            assert_eq!("one".to_string(), tokens1[1].0);

            if let Ok(tokens2) = tokenise_entry(&mut stream) {
                assert_eq!(2, tokens2.len());
                assert_eq!("entry".to_string(), tokens2[0].0);
                assert_eq!("two".to_string(), tokens2[1].0);

                assert_eq!(None, stream.next());
            } else {
                panic!("expected tokenisation of entry 1");
            }
        } else {
            panic!("expected tokenisation of entry 1");
        }
    }

    #[test]
    fn tokenise_entry_multiline_continuation() {
        let mut stream = "line ( with \n continuation )".chars().peekable();
        if let Ok(tokens) = tokenise_entry(&mut stream) {
            assert_eq!(3, tokens.len());
            assert_eq!("line".to_string(), tokens[0].0);
            assert_eq!("with".to_string(), tokens[1].0);
            assert_eq!("continuation".to_string(), tokens[2].0);
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_entry_multiline_string() {
        let mut stream = "line \"with \n continuation\"".chars().peekable();
        if let Ok(tokens) = tokenise_entry(&mut stream) {
            assert_eq!(2, tokens.len());
            assert_eq!("line".to_string(), tokens[0].0);
            assert_eq!("with \n continuation".to_string(), tokens[1].0);
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_entry_handles_embedded_quotes() {
        let entry = "foo\"bar\"baz";
        if let Ok(tokens) = tokenise_entry(&mut entry.chars().peekable()) {
            assert!(!tokens.is_empty());
            assert_eq!(entry, tokens[0].0);
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_escape_non_numeric() {
        let mut stream = "ab".chars().peekable();
        if let Ok(c) = tokenise_escape(&mut stream) {
            assert_eq!(b'a', c);
            assert_eq!(Some('b'), stream.next());
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_escape_one_digits() {
        assert!(matches!(
            tokenise_escape(&mut "1".chars().peekable()),
            Err(Error::TokeniserUnexpectedEscape { .. })
        ));
    }

    #[test]
    fn tokenise_escape_two_digits() {
        assert!(matches!(
            tokenise_escape(&mut "12".chars().peekable()),
            Err(Error::TokeniserUnexpectedEscape { .. })
        ));
    }

    #[test]
    fn tokenise_escape_three_digits() {
        let mut stream = "123".chars().peekable();
        if let Ok(c) = tokenise_escape(&mut stream) {
            assert_eq!(123, c);
            assert_eq!(None, stream.next());
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_escape_three_digits_too_big() {
        assert!(matches!(
            tokenise_escape(&mut "999".chars().peekable()),
            Err(Error::TokeniserUnexpectedEscape { .. })
        ));
    }

    #[test]
    fn tokenise_escape_four_digits() {
        let mut stream = "1234".chars().peekable();
        if let Ok(c) = tokenise_escape(&mut stream) {
            assert_eq!(123, c);
            assert_eq!(Some('4'), stream.next());
        } else {
            panic!("expected tokenisation");
        }
    }

    fn tokenise_str(s: &str) -> Vec<(String, Vec<u8>)> {
        tokenise_entry(&mut s.chars().peekable()).unwrap()
    }
}
