use std::iter::Peekable;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;
use tokio::fs::read_to_string;

use crate::protocol::types::*;
use crate::zones::types::*;

impl Zone {
    /// Read a zone file.
    ///
    /// If it has a SOA record, it is an authoritative zone: it may
    /// only have *one* SOA record, and all RRs must be subdomains of
    /// the SOA domain.
    ///
    /// If it does not have a SOA record, it is a non-authoritative
    /// zone, and the root domain will be used for its apex.
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        match read_to_string(path).await {
            Ok(data) => Self::deserialise(&data),
            Err(error) => Err(Error::IO { error }),
        }
    }

    /// Parse a string of zone data
    ///
    /// This implementation does not support `$INCLUDE` entries or
    /// non-`IN` record classes.  These will raise an error.
    pub fn deserialise(data: &str) -> Result<Self, Error> {
        let mut rrs = Vec::new();
        let mut wildcard_rrs = Vec::new();
        let mut apex_and_soa = None;
        let mut origin = None;
        let mut previous_domain = None;
        let mut previous_ttl = None;
        let mut stream = data.chars().peekable();
        while let Some(entry) = parse_entry(&origin, &previous_domain, &previous_ttl, &mut stream)?
        {
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
                        } else {
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
                        }
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
                    } else {
                        wildcard_rrs.push(rr);
                    }
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
            } else {
                zone.insert(&rr.name, rr.rtype_with_data, rr.ttl);
            }
        }

        for rr in wildcard_rrs {
            if !rr.name.is_subdomain_of(zone.get_apex()) {
                return Err(Error::NotSubdomainOfApex {
                    apex: zone.get_apex().clone(),
                    name: rr.name,
                });
            } else {
                zone.insert_wildcard(&rr.name, rr.rtype_with_data, rr.ttl);
            }
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
fn parse_entry<I: Iterator<Item = char>>(
    origin: &Option<DomainName>,
    previous_domain: &Option<MaybeWildcard>,
    previous_ttl: &Option<u32>,
    stream: &mut Peekable<I>,
) -> Result<Option<Entry>, Error> {
    loop {
        let tokens = tokenise_entry(stream)?;
        if tokens.is_empty() {
            if stream.peek() == None {
                return Ok(None);
            }
        } else if tokens[0] == "$ORIGIN" {
            return Ok(Some(parse_origin(origin, tokens)?));
        } else if tokens[0] == "$INCLUDE" {
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
fn parse_origin(origin: &Option<DomainName>, tokens: Vec<String>) -> Result<Entry, Error> {
    if tokens.len() != 2 {
        return Err(Error::WrongLen { tokens });
    }

    if tokens[0] != "$ORIGIN" {
        return Err(Error::Unexpected {
            expected: "$ORIGIN".to_string(),
            tokens,
        });
    }

    let name = parse_domain(origin, &tokens[1])?;
    Ok(Entry::Origin { name })
}

/// ```text
/// $INCLUDE <file-name> [<domain-name>]
/// ```
fn parse_include(origin: &Option<DomainName>, tokens: Vec<String>) -> Result<Entry, Error> {
    if tokens.len() != 2 && tokens.len() != 3 {
        return Err(Error::WrongLen { tokens });
    }

    if tokens[0] != "$INCLUDE" {
        return Err(Error::Unexpected {
            expected: "$INCLUDE".to_string(),
            tokens,
        });
    }

    let path = tokens[1].clone();
    let name = if tokens.len() == 3 {
        Some(parse_domain(origin, &tokens[2])?)
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
fn parse_rr(
    origin: &Option<DomainName>,
    previous_domain: &Option<MaybeWildcard>,
    previous_ttl: &Option<u32>,
    tokens: Vec<String>,
) -> Result<Entry, Error> {
    if tokens.is_empty() {
        return Err(Error::WrongLen { tokens });
    }

    if tokens.len() >= 4 {
        if let Some(rtype_with_data) = try_parse_rtype_with_data(origin, &tokens[3..]) {
            // <domain-name> <ttl>   <class> <type> <rdata>
            // <domain-name> <class> <ttl>   <type> <rdata>
            let wname = parse_domain_or_wildcard(origin, &tokens[0])?;
            let ttl = if tokens[2] == "IN" {
                parse_u32(&tokens[1])?
            } else if tokens[1] == "IN" {
                parse_u32(&tokens[2])?
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
            return if tokens[1] == "IN" {
                if tokens[0].chars().all(|c| c.is_ascii_digit()) {
                    let ttl = parse_u32(&tokens[0])?;
                    if let Some(wname) = previous_domain {
                        Ok(to_rr(wname.clone(), rtype_with_data, ttl))
                    } else {
                        Err(Error::MissingDomainName { tokens })
                    }
                } else {
                    let wname = parse_domain_or_wildcard(origin, &tokens[0])?;
                    if let Some(ttl) = previous_ttl {
                        Ok(to_rr(wname, rtype_with_data, *ttl))
                    } else if rtype_with_data.rtype() == RecordType::SOA {
                        Ok(to_rr(wname, rtype_with_data, 0))
                    } else {
                        Err(Error::MissingTTL { tokens })
                    }
                }
            } else if tokens[0] == "IN" {
                let ttl = parse_u32(&tokens[1])?;
                if let Some(wname) = previous_domain {
                    Ok(to_rr(wname.clone(), rtype_with_data, ttl))
                } else {
                    Err(Error::MissingDomainName { tokens })
                }
            } else {
                let wname = parse_domain_or_wildcard(origin, &tokens[0])?;
                let ttl = parse_u32(&tokens[1])?;
                Ok(to_rr(wname, rtype_with_data, ttl))
            };
        }
    }

    if tokens.len() >= 2 {
        if let Some(rtype_with_data) = try_parse_rtype_with_data(origin, &tokens[1..]) {
            // <domain-name>                 <type> <rdata>
            //               <ttl>           <type> <rdata>
            //                       <class> <type> <rdata>
            return if tokens[0] == "IN" {
                if let Some(wname) = previous_domain {
                    if let Some(ttl) = previous_ttl {
                        Ok(to_rr(wname.clone(), rtype_with_data, *ttl))
                    } else if rtype_with_data.rtype() == RecordType::SOA {
                        Ok(to_rr(wname.clone(), rtype_with_data, 0))
                    } else {
                        Err(Error::MissingTTL { tokens })
                    }
                } else {
                    Err(Error::MissingDomainName { tokens })
                }
            } else if tokens[0].chars().all(|c| c.is_ascii_digit()) {
                let ttl = parse_u32(&tokens[0])?;
                if let Some(wname) = previous_domain {
                    Ok(to_rr(wname.clone(), rtype_with_data, ttl))
                } else {
                    Err(Error::MissingDomainName { tokens })
                }
            } else {
                let wname = parse_domain_or_wildcard(origin, &tokens[0])?;
                if let Some(ttl) = previous_ttl {
                    Ok(to_rr(wname, rtype_with_data, *ttl))
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
                    Ok(to_rr(wname.clone(), rtype_with_data, *ttl))
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
    tokens: &[String],
) -> Option<RecordTypeWithData> {
    if tokens.is_empty() {
        return None;
    }

    match tokens[0].as_str() {
        "A" if tokens.len() == 2 => match Ipv4Addr::from_str(&tokens[1]) {
            Ok(address) => Some(RecordTypeWithData::A { address }),
            _ => None,
        },
        "NS" if tokens.len() == 2 => match parse_domain(origin, &tokens[1]) {
            Ok(nsdname) => Some(RecordTypeWithData::NS { nsdname }),
            _ => None,
        },
        "MD" if tokens.len() == 2 => match parse_domain(origin, &tokens[1]) {
            Ok(madname) => Some(RecordTypeWithData::MD { madname }),
            _ => None,
        },
        "MF" if tokens.len() == 2 => match parse_domain(origin, &tokens[1]) {
            Ok(madname) => Some(RecordTypeWithData::MF { madname }),
            _ => None,
        },
        "CNAME" if tokens.len() == 2 => match parse_domain(origin, &tokens[1]) {
            Ok(cname) => Some(RecordTypeWithData::CNAME { cname }),
            _ => None,
        },
        "SOA" if tokens.len() == 8 => match (
            parse_domain(origin, &tokens[1]),
            parse_domain(origin, &tokens[2]),
            u32::from_str(&tokens[3]),
            u32::from_str(&tokens[4]),
            u32::from_str(&tokens[5]),
            u32::from_str(&tokens[6]),
            u32::from_str(&tokens[7]),
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
        "MB" if tokens.len() == 2 => match parse_domain(origin, &tokens[1]) {
            Ok(madname) => Some(RecordTypeWithData::MB { madname }),
            _ => None,
        },
        "MG" if tokens.len() == 2 => match parse_domain(origin, &tokens[1]) {
            Ok(mdmname) => Some(RecordTypeWithData::MG { mdmname }),
            _ => None,
        },
        "MR" if tokens.len() == 2 => match parse_domain(origin, &tokens[1]) {
            Ok(newname) => Some(RecordTypeWithData::MR { newname }),
            _ => None,
        },
        "NULL" if tokens.len() == 2 => Some(RecordTypeWithData::NULL {
            octets: tokens[1].as_bytes().to_vec(),
        }),
        "WKS" if tokens.len() == 2 => Some(RecordTypeWithData::WKS {
            octets: tokens[1].as_bytes().to_vec(),
        }),
        "PTR" if tokens.len() == 2 => match parse_domain(origin, &tokens[1]) {
            Ok(ptrdname) => Some(RecordTypeWithData::PTR { ptrdname }),
            _ => None,
        },
        "HINFO" if tokens.len() == 2 => Some(RecordTypeWithData::HINFO {
            octets: tokens[1].as_bytes().to_vec(),
        }),
        "MINFO" if tokens.len() == 3 => match (
            parse_domain(origin, &tokens[1]),
            parse_domain(origin, &tokens[2]),
        ) {
            (Ok(rmailbx), Ok(emailbx)) => Some(RecordTypeWithData::MINFO { rmailbx, emailbx }),
            _ => None,
        },
        "MX" if tokens.len() == 3 => {
            match (u16::from_str(&tokens[1]), parse_domain(origin, &tokens[2])) {
                (Ok(preference), Ok(exchange)) => Some(RecordTypeWithData::MX {
                    preference,
                    exchange,
                }),
                _ => None,
            }
        }
        "TXT" if tokens.len() == 2 => Some(RecordTypeWithData::TXT {
            octets: tokens[1].as_bytes().to_vec(),
        }),
        "AAAA" if tokens.len() == 2 => match Ipv6Addr::from_str(&tokens[1]) {
            Ok(address) => Some(RecordTypeWithData::AAAA { address }),
            _ => None,
        },
        _ => None,
    }
}

/// Parse a regular or wildcard domain name.
fn parse_domain_or_wildcard(
    origin: &Option<DomainName>,
    dotted_string: &str,
) -> Result<MaybeWildcard, Error> {
    let dotted_string_vec = dotted_string.chars().collect::<Vec<char>>();

    if dotted_string_vec.is_empty() {
        panic!("reached parse_domain_or_wildcard with an empty string");
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
        let name = parse_domain(origin, &dotted_string_vec[2..].iter().collect::<String>())?;
        Ok(MaybeWildcard::Wildcard { name })
    } else {
        let name = parse_domain(origin, dotted_string)?;
        Ok(MaybeWildcard::Normal { name })
    }
}

/// Parse a domain name, appending the origin if it's not absolute.
fn parse_domain(origin: &Option<DomainName>, dotted_string: &str) -> Result<DomainName, Error> {
    let dotted_string_vec = dotted_string.chars().collect::<Vec<char>>();

    if dotted_string_vec.is_empty() {
        panic!("reached parse_domain with an empty string");
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
        if let Some(mut domain) = DomainName::from_dotted_string(dotted_string) {
            domain.labels.pop();
            domain.octets.pop();
            domain.labels.append(&mut name.labels.clone());
            domain.octets.append(&mut name.octets.clone());
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
fn tokenise_entry<I: Iterator<Item = char>>(
    stream: &mut Peekable<I>,
) -> Result<Vec<String>, Error> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut state = State::Initial;
    let mut line_continuation = false;

    while let Some(c) = stream.next() {
        state = match (state, c) {
            (State::Initial, ' ') => {
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                State::Initial
            }
            (State::Initial, '\t') => {
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                State::Initial
            }
            (State::Initial, '\r') => {
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                State::Initial
            }
            (State::Initial, '\n') => {
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                if line_continuation {
                    State::Initial
                } else {
                    break;
                }
            }
            (State::Initial, ';') => {
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                State::SkipToEndOfComment
            }
            (State::Initial, '(') => {
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                if line_continuation {
                    return Err(Error::TokeniserUnexpected { unexpected: '(' });
                } else {
                    line_continuation = true;
                    State::Initial
                }
            }
            (State::Initial, ')') => {
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                if !line_continuation {
                    return Err(Error::TokeniserUnexpected { unexpected: ')' });
                } else {
                    line_continuation = false;
                    State::Initial
                }
            }
            (State::Initial, '"') => {
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                State::QuotedString
            }
            (State::Initial, '\\') => {
                token.push(tokenise_escape(stream)?);
                State::Initial
            }
            (State::Initial, raw) => {
                token.push(raw);
                State::Initial
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
                if !token.is_empty() {
                    tokens.push(token);
                    token = String::new();
                }
                State::Initial
            }
            (State::QuotedString, '\\') => {
                token.push(tokenise_escape(stream)?);
                State::QuotedString
            }
            (State::QuotedString, raw) => {
                token.push(raw);
                State::QuotedString
            }
        }
    }

    if !token.is_empty() {
        tokens.push(token);
    }

    Ok(tokens)
}

/// Tokenise an escape sequence
fn tokenise_escape<I: Iterator<Item = char>>(stream: &mut I) -> Result<char, Error> {
    if let Some(c1) = stream.next() {
        match c1.to_digit(10) {
            Some(d1) => {
                if let Some(c2) = stream.next() {
                    match c2.to_digit(10) {
                        Some(d2) => {
                            if let Some(c3) = stream.next() {
                                match c3.to_digit(10) {
                                    Some(d3) => match u8::try_from(d1 * 100 + d2 * 10 + d3) {
                                        Ok(num) => Ok(num as char),
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
            _ => Ok(c1),
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
#[derive(Debug)]
pub enum Error {
    IO {
        error: std::io::Error,
    },
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
        tokens: Vec<String>,
    },
    ExpectedU32 {
        digits: String,
    },
    ExpectedOrigin,
    ExpectedDomainName {
        dotted_string: String,
    },
    WrongLen {
        tokens: Vec<String>,
    },
    MissingType {
        tokens: Vec<String>,
    },
    MissingTTL {
        tokens: Vec<String>,
    },
    MissingDomainName {
        tokens: Vec<String>,
    },
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
            name: domain("lan"),
            rtype_with_data: RecordTypeWithData::SOA {
                mname: domain("nyarlathotep.lan"),
                rname: domain("barrucadu.nyarlathotep.lan"),
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
            a_record("nyarlathotep.lan", Ipv4Addr::new(10, 0, 0, 3)),
        ];
        expected_all_records.sort();

        let expected_all_wildcard_records =
            vec![cname_record("nyarlathotep.lan", "nyarlathotep.lan")];

        let mut actual_all_records = Vec::with_capacity(expected_all_records.capacity());
        for (name, zrs) in zone.all_records().iter() {
            for zr in zrs {
                actual_all_records.push(zr.to_rr(name));
            }
        }
        actual_all_records.sort();

        let mut actual_all_wildcard_records =
            Vec::with_capacity(expected_all_wildcard_records.capacity());
        for (name, zrs) in zone.all_wildcard_records().iter() {
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
        let tokens = vec![
            "*".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "A".to_string(),
            "10.0.0.2".to_string(),
        ];

        assert!(matches!(
            parse_rr(&None, &None, &None, tokens.clone()),
            Err(Error::ExpectedOrigin)
        ));

        if let Ok(parsed) = parse_rr(&Some(domain("example.com")), &None, &None, tokens) {
            assert_eq!(
                Entry::WildcardRR {
                    rr: ResourceRecord {
                        name: domain("example.com"),
                        rtype_with_data: RecordTypeWithData::A {
                            address: Ipv4Addr::new(10, 0, 0, 2)
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_previous_domain() {
        let tokens = vec![
            "IN".to_string(),
            "300".to_string(),
            "A".to_string(),
            "10.0.0.2".to_string(),
        ];

        assert!(matches!(
            parse_rr(&None, &None, &None, tokens.clone()),
            Err(Error::MissingDomainName { .. })
        ));

        if let Ok(parsed) = parse_rr(
            &None,
            &Some(MaybeWildcard::Normal {
                name: domain("example.com"),
            }),
            &None,
            tokens,
        ) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("example.com"),
                        rtype_with_data: RecordTypeWithData::A {
                            address: Ipv4Addr::new(10, 0, 0, 2)
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_previous_ttl() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "A".to_string(),
            "10.0.0.2".to_string(),
        ];

        assert!(matches!(
            parse_rr(&None, &None, &None, tokens.clone()),
            Err(Error::MissingTTL { .. })
        ));

        if let Ok(parsed) = parse_rr(&None, &None, &Some(42), tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::A {
                            address: Ipv4Addr::new(10, 0, 0, 2)
                        },
                        rclass: RecordClass::IN,
                        ttl: 42
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_a() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "A".to_string(),
            "10.0.0.2".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::A {
                            address: Ipv4Addr::new(10, 0, 0, 2)
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_ns() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "NS".to_string(),
            "ns1.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::NS {
                            nsdname: domain("ns1.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_md() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "MD".to_string(),
            "madname.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::MD {
                            madname: domain("madname.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mf() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "MF".to_string(),
            "madname.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::MF {
                            madname: domain("madname.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_cname() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "CNAME".to_string(),
            "cname.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::CNAME {
                            cname: domain("cname.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_soa() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "SOA".to_string(),
            "mname.lan.".to_string(),
            "rname.lan.".to_string(),
            "100".to_string(),
            "200".to_string(),
            "300".to_string(),
            "400".to_string(),
            "500".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::SOA {
                            mname: domain("mname.lan"),
                            rname: domain("rname.lan"),
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
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mb() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "MB".to_string(),
            "madname.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::MB {
                            madname: domain("madname.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mg() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "MG".to_string(),
            "mdmname.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::MG {
                            mdmname: domain("mdmname.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mr() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "MR".to_string(),
            "newname.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::MR {
                            newname: domain("newname.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_null() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "NULL".to_string(),
            "123".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::NULL {
                            octets: vec![b'1', b'2', b'3'],
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_wks() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "WKS".to_string(),
            "123".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::WKS {
                            octets: vec![b'1', b'2', b'3'],
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_ptr() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "PTR".to_string(),
            "ptrdname.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::PTR {
                            ptrdname: domain("ptrdname.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_hinfo() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "HINFO".to_string(),
            "123".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::HINFO {
                            octets: vec![b'1', b'2', b'3'],
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_minfo() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "MINFO".to_string(),
            "rmailbx.lan.".to_string(),
            "emailbx.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::MINFO {
                            rmailbx: domain("rmailbx.lan"),
                            emailbx: domain("emailbx.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_mx() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "MX".to_string(),
            "42".to_string(),
            "exchange.lan.".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::MX {
                            preference: 42,
                            exchange: domain("exchange.lan"),
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_txt() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "TXT".to_string(),
            "123".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::TXT {
                            octets: vec![b'1', b'2', b'3'],
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
        } else {
            panic!("expected successful parse");
        }
    }

    #[test]
    fn parse_rr_aaaa() {
        let tokens = vec![
            "nyarlathotep.lan.".to_string(),
            "IN".to_string(),
            "300".to_string(),
            "AAAA".to_string(),
            "::1:2:3".to_string(),
        ];
        if let Ok(parsed) = parse_rr(&None, &None, &None, tokens) {
            assert_eq!(
                Entry::RR {
                    rr: ResourceRecord {
                        name: domain("nyarlathotep.lan"),
                        rtype_with_data: RecordTypeWithData::AAAA {
                            address: Ipv6Addr::new(0, 0, 0, 0, 0, 1, 2, 3)
                        },
                        rclass: RecordClass::IN,
                        ttl: 300
                    }
                },
                parsed
            )
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

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com")), "@") {
            assert_eq!(
                MaybeWildcard::Normal {
                    name: domain("example.com")
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

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com")), "*.@") {
            assert_eq!(
                MaybeWildcard::Wildcard {
                    name: domain("example.com")
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

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com")), "www") {
            assert_eq!(
                MaybeWildcard::Normal {
                    name: domain("www.example.com")
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

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com")), "*") {
            assert_eq!(
                MaybeWildcard::Wildcard {
                    name: domain("example.com")
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
                    name: domain("www.example.com")
                },
                name
            );
        } else {
            panic!("expected parse");
        }

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com")), "www.example.com.")
        {
            assert_eq!(
                MaybeWildcard::Normal {
                    name: domain("www.example.com")
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
                    name: domain("example.com")
                },
                name
            );
        } else {
            panic!("expected parse");
        }

        if let Ok(name) = parse_domain_or_wildcard(&Some(domain("example.com")), "*.example.com.") {
            assert_eq!(
                MaybeWildcard::Wildcard {
                    name: domain("example.com")
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
            assert_eq!(
                vec![
                    "a".to_string(),
                    "b".to_string(),
                    "c".to_string(),
                    " quoted string 1 ".to_string(),
                    "quoted string 2".to_string(),
                    "\"".to_string(),
                    "unquoted!".to_string(),
                    "(".to_string()
                ],
                tokens
            );
            assert_eq!(None, stream.next());
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_entry_multi() {
        let mut stream = "entry one\nentry two".chars().peekable();
        if let Ok(tokens1) = tokenise_entry(&mut stream) {
            assert_eq!(vec!["entry".to_string(), "one".to_string(),], tokens1);
            if let Ok(tokens2) = tokenise_entry(&mut stream) {
                assert_eq!(vec!["entry".to_string(), "two".to_string(),], tokens2);
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
            assert_eq!(
                vec![
                    "line".to_string(),
                    "with".to_string(),
                    "continuation".to_string()
                ],
                tokens
            );
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_entry_multiline_string() {
        let mut stream = "line \"with \n continuation\"".chars().peekable();
        if let Ok(tokens) = tokenise_entry(&mut stream) {
            assert_eq!(
                vec!["line".to_string(), "with \n continuation".to_string()],
                tokens
            );
        } else {
            panic!("expected tokenisation");
        }
    }

    #[test]
    fn tokenise_escape_non_numeric() {
        let mut stream = "ab".chars().peekable();
        if let Ok(c) = tokenise_escape(&mut stream) {
            assert_eq!('a', c);
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
            assert_eq!(123 as char, c);
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
            assert_eq!(123 as char, c);
            assert_eq!(Some('4'), stream.next());
        } else {
            panic!("expected tokenisation");
        }
    }
}
