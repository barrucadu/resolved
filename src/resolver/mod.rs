pub mod cache;
pub mod rr_util;

use async_recursion::async_recursion;
use rand::Rng;
use std::cmp::Ordering;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use self::cache::SharedCache;
use self::rr_util::*;

use crate::net_util::{read_tcp_bytes, send_tcp_bytes, send_udp_bytes};
use crate::protocol::wire_types::*;
use crate::zones::{ZoneResult, Zones};

/// Resolve a question using the standard DNS algorithms.
pub async fn resolve(
    is_recursive: bool,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    if is_recursive {
        resolve_recursive(zones, cache, question).await
    } else {
        resolve_nonrecursive(zones, cache, question)
    }
}

/// Non-recursive DNS resolution.
///
/// This corresponds to steps 2, 3, and 4 of the standard nameserver
/// algorithm:
///
/// - step 1 is "check if this is a recursive query and go to step 5
///   if so, step 2 if not;
///
/// - step 5 is "use the recursive resolution algorithm instead"; and
///
/// - step 6 is "add useful additional records", which is delightfully
///   vague and I'm skipping for now since I can't see evidence of
///   other servers doing this.
///
/// This function gives up if the CNAMEs form a cycle.
///
/// See section 4.3.2 of RFC 1034.
pub fn resolve_nonrecursive(
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    // TODO: bound recursion depth

    let mut rrs_from_zone = Vec::new();

    if let Some(zone) = zones.get(&question.name) {
        // `zone.resolve` implements the non-recursive part of step 3
        // of the standard resolver algorithm: matching down through
        // the zone and returning what sort of end state is reached.
        match zone.resolve(&question.name, question.qtype) {
            // If we get an answer:
            //
            // - if the zone is authoritative: we're done; this fully
            // answers the question, there's no need to consult the
            // cache for additional records.
            //
            // - if the zone is not authoritative: store the RRs but
            // pass the query onto the cache (handled below), to see
            // if this fetches any new records.
            Some(ZoneResult::Answer { rrs }) => {
                println!(
                    "[DEBUG] zone {:?} {} ANSWER for {:?} {:?} {:?}",
                    zone.get_apex().to_dotted_string(),
                    if zone.is_authoritative() {
                        "AUTHORITATIVE"
                    } else {
                        "NON-AUTHORITATIVE"
                    },
                    question.name.to_dotted_string(),
                    question.qclass,
                    question.qtype
                );

                if let Some(soa_rr) = zone.soa_rr() {
                    return Some(ResolvedRecord::Authoritative {
                        rrs,
                        authority_rrs: vec![soa_rr],
                    });
                } else {
                    rrs_from_zone = rrs;
                }
            }
            // If the name is a CNAME, try resolving it, then:
            //
            // - if resolving it only touches authoritative zones:
            // return the response, which is authoritative if and only
            // if this starting zone is authoritative, without
            // consulting the cache for additional records.
            //
            // - if resolving it touches non-authoritative zones or
            // the cache: return the response, which is not
            // authoritative.
            //
            // - if resolving it fails: return the response, which is
            // authoritative if and only if this starting zone is
            // authoritative.
            Some(ZoneResult::CNAME { cname_rr }) => {
                println!(
                    "[DEBUG] zone {:?} {} CNAME for {:?} {:?} {:?}",
                    zone.get_apex().to_dotted_string(),
                    if zone.is_authoritative() {
                        "AUTHORITATIVE"
                    } else {
                        "NON-AUTHORITATIVE"
                    },
                    question.name.to_dotted_string(),
                    question.qclass,
                    question.qtype
                );

                let cname = if let RecordTypeWithData::CNAME { cname } = &cname_rr.rtype_with_data {
                    cname
                } else {
                    println!("[ERROR] expected CNAME RR (in zone)");
                    return None;
                };

                return Some(
                    match resolve_nonrecursive(
                        zones,
                        cache,
                        &Question {
                            name: cname.clone(),
                            qtype: question.qtype,
                            qclass: question.qclass,
                        },
                    ) {
                        Some(ResolvedRecord::Authoritative {
                            rrs: mut cname_rrs, ..
                        }) => {
                            let mut rrs = vec![cname_rr.clone()];
                            rrs.append(&mut cname_rrs);

                            if zone.is_authoritative() {
                                ResolvedRecord::Authoritative {
                                    rrs,
                                    authority_rrs: Vec::new(),
                                }
                            } else {
                                ResolvedRecord::NonAuthoritative { rrs }
                            }
                        }
                        Some(ResolvedRecord::NonAuthoritative { rrs: mut cname_rrs }) => {
                            let mut rrs = vec![cname_rr.clone()];
                            rrs.append(&mut cname_rrs);
                            ResolvedRecord::NonAuthoritative { rrs }
                        }
                        _ => {
                            if let Some(soa_rr) = zone.soa_rr() {
                                ResolvedRecord::Authoritative {
                                    rrs: vec![cname_rr.clone()],
                                    authority_rrs: vec![soa_rr],
                                }
                            } else {
                                ResolvedRecord::NonAuthoritative {
                                    rrs: vec![cname_rr.clone()],
                                }
                            }
                        }
                    },
                );
            }
            // If the name is delegated:
            //
            // - if this zone is authoritative, return the response
            // with the NS RRs in the AUTHORITY section.
            //
            // - otherwise ignore and proceed to cache.
            Some(ZoneResult::Delegation { ns_rrs }) => {
                println!(
                    "[DEBUG] zone {:?} {} DELEGATION for {:?} {:?} {:?}",
                    zone.get_apex().to_dotted_string(),
                    if zone.is_authoritative() {
                        "AUTHORITATIVE"
                    } else {
                        "NON-AUTHORITATIVE"
                    },
                    question.name.to_dotted_string(),
                    question.qclass,
                    question.qtype
                );

                if zone.is_authoritative() {
                    return Some(ResolvedRecord::Authoritative {
                        rrs: Vec::new(),
                        authority_rrs: ns_rrs,
                    });
                }
            }
            // If the name could not be resolved:
            //
            // - if this zone is authoritative, a NXDOMAIN response
            // (todo)
            //
            // - otherwise ignore and proceed to cache.
            Some(ZoneResult::NameError) => {
                println!(
                    "[DEBUG] zone {:?} {} NAME ERROR for {:?} {:?} {:?}",
                    zone.get_apex().to_dotted_string(),
                    if zone.is_authoritative() {
                        "AUTHORITATIVE"
                    } else {
                        "NON-AUTHORITATIVE"
                    },
                    question.name.to_dotted_string(),
                    question.qclass,
                    question.qtype
                );

                if let Some(soa_rr) = zone.soa_rr() {
                    return Some(ResolvedRecord::AuthoritativeNameError {
                        authority_rrs: vec![soa_rr],
                    });
                }
            }
            // This shouldn't happen
            None => {
                println!(
                    "[ERROR] zone {:?} domain {:?} mis-match!",
                    zone.get_apex().to_dotted_string(),
                    question.name.to_dotted_string()
                );

                return None;
            }
        }
    }

    // If we get here, either:
    //
    // - there is no zone for this question (in practice this will be
    // unlikely, as the root hints get put into a non-authoritative
    // root zone - and without root hints, we can't do much)
    //
    // - the query was answered by a non-authoritative zone, which
    // means we may have other relevant RRs in the cache
    //
    // - the query could not be answered, because the
    // non-authoritative zone responsible for the name either doesn't
    // contain the name, or only has NS records (and the query is not
    // for NS records - if it were, that would be a non-authoritative
    // answer).
    //
    // In all cases, consult the cache for an answer to the question,
    // and combine with the RRs we already have.

    let mut rrs_from_cache = cache.get(&question.name, &question.qtype);
    println!(
        "[DEBUG] cache {} for {:?} {:?} {:?}",
        if rrs_from_cache.is_empty() {
            "MISS"
        } else {
            "HIT"
        },
        question.name.to_dotted_string(),
        question.qclass,
        question.qtype
    );

    if rrs_from_cache.is_empty() && question.qtype != QueryType::Record(RecordType::CNAME) {
        let cache_cname_rrs = cache.get(&question.name, &QueryType::Record(RecordType::CNAME));
        println!(
            "[DEBUG] cache CNAME {} for {:?} {:?} {:?}",
            if cache_cname_rrs.is_empty() {
                "MISS"
            } else {
                "HIT"
            },
            question.name.to_dotted_string(),
            question.qclass,
            question.qtype
        );

        if !cache_cname_rrs.is_empty() {
            let cname_rr = cache_cname_rrs[0].clone();
            rrs_from_cache = vec![cname_rr.clone()];
            let cname = if let RecordTypeWithData::CNAME { cname } = cname_rr.rtype_with_data {
                cname
            } else {
                println!("[ERROR] expected CNAME RR (in cache)");
                return None;
            };
            if let Some(resolved) = resolve_nonrecursive(
                zones,
                cache,
                &Question {
                    name: cname,
                    qtype: question.qtype,
                    qclass: question.qclass,
                },
            ) {
                rrs_from_cache.append(&mut resolved.rrs());
            }
        }
    }

    let mut rrs = Vec::with_capacity(rrs_from_zone.len() + rrs_from_cache.len());
    rrs.append(&mut rrs_from_zone);
    rrs.append(&mut rrs_from_cache);

    if rrs.is_empty() {
        None
    } else {
        Some(ResolvedRecord::NonAuthoritative { rrs })
    }
}

/// Recursive DNS resolution.
///
/// This corresponds to the standard resolver algorithm.  If
/// information is not held locally, it will call out to remote
/// nameservers, starting with the given root hints.  Since it may
/// make network requests, this function is async.
///
/// This has a 60s timeout.
///
/// See section 5.3.3 of RFC 1034.
pub async fn resolve_recursive(
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    match timeout(
        Duration::from_secs(60),
        resolve_recursive_notimeout(zones, cache, question),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => None,
    }
}

/// Timeout-less version of `resolve_recursive`.
#[async_recursion]
async fn resolve_recursive_notimeout(
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    // TODO: bound recursion depth

    if let resolved @ Some(_) = resolve_nonrecursive(zones, cache, question) {
        return resolved;
    }

    if let Some(mut candidates) = candidate_nameservers(zones, cache, &question.name) {
        'query_nameservers: while let Some(candidate) = candidates.hostnames.pop() {
            if let Some(ip) = match candidate {
                HostOrIP::IP(ip) => Some(ip),
                HostOrIP::Host(name) => resolve_recursive_notimeout(
                    zones,
                    cache,
                    &Question {
                        name: name.clone(),
                        qclass: QueryClass::Record(RecordClass::IN),
                        qtype: QueryType::Record(RecordType::A),
                    },
                )
                .await
                .and_then(|res| get_ip(&res.rrs(), &name)),
            } {
                match query_nameserver(&ip, question, candidates.match_count()).await {
                    Some(NameserverResponse::Answer { rrs }) => {
                        for rr in &rrs {
                            cache.insert(rr);
                        }
                        println!("[DEBUG] got response to current query");
                        return Some(ResolvedRecord::NonAuthoritative { rrs });
                    }
                    Some(NameserverResponse::Delegation { rrs, delegation }) => {
                        for rr in &rrs {
                            cache.insert(rr);
                        }
                        candidates = delegation;
                        println!("[DEBUG] found better nameserver - restarting current query");
                        continue 'query_nameservers;
                    }
                    Some(NameserverResponse::CNAME { rrs, cname }) => {
                        for rr in &rrs {
                            cache.insert(rr);
                        }
                        let cname_question = Question {
                            name: cname,
                            qclass: question.qclass,
                            qtype: question.qtype,
                        };
                        println!("[DEBUG] current query is a CNAME - restarting with CNAME target");
                        if let Some(resolved) =
                            resolve_recursive_notimeout(zones, cache, &cname_question).await
                        {
                            let mut r_rrs = resolved.rrs();
                            let mut combined_rrs = Vec::with_capacity(rrs.len() + r_rrs.len());
                            combined_rrs.append(&mut rrs.clone());
                            combined_rrs.append(&mut r_rrs);
                            return Some(ResolvedRecord::NonAuthoritative { rrs: combined_rrs });
                        } else {
                            return None;
                        }
                    }
                    None => (),
                }
            }

            return None;
        }
    } else {
        println!("[DEBUG] no candidate nameservers");
    }

    None
}

/// The result of a name resolution attempt.
///
/// If this is a `CNAME`, it should be added to the answer section of
/// the response message, and resolution repeated for the CNAME.  This
/// may build up a chain of `CNAME`s for some names.
///
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ResolvedRecord {
    Authoritative {
        rrs: Vec<ResourceRecord>,
        authority_rrs: Vec<ResourceRecord>,
    },
    AuthoritativeNameError {
        authority_rrs: Vec<ResourceRecord>,
    },
    NonAuthoritative {
        rrs: Vec<ResourceRecord>,
    },
}

impl ResolvedRecord {
    pub fn rrs(self) -> Vec<ResourceRecord> {
        match self {
            ResolvedRecord::Authoritative { rrs, .. } => rrs,
            ResolvedRecord::AuthoritativeNameError { .. } => Vec::new(),
            ResolvedRecord::NonAuthoritative { rrs } => rrs,
        }
    }
}

/// Get the best nameservers by non-recursively looking them up for
/// the domain and all its superdomains, in order.  If no nameservers
/// are found, the root hints are returned.
///
/// This corresponds to step 2 of the standard resolver algorithm.
pub fn candidate_nameservers(
    zones: &Zones,
    cache: &SharedCache,
    question: &DomainName,
) -> Option<Nameservers> {
    for i in 0..question.labels.len() {
        let labels = &question.labels[i..];
        if let Some(name) = DomainName::from_labels(labels.into()) {
            let ns_q = Question {
                name: name.clone(),
                qtype: QueryType::Record(RecordType::NS),
                qclass: QueryClass::Record(RecordClass::IN),
            };

            let mut hostnames = Vec::new();

            if let Some(resolved) = resolve_nonrecursive(zones, cache, &ns_q) {
                for ns_rr in resolved.rrs() {
                    if let RecordTypeWithData::NS { nsdname } = &ns_rr.rtype_with_data {
                        hostnames.push(HostOrIP::Host(nsdname.clone()));
                    }
                }
            }

            if !hostnames.is_empty() {
                return Some(Nameservers {
                    hostnames,
                    name: ns_q.name,
                });
            }
        }
    }

    None
}

/// Query a remote nameserver to answer a question.
///
/// This does a non-recursive query, so that we can cache intermediate
/// results.
///
/// This corresponds to step 3 of the standard resolver algorithm.
pub async fn query_nameserver(
    address: &Ipv4Addr,
    question: &Question,
    current_match_count: usize,
) -> Option<NameserverResponse> {
    let request = Message::from_question(rand::thread_rng().gen(), question.clone());

    println!(
        "[DEBUG] query remote nameserver {:?} for {:?} {:?} {:?}",
        address,
        question.name.to_dotted_string(),
        question.qclass,
        question.qtype
    );

    match request.clone().to_octets() {
        Ok(mut serialised_request) => {
            let udp_response = query_nameserver_udp(address, &mut serialised_request)
                .await
                .and_then(|res| validate_nameserver_response(&request, res, current_match_count));
            if udp_response.is_some() {
                udp_response
            } else {
                query_nameserver_tcp(address, &mut serialised_request)
                    .await
                    .and_then(|res| {
                        validate_nameserver_response(&request, res, current_match_count)
                    })
            }
        }
        Err(err) => {
            println!(
                "[INTERNAL ERROR] could not serialise message {:?} \"{:?}\"",
                request, err
            );
            None
        }
    }
}

/// Send a message to a remote nameserver over UDP, returning the
/// response.  If the message would be truncated, or an error occurs
/// while sending it, `None` is returned.  Otherwise the deserialised
/// response message is: but this response is NOT validated -
/// consumers MUST validate the response before using it!
///
/// This has a 5s timeout.
pub async fn query_nameserver_udp(
    address: &Ipv4Addr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    match timeout(
        Duration::from_secs(5),
        query_nameserver_udp_notimeout(address, serialised_request),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => None,
    }
}

/// Timeout-less version of `query_nameserver_udp`.
async fn query_nameserver_udp_notimeout(
    address: &Ipv4Addr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    if serialised_request.len() > 512 {
        return None;
    }

    let mut buf = vec![0u8; 512];
    match UdpSocket::bind("0.0.0.0:0").await {
        Ok(sock) => match sock.connect((*address, 53)).await {
            Ok(_) => match send_udp_bytes(&sock, serialised_request).await {
                Ok(_) => match sock.recv(&mut buf).await {
                    Ok(_) => match Message::from_octets(&buf) {
                        Ok(response) => Some(response),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Send a message to a remote nameserver over TCP, returning the
/// response.  This has the same return value caveats as
/// `query_nameserver_udp`.
///
/// This has a 5s timeout.
pub async fn query_nameserver_tcp(
    address: &Ipv4Addr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    match timeout(
        Duration::from_secs(5),
        query_nameserver_tcp_notimeout(address, serialised_request),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => None,
    }
}

/// Timeout-less version of `query_nameserver_tcp`.
async fn query_nameserver_tcp_notimeout(
    address: &Ipv4Addr,
    serialised_request: &mut [u8],
) -> Option<Message> {
    match TcpStream::connect((*address, 53)).await {
        Ok(mut stream) => match send_tcp_bytes(&mut stream, serialised_request).await {
            Ok(_) => match read_tcp_bytes(&mut stream).await {
                Ok(bytes) => match Message::from_octets(bytes.as_ref()) {
                    Ok(response) => Some(response),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Validate a nameserver response against the question:
///
/// - Check the ID, opcode, and questions match the question.
///
/// - Check it is a response and no error is signalled.
///
/// - Check it is not truncated.
///
/// Then, only keep valid RRs:
///
/// - RRs matching the query domain (or the name it ends up being
///   after following `CNAME`s) and type (or `CNAME`)
///
/// - `NS` RRs for a superdomain of the query domain (if it matches
///   better than our current nameservers).
///
/// - `A` RRs corresponding to a selected `NS` RR
///
/// Then, decide whether:
///
/// - This is an answer: it has a possibly-empty sequence of CNAME RRs
///   and a record of the right type at the final name.
///
/// - This is a cname to follow: it has a non-empty sequence of CNAME
///   RRs but no final record of the right type.
///
/// - This is a delegation to other nameservers: there's at least one
///   NS RR.
///
/// This makes the simplifying assumption that the question message
/// has a single question in it, because that is how this function is
/// used by this module.  If that assumption does not hold, a valid
/// answer may be reported as invalid.
pub fn validate_nameserver_response(
    request: &Message,
    response: Message,
    current_match_count: usize,
) -> Option<NameserverResponse> {
    // precondition
    if request.questions.len() != 1 {
        panic!("validate_nameserver_response only works for single-question messages");
    }

    // step 1: validation
    let question = &request.questions[0];

    if request.header.id != response.header.id {
        return None;
    }
    if !response.header.is_response {
        return None;
    }
    if request.header.opcode != response.header.opcode {
        return None;
    }
    if response.header.is_truncated {
        return None;
    }
    if response.header.rcode != Rcode::NoError {
        return None;
    }
    if request.questions != response.questions {
        return None;
    }

    if let Some((final_name, cname_map)) =
        follow_cnames(&response.answers, &question.name, &question.qtype)
    {
        // step 2.1: get RRs matching the query name or the names it
        // `CNAME`s to

        let mut rrs_for_query = Vec::<ResourceRecord>::with_capacity(response.answers.len());
        let mut seen_final_record = false;
        let mut all_unknown = true;
        for an in &response.answers {
            if an.is_unknown() {
                continue;
            }

            let rtype = an.rtype_with_data.rtype();
            all_unknown = false;

            if rtype.matches(&question.qtype) && an.name == final_name {
                rrs_for_query.push(an.clone());
                seen_final_record = true;
            } else if rtype == RecordType::CNAME && cname_map.contains_key(&an.name) {
                rrs_for_query.push(an.clone());
            }
        }

        if all_unknown {
            None
        } else if rrs_for_query.is_empty() {
            panic!("[ERROR] validate_nameserver_response: there should at least be CNAME RRs here")
        } else {
            // step 3.1 & 3.2: what sort of answer is this?
            if seen_final_record {
                Some(NameserverResponse::Answer { rrs: rrs_for_query })
            } else {
                Some(NameserverResponse::CNAME {
                    rrs: rrs_for_query,
                    cname: final_name,
                })
            }
        }
    } else {
        // steps 2.2 & 2.3: get NS RRs and their associated A RRs.
        //
        // NOTE: `NS` RRs may be in the ANSWER *or* AUTHORITY
        // sections.

        let (match_name, ns_names) = {
            let ns_from_answers =
                get_better_ns_names(&response.answers, &question.name, current_match_count);
            let ns_from_authority =
                get_better_ns_names(&response.authority, &question.name, current_match_count);
            match (ns_from_answers, ns_from_authority) {
                (Some((mn1, nss1)), Some((mn2, nss2))) => {
                    match mn1.labels.len().cmp(&mn2.labels.len()) {
                        Ordering::Greater => (mn1, nss1),
                        Ordering::Equal => (mn1, nss1.union(&nss2).cloned().collect()),
                        Ordering::Less => (mn2, nss2),
                    }
                }
                (Some((mn, nss)), None) => (mn, nss),
                (None, Some((mn, nss))) => (mn, nss),
                (None, None) => return None,
            }
        };

        // *2 because, you never know, the upstream nameserver may
        // have been kind enough to give an A record along with each
        // NS record, if we're lucky.
        let mut nameserver_rrs = Vec::<ResourceRecord>::with_capacity(ns_names.len() * 2);
        for rr in &response.answers {
            match &rr.rtype_with_data {
                RecordTypeWithData::NS { nsdname } if ns_names.contains(nsdname) => {
                    nameserver_rrs.push(rr.clone())
                }
                RecordTypeWithData::A { .. } if ns_names.contains(&rr.name) => {
                    nameserver_rrs.push(rr.clone())
                }
                _ => (),
            }
        }
        for rr in &response.authority {
            match &rr.rtype_with_data {
                RecordTypeWithData::NS { nsdname } if ns_names.contains(nsdname) => {
                    nameserver_rrs.push(rr.clone())
                }
                _ => (),
            }
        }
        for rr in &response.additional {
            match &rr.rtype_with_data {
                RecordTypeWithData::A { .. } if ns_names.contains(&rr.name) => {
                    nameserver_rrs.push(rr.clone())
                }
                _ => (),
            }
        }

        // step 3.3: this is a delegation
        Some(NameserverResponse::Delegation {
            rrs: nameserver_rrs,
            delegation: Nameservers {
                hostnames: ns_names.into_iter().map(HostOrIP::Host).collect(),
                name: match_name,
            },
        })
    }
}

/// A set of nameservers for a domain
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Nameservers {
    /// Guaranteed to be non-empty.
    ///
    /// TODO: find a non-empty-vec type
    pub hostnames: Vec<HostOrIP>,
    pub name: DomainName,
}

impl Nameservers {
    pub fn match_count(&self) -> usize {
        self.name.labels.len()
    }
}

/// A hostname or an IP
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum HostOrIP {
    Host(DomainName),
    IP(Ipv4Addr),
}

/// A response from a remote nameserver
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NameserverResponse {
    Answer {
        rrs: Vec<ResourceRecord>,
    },
    CNAME {
        rrs: Vec<ResourceRecord>,
        cname: DomainName,
    },
    Delegation {
        rrs: Vec<ResourceRecord>,
        delegation: Nameservers,
    },
}

#[cfg(test)]
mod tests {
    use super::cache::test_util::*;
    use super::*;
    use crate::protocol::wire_types::test_util::*;
    use crate::zones::{Zone, SOA};

    #[test]
    fn resolve_nonrecursive_is_authoritative_for_zones_with_soa() {
        let soa_rr = zones_soa_rr();
        let mut expected = vec![
            a_record("authoritative.example.com", Ipv4Addr::new(1, 1, 1, 1)),
            soa_rr.clone(),
        ];
        expected.sort();

        if let Some(ResolvedRecord::Authoritative {
            mut rrs,
            authority_rrs,
        }) = resolve_nonrecursive(
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("authoritative.example.com"),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            rrs.sort();

            assert_eq!(vec![soa_rr], authority_rrs);
            assert_eq!(expected, rrs);
        } else {
            panic!("expected authoritative response");
        }
    }

    #[test]
    fn resolve_nonrecursive_is_nonauthoritative_for_zones_without_soa() {
        assert_eq!(
            Some(ResolvedRecord::NonAuthoritative {
                rrs: vec![a_record("a.example.com", Ipv4Addr::new(1, 1, 1, 1))],
            }),
            resolve_nonrecursive(
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("a.example.com"),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                }
            )
        )
    }

    #[test]
    fn resolve_nonrecursive_is_nonauthoritative_for_cache() {
        let rr = a_record("cached.example.com", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&rr);

        if let Some(ResolvedRecord::NonAuthoritative { rrs }) = resolve_nonrecursive(
            &zones(),
            &cache,
            &Question {
                name: domain("cached.example.com"),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_cache_response(&rr, rrs);
        } else {
            panic!("expected Some response");
        }
    }

    #[test]
    fn resolve_nonrecursive_prefers_authoritative_zones() {
        let soa_rr = zones_soa_rr();
        let mut expected = vec![
            a_record("authoritative.example.com", Ipv4Addr::new(1, 1, 1, 1)),
            soa_rr.clone(),
        ];
        expected.sort();

        let cache = SharedCache::new();
        cache.insert(&a_record(
            "authoritative.example.com",
            Ipv4Addr::new(8, 8, 8, 8),
        ));

        if let Some(ResolvedRecord::Authoritative {
            mut rrs,
            authority_rrs,
        }) = resolve_nonrecursive(
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("authoritative.example.com"),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            rrs.sort();

            assert_eq!(vec![soa_rr], authority_rrs);
            assert_eq!(expected, rrs);
        } else {
            panic!("expected authoritative response");
        }
    }

    #[test]
    fn resolve_nonrecursive_combines_nonauthoritative_zones_with_cache() {
        let zone_rr = a_record("a.example.com", Ipv4Addr::new(1, 1, 1, 1));
        let cache_rr = a_record("a.example.com", Ipv4Addr::new(8, 8, 8, 8));

        let cache = SharedCache::new();
        cache.insert(&cache_rr);

        if let Some(ResolvedRecord::NonAuthoritative { rrs }) = resolve_nonrecursive(
            &zones(),
            &cache,
            &Question {
                name: domain("a.example.com"),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_eq!(2, rrs.len());
            assert_cache_response(&zone_rr, vec![rrs[0].clone()]);
            assert_cache_response(&cache_rr, vec![rrs[1].clone()]);
        } else {
            panic!("expected Some response");
        }
    }

    #[test]
    fn resolve_nonrecursive_expands_cnames_from_zone() {
        let cname_rr = cname_record(
            "cname-a.authoritative.example.com",
            "authoritative.example.com",
        );
        let a_rr = a_record("authoritative.example.com", Ipv4Addr::new(1, 1, 1, 1));

        if let Some(ResolvedRecord::Authoritative { rrs, authority_rrs }) = resolve_nonrecursive(
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("cname-a.authoritative.example.com"),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert!(authority_rrs.is_empty());
            assert_eq!(2, rrs.len());
            assert_cache_response(&cname_rr, vec![rrs[0].clone()]);
            assert_cache_response(&a_rr, vec![rrs[1].clone()]);
        } else {
            panic!("expected Some response");
        }
    }

    #[test]
    fn resolve_nonrecursive_expands_cnames_from_cache() {
        let cname_rr1 = cname_record("cname-1.example.com", "cname-2.example.com");
        let cname_rr2 = cname_record("cname-2.example.com", "a.example.com");
        let a_rr = a_record("a.example.com", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&cname_rr1);
        cache.insert(&cname_rr2);

        if let Some(ResolvedRecord::NonAuthoritative { rrs }) = resolve_nonrecursive(
            &zones(),
            &cache,
            &Question {
                name: domain("cname-1.example.com"),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_eq!(3, rrs.len());
            assert_cache_response(&cname_rr1, vec![rrs[0].clone()]);
            assert_cache_response(&cname_rr2, vec![rrs[1].clone()]);
            assert_cache_response(&a_rr, vec![rrs[2].clone()]);
        } else {
            panic!("expected Some response");
        }
    }

    #[test]
    fn resolve_nonrecursive_propagates_cname_nonauthority() {
        let cname_rr = cname_record("cname-na.authoritative.example.com", "a.example.com");
        let a_rr = a_record("a.example.com", Ipv4Addr::new(1, 1, 1, 1));

        if let Some(ResolvedRecord::NonAuthoritative { rrs }) = resolve_nonrecursive(
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("cname-na.authoritative.example.com"),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_eq!(2, rrs.len());
            assert_cache_response(&cname_rr, vec![rrs[0].clone()]);
            assert_cache_response(&a_rr, vec![rrs[1].clone()]);
        } else {
            panic!("expected Some response");
        }
    }

    #[test]
    fn resolve_nonrecursive_delegates_from_authoritative_zone() {
        assert_eq!(
            Some(ResolvedRecord::Authoritative {
                rrs: Vec::new(),
                authority_rrs: vec![ns_record(
                    "delegated.authoritative.example.com",
                    "ns.delegated.authoritative.example.com"
                )]
            }),
            resolve_nonrecursive(
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("www.delegated.authoritative.example.com"),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                }
            )
        );
    }

    #[test]
    fn resolve_nonrecursive_does_not_delegate_from_nonauthoritative_zone() {
        assert_eq!(
            None,
            resolve_nonrecursive(
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("www.delegated.example.com"),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                }
            )
        );
    }

    #[test]
    fn resolve_nonrecursive_nameerrors_from_authoritative_zone() {
        assert_eq!(
            Some(ResolvedRecord::AuthoritativeNameError {
                authority_rrs: vec![zones_soa_rr()]
            }),
            resolve_nonrecursive(
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("no.such.name.authoritative.example.com"),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                },
            )
        );
    }

    #[test]
    fn resolve_nonrecursive_does_not_nameerror_from_nonauthoritative_zone() {
        assert_eq!(
            None,
            resolve_nonrecursive(
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("no.such.name.example.com"),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                },
            )
        );
    }

    #[test]
    fn candidate_nameservers_gets_all_matches() {
        let qdomain = domain("com");
        assert_eq!(
            Some(Nameservers {
                hostnames: vec![
                    HostOrIP::Host(domain("ns1.example.com")),
                    HostOrIP::Host(domain("ns2.example.com"))
                ],
                name: qdomain.clone(),
            }),
            candidate_nameservers(&zones(), &cache_with_nameservers(&["com"]), &qdomain)
        );
    }

    #[test]
    fn candidate_nameservers_returns_longest_match() {
        assert_eq!(
            Some(Nameservers {
                hostnames: vec![
                    HostOrIP::Host(domain("ns1.example.com")),
                    HostOrIP::Host(domain("ns2.example.com"))
                ],
                name: domain("example.com"),
            }),
            candidate_nameservers(
                &zones(),
                &cache_with_nameservers(&["example.com", "com"]),
                &domain("www.example.com")
            )
        );
    }

    #[test]
    fn candidate_nameservers_returns_none_on_failure() {
        assert_eq!(
            None,
            candidate_nameservers(&zones(), &cache_with_nameservers(&["com"]), &domain("net"))
        );
    }

    #[test]
    fn validate_nameserver_response_accepts() {
        let (request, response) = matching_nameserver_response();

        assert!(validate_nameserver_response(&request, response, 0).is_some());
    }

    #[test]
    fn validate_nameserver_response_checks_id() {
        let (request, mut response) = matching_nameserver_response();
        response.header.id += 1;

        assert_eq!(None, validate_nameserver_response(&request, response, 0));
    }

    #[test]
    fn validate_nameserver_response_checks_qr() {
        let (request, mut response) = matching_nameserver_response();
        response.header.is_response = false;

        assert_eq!(None, validate_nameserver_response(&request, response, 0));
    }

    #[test]
    fn validate_nameserver_response_checks_opcode() {
        let (request, mut response) = matching_nameserver_response();
        response.header.opcode = Opcode::Status;

        assert_eq!(None, validate_nameserver_response(&request, response, 0));
    }

    #[test]
    fn validate_nameserver_response_does_not_check_aa() {
        let (request, mut response) = matching_nameserver_response();
        response.header.is_authoritative = !response.header.is_authoritative;

        assert!(validate_nameserver_response(&request, response, 0).is_some());
    }

    #[test]
    fn validate_nameserver_response_checks_tc() {
        let (request, mut response) = matching_nameserver_response();
        response.header.is_truncated = true;

        assert_eq!(None, validate_nameserver_response(&request, response, 0));
    }

    #[test]
    fn validate_nameserver_response_does_not_check_rd() {
        let (request, mut response) = matching_nameserver_response();
        response.header.recursion_desired = !response.header.recursion_desired;

        assert!(validate_nameserver_response(&request, response, 0).is_some());
    }

    #[test]
    fn validate_nameserver_response_does_not_check_ra() {
        let (request, mut response) = matching_nameserver_response();
        response.header.recursion_available = !response.header.recursion_available;

        assert!(validate_nameserver_response(&request, response, 0).is_some());
    }

    #[test]
    fn validate_nameserver_response_checks_rcode() {
        let (request, mut response) = matching_nameserver_response();
        response.header.rcode = Rcode::ServerFailure;

        assert_eq!(None, validate_nameserver_response(&request, response, 0));
    }

    #[test]
    fn validate_nameserver_response_returns_answer() {
        let (request, response) = nameserver_response(
            "www.example.com",
            &[a_record("www.example.com", Ipv4Addr::new(127, 0, 0, 1))],
            &[],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::Answer {
                rrs: vec![a_record("www.example.com", Ipv4Addr::new(127, 0, 0, 1))],
            }),
            validate_nameserver_response(&request, response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_drops_unknown_rrs() {
        let request = Message::from_question(
            1234,
            Question {
                name: domain("www.example.com"),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Record(RecordClass::IN),
            },
        );

        let mut response = request.make_response();
        response.answers = [
            unknown_record("www.example.com", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            a_record("www.example.com", Ipv4Addr::new(1, 1, 1, 1)),
        ]
        .into();

        assert_eq!(
            Some(NameserverResponse::Answer {
                rrs: vec![a_record("www.example.com", Ipv4Addr::new(1, 1, 1, 1))],
            }),
            validate_nameserver_response(&request, response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_returns_none_if_all_rrs_unknown() {
        let request = Message::from_question(
            1234,
            Question {
                name: domain("www.example.com"),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Record(RecordClass::IN),
            },
        );

        let mut response = request.make_response();
        response.answers = [unknown_record(
            "www.example.com",
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        )]
        .into();

        assert_eq!(None, validate_nameserver_response(&request, response, 0));
    }

    #[test]
    fn validate_nameserver_response_follows_cnames() {
        let (request, response) = nameserver_response(
            "www.example.com",
            &[
                cname_record("www.example.com", "cname-target.example.com"),
                a_record("cname-target.example.com", Ipv4Addr::new(127, 0, 0, 1)),
            ],
            &[],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::Answer {
                rrs: vec![
                    cname_record("www.example.com", "cname-target.example.com"),
                    a_record("cname-target.example.com", Ipv4Addr::new(127, 0, 0, 1))
                ],
            }),
            validate_nameserver_response(&request, response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_returns_partial_answer() {
        let (request, response) = nameserver_response(
            "www.example.com",
            &[cname_record("www.example.com", "cname-target.example.com")],
            &[],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::CNAME {
                rrs: vec![cname_record("www.example.com", "cname-target.example.com")],
                cname: domain("cname-target.example.com"),
            }),
            validate_nameserver_response(&request, response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_gets_ns_from_answers_and_authority_but_not_additional() {
        let (request, response) = nameserver_response(
            "www.example.com",
            &[ns_record("example.com", "ns-an.example.net")],
            &[ns_record("example.com", "ns-ns.example.net")],
            &[ns_record("example.com", "ns-ar.example.net")],
        );

        match validate_nameserver_response(&request, response, 0) {
            Some(NameserverResponse::Delegation {
                rrs: mut actual_rrs,
                delegation: mut actual_delegation,
            }) => {
                let mut expected_rrs = vec![
                    ns_record("example.com", "ns-an.example.net"),
                    ns_record("example.com", "ns-ns.example.net"),
                ];

                expected_rrs.sort();
                actual_rrs.sort();

                assert_eq!(expected_rrs, actual_rrs);

                let mut expected_delegation = Nameservers {
                    hostnames: vec![
                        HostOrIP::Host(domain("ns-an.example.net")),
                        HostOrIP::Host(domain("ns-ns.example.net")),
                    ],
                    name: domain("example.com"),
                };

                expected_delegation.hostnames.sort();
                actual_delegation.hostnames.sort();

                assert_eq!(expected_delegation, actual_delegation);
            }
            actual => panic!("Expected delegation, got {:?}", actual),
        }
    }

    #[test]
    fn validate_nameserver_response_only_returns_better_ns() {
        let (request, response) = nameserver_response(
            "long.subdomain.example.com",
            &[ns_record("example.com", "ns.example.net")],
            &[],
            &[],
        );

        assert_eq!(
            None,
            validate_nameserver_response(
                &request,
                response,
                domain("subdomain.example.com").labels.len()
            )
        );
    }

    #[test]
    fn validate_nameserver_response_prefers_best_ns() {
        let (request, response1) = nameserver_response(
            "long.subdomain.example.com",
            &[ns_record("subdomain.example.com", "ns-better.example.net")],
            &[ns_record("example.com", "ns-worse.example.net")],
            &[],
        );
        let (_, response2) = nameserver_response(
            "long.subdomain.example.com",
            &[ns_record("example.com", "ns-worse.example.net")],
            &[ns_record("subdomain.example.com", "ns-better.example.net")],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::Delegation {
                rrs: vec![ns_record("subdomain.example.com", "ns-better.example.net"),],
                delegation: Nameservers {
                    hostnames: vec![HostOrIP::Host(domain("ns-better.example.net")),],
                    name: domain("subdomain.example.com"),
                },
            }),
            validate_nameserver_response(&request, response1, 0)
        );

        assert_eq!(
            Some(NameserverResponse::Delegation {
                rrs: vec![ns_record("subdomain.example.com", "ns-better.example.net"),],
                delegation: Nameservers {
                    hostnames: vec![HostOrIP::Host(domain("ns-better.example.net")),],
                    name: domain("subdomain.example.com"),
                },
            }),
            validate_nameserver_response(&request, response2, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_gets_ns_a_from_answers_and_additional_but_not_authority() {
        let (request, response) = nameserver_response(
            "www.example.com",
            &[
                ns_record("example.com", "ns-an.example.net"),
                a_record("ns-an.example.net", Ipv4Addr::new(1, 1, 1, 1)),
                a_record("ns-ns.example.net", Ipv4Addr::new(1, 1, 1, 1)),
            ],
            &[
                ns_record("example.com", "ns-ns.example.net"),
                a_record("ns-an.example.net", Ipv4Addr::new(2, 2, 2, 2)),
                a_record("ns-ns.example.net", Ipv4Addr::new(2, 2, 2, 2)),
            ],
            &[
                a_record("ns-an.example.net", Ipv4Addr::new(3, 3, 3, 3)),
                a_record("ns-ns.example.net", Ipv4Addr::new(3, 3, 3, 3)),
            ],
        );

        match validate_nameserver_response(&request, response, 0) {
            Some(NameserverResponse::Delegation {
                rrs: mut actual_rrs,
                delegation: _,
            }) => {
                let mut expected_rrs = vec![
                    ns_record("example.com", "ns-an.example.net"),
                    ns_record("example.com", "ns-ns.example.net"),
                    a_record("ns-an.example.net", Ipv4Addr::new(1, 1, 1, 1)),
                    a_record("ns-ns.example.net", Ipv4Addr::new(1, 1, 1, 1)),
                    a_record("ns-an.example.net", Ipv4Addr::new(3, 3, 3, 3)),
                    a_record("ns-ns.example.net", Ipv4Addr::new(3, 3, 3, 3)),
                ];

                expected_rrs.sort();
                actual_rrs.sort();

                assert_eq!(expected_rrs, actual_rrs);
            }
            actual => panic!("Expected delegation, got {:?}", actual),
        }
    }

    #[test]
    fn validate_nameserver_response_returns_none_if_no_matching_records() {}

    fn cache_with_nameservers(names: &[&str]) -> SharedCache {
        let cache = SharedCache::new();

        for name in names {
            cache.insert(&ns_record(name, "ns1.example.com"));
            cache.insert(&ns_record(name, "ns2.example.com"));
        }

        cache
    }

    fn zones() -> Zones {
        let mut zone_na = Zone::default();
        zone_na.insert(
            &domain("blocked.example.com"),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(0, 0, 0, 0),
            },
            300,
        );
        zone_na.insert(
            &domain("cname-and-a.example.com"),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_na.insert(
            &domain("cname-and-a.example.com"),
            RecordTypeWithData::CNAME {
                cname: domain("cname-target.example.com"),
            },
            300,
        );
        zone_na.insert(
            &domain("a.example.com"),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_na.insert(
            &domain("delegated.example.com"),
            RecordTypeWithData::NS {
                nsdname: domain("ns.delegated.example.com"),
            },
            300,
        );

        let mut zone_a = Zone::new(
            domain("authoritative.example.com"),
            Some(SOA {
                mname: domain("mname"),
                rname: domain("rname"),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            }),
        );
        zone_a.insert(
            &domain("authoritative.example.com"),
            RecordTypeWithData::A {
                address: Ipv4Addr::new(1, 1, 1, 1),
            },
            300,
        );
        zone_a.insert(
            &domain("cname-a.authoritative.example.com"),
            RecordTypeWithData::CNAME {
                cname: domain("authoritative.example.com"),
            },
            300,
        );
        zone_a.insert(
            &domain("cname-na.authoritative.example.com"),
            RecordTypeWithData::CNAME {
                cname: domain("a.example.com"),
            },
            300,
        );
        zone_a.insert(
            &domain("delegated.authoritative.example.com"),
            RecordTypeWithData::NS {
                nsdname: domain("ns.delegated.authoritative.example.com"),
            },
            300,
        );

        let mut zones = Zones::new();
        zones.insert(zone_na);
        zones.insert(zone_a);

        zones
    }

    fn zones_soa_rr() -> ResourceRecord {
        zones()
            .get(&domain("authoritative.example.com"))
            .unwrap()
            .soa_rr()
            .unwrap()
    }

    fn matching_nameserver_response() -> (Message, Message) {
        nameserver_response(
            "www.example.com",
            &[a_record("www.example.com", Ipv4Addr::new(1, 1, 1, 1))],
            &[],
            &[],
        )
    }

    fn nameserver_response(
        name: &str,
        answers: &[ResourceRecord],
        authority: &[ResourceRecord],
        additional: &[ResourceRecord],
    ) -> (Message, Message) {
        let request = Message::from_question(
            1234,
            Question {
                name: domain(name),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Record(RecordClass::IN),
            },
        );

        let mut response = request.make_response();
        response.answers = answers.into();
        response.authority = authority.into();
        response.additional = additional.into();

        (request, response)
    }
}
