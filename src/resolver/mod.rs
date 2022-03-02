pub mod cache;
pub mod rr_util;

use async_recursion::async_recursion;
use rand::Rng;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use self::cache::SharedCache;
use self::rr_util::*;

use crate::net_util::{read_tcp_bytes, send_tcp_bytes, send_udp_bytes};
use crate::protocol::wire_types::*;
use crate::settings::Settings;

/// Resolve a question using the standard DNS algorithms.
pub async fn resolve(
    is_recursive: bool,
    upstream_nameservers: &[Ipv4Addr],
    local_zone: &Settings,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    if is_recursive {
        resolve_recursive(upstream_nameservers, local_zone, cache, question).await
    } else {
        resolve_nonrecursive(local_zone, cache, question)
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
    local_zone: &Settings,
    cache: &SharedCache,
    initial_question: &Question,
) -> Option<ResolvedRecord> {
    let mut questions = vec![initial_question.clone()];
    let mut rrs = Vec::new();
    let mut authority = None;
    let mut authoritative = true;
    let mut cnames_followed = HashSet::new();

    while !questions.is_empty() {
        let mut new_questions = Vec::new();

        for question in questions {
            let mut new_rrs = Vec::new();

            if let Some(rr) = authoritative_from_zone(local_zone, &question) {
                new_rrs.push(rr.clone());
            } else {
                let (cached_rrs, cached_authority_rr) =
                    nonauthoritative_from_cache(cache, &question);
                if !cached_rrs.is_empty() {
                    new_rrs.append(&mut cached_rrs.clone());
                    authority = cached_authority_rr;
                    authoritative = false;

                    println!(
                        "[DEBUG] cache HIT for {:?} {:?} {:?}",
                        question.name.to_dotted_string(),
                        question.qclass,
                        question.qtype
                    );
                } else {
                    println!(
                        "[DEBUG] cache MISS for {:?} {:?} {:?}",
                        question.name.to_dotted_string(),
                        question.qclass,
                        question.qtype
                    );
                }
            }

            if question.qtype != QueryType::Record(RecordType::CNAME) {
                for rr in &new_rrs {
                    if let RecordTypeWithData::Named {
                        rtype: RecordType::CNAME,
                        name,
                    } = &rr.rtype_with_data
                    {
                        if !cnames_followed.contains(name) {
                            let mut new_question = question.clone();
                            new_question.name = name.clone();
                            new_questions.push(new_question);
                            cnames_followed.insert(name.clone());
                        }
                    }
                }
            }
            rrs.append(&mut new_rrs);
        }

        questions = new_questions;
    }

    if rrs.is_empty() {
        None
    } else if authoritative {
        Some(ResolvedRecord::Authoritative { rrs })
    } else {
        Some(ResolvedRecord::NonAuthoritative { rrs, authority })
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
    root_hints: &[Ipv4Addr],
    local_zone: &Settings,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    match timeout(
        Duration::from_secs(60),
        resolve_recursive_notimeout(root_hints, local_zone, cache, question),
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
    root_hints: &[Ipv4Addr],
    local_zone: &Settings,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    // TODO: bound recursion depth

    if let Some(resolved) = resolve_nonrecursive(local_zone, cache, question) {
        let rrs = resolved.clone().rrs();
        let authority = resolved.authority();
        return Some(ResolvedRecord::NonAuthoritative { rrs, authority });
    }

    let mut candidates = candidate_nameservers(root_hints, local_zone, cache, &question.name);
    'query_nameservers: while let Some(candidate) = candidates.hostnames.pop() {
        if let Some(ip) = match candidate {
            HostOrIP::IP(ip) => Some(ip),
            HostOrIP::Host(name) => resolve_recursive_notimeout(
                root_hints,
                local_zone,
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
                Some(NameserverResponse::Answer { rrs, authority }) => {
                    for rr in &rrs {
                        cache.insert(rr);
                    }
                    println!("[DEBUG] got response to current query");
                    return Some(ResolvedRecord::NonAuthoritative { rrs, authority });
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
                        resolve_recursive_notimeout(root_hints, local_zone, cache, &cname_question)
                            .await
                    {
                        let mut r_rrs = resolved.clone().rrs();
                        let mut combined_rrs = Vec::with_capacity(rrs.len() + r_rrs.len());
                        combined_rrs.append(&mut rrs.clone());
                        combined_rrs.append(&mut r_rrs);
                        return Some(ResolvedRecord::NonAuthoritative {
                            rrs: combined_rrs,
                            authority: resolved.authority(),
                        });
                    } else {
                        return None;
                    }
                }
                None => (),
            }
        }

        return None;
    }

    None
}

/// The result of a name resolution attempt.
///
/// If this is a `CNAME`, it should be added to the answer section of
/// the response message, and resolution repeated for the CNAME.  This
/// may build up a chain of `CNAME`s for some names.
///
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResolvedRecord {
    Authoritative {
        rrs: Vec<ResourceRecord>,
    },
    NonAuthoritative {
        rrs: Vec<ResourceRecord>,
        authority: Option<ResourceRecord>,
    },
}

impl ResolvedRecord {
    pub fn rrs(self) -> Vec<ResourceRecord> {
        match self {
            ResolvedRecord::Authoritative { rrs } => rrs,
            ResolvedRecord::NonAuthoritative { rrs, authority: _ } => rrs,
        }
    }

    pub fn authority(self) -> Option<ResourceRecord> {
        match self {
            ResolvedRecord::Authoritative { rrs: _ } => None,
            ResolvedRecord::NonAuthoritative { rrs: _, authority } => authority,
        }
    }
}

/// Locally-defined records for DNS blocklisting and LAN DNS.
///
/// This corresponds to steps 3.a and 3.c of the standard nameserver
/// algorithm.  Since this program is intended for just simple local
/// resolution, and in particular it does not support delegating to
/// another zone: all local records are in the same zone.
pub fn authoritative_from_zone(
    local_zone: &Settings,
    question: &Question,
) -> Option<ResourceRecord> {
    let make_rr = |rtype_with_data| ResourceRecord {
        name: question.name.clone(),
        rtype_with_data,
        rclass: match question.qclass {
            QueryClass::Record(rc) => rc,
            QueryClass::Wildcard => RecordClass::IN,
        },
        ttl: 300,
    };

    // TODO: use a more efficient data structure (like a trie)
    for static_record in &local_zone.static_records {
        if static_record.domain.matches(&question.name) {
            if let Some(name) = &static_record.record_cname {
                return Some(make_rr(RecordTypeWithData::Named {
                    rtype: RecordType::CNAME,
                    name: name.domain.clone(),
                }));
            } else if question.qtype == QueryType::Record(RecordType::A) {
                if let Some(address) = static_record.record_a {
                    return Some(make_rr(RecordTypeWithData::Uninterpreted {
                        rtype: RecordType::A,
                        octets: Vec::from(address.octets()),
                    }));
                }
            }
        }
    }

    // TODO: use a more efficient data structure (like a trie)
    for blocked_domain in &local_zone.blocked_domains {
        if blocked_domain.matches(&question.name) {
            // Return an A record pointing to 0.0.0.0 - copied from
            // what pi hole does.
            return Some(make_rr(RecordTypeWithData::Uninterpreted {
                rtype: RecordType::A,
                octets: vec![0, 0, 0, 0],
            }));
        }
    }

    None
}

/// Cached records
///
/// This corresponds to step 4 of the standard nameserver algorithm.
pub fn nonauthoritative_from_cache(
    cache: &SharedCache,
    question: &Question,
) -> (Vec<ResourceRecord>, Option<ResourceRecord>) {
    // TODO: implement authority record
    (
        cache.get(&question.name, &question.qtype, &question.qclass),
        None,
    )
}

/// Get the best nameservers.
///
/// This corresponds to step 2 of the standard resolver algorithm.
pub fn candidate_nameservers(
    root_hints: &[Ipv4Addr],
    local_zone: &Settings,
    cache: &SharedCache,
    question: &DomainName,
) -> Nameservers {
    for i in 0..question.labels.len() {
        let labels = &question.labels[i..];
        if let Some(name) = DomainName::from_labels(labels.into()) {
            if let Some(nameservers) = find_nameservers(local_zone, cache, &name) {
                return nameservers;
            }
        }
    }

    let mut root_hostnames = Vec::with_capacity(root_hints.len());
    for ip in root_hints {
        root_hostnames.push(HostOrIP::IP(*ip));
    }

    Nameservers {
        hostnames: root_hostnames,
        name: DomainName::root_domain(),
    }
}

/// Non-recursively look up nameservers for a domain and return their
/// hostnames.
pub fn find_nameservers(
    local_zone: &Settings,
    cache: &SharedCache,
    name: &DomainName,
) -> Option<Nameservers> {
    let mut hostnames = Vec::new();

    let ns_q = Question {
        name: name.clone(),
        qtype: QueryType::Record(RecordType::NS),
        qclass: QueryClass::Record(RecordClass::IN),
    };

    if let Some(resolved) = resolve_nonrecursive(local_zone, cache, &ns_q) {
        for ns_rr in resolved.rrs() {
            if let RecordTypeWithData::Named {
                rtype: RecordType::NS,
                name,
            } = &ns_rr.rtype_with_data
            {
                hostnames.push(HostOrIP::Host(name.clone()));
            }
        }
    }

    if hostnames.is_empty() {
        None
    } else {
        Some(Nameservers {
            hostnames,
            name: ns_q.name,
        })
    }
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
    let mut serialised_request = request.clone().to_octets();

    println!(
        "[DEBUG] query remote nameserver {:?} for {:?} {:?} {:?}",
        address,
        question.name.to_dotted_string(),
        question.qclass,
        question.qtype
    );

    let udp_response = query_nameserver_udp(address, &mut serialised_request)
        .await
        .and_then(|res| validate_nameserver_response(&request, res, current_match_count));
    if udp_response.is_some() {
        udp_response
    } else {
        query_nameserver_tcp(address, &mut serialised_request)
            .await
            .and_then(|res| validate_nameserver_response(&request, res, current_match_count))
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
///   after following `CNAME`s, class, and type (or `CNAME`)
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
    if request.header.qdcount != response.header.qdcount {
        return None;
    }
    if request.questions != response.questions {
        return None;
    }

    if let Some((final_name, cname_map)) = follow_cnames(
        &response.answers,
        &question.name,
        &question.qclass,
        &question.qtype,
    ) {
        // step 2.1: get RRs matching the query name or the names it
        // `CNAME`s to

        let mut rrs_for_query =
            Vec::<ResourceRecord>::with_capacity(response.header.ancount as usize);
        let mut seen_final_record = false;
        for an in &response.answers {
            if an.rclass.matches(&question.qclass) {
                let rtype = an.rtype_with_data.rtype();
                if rtype.matches(&question.qtype) && an.name == final_name {
                    rrs_for_query.push(an.clone());
                    seen_final_record = true;
                } else if rtype == RecordType::CNAME && cname_map.contains_key(&an.name) {
                    rrs_for_query.push(an.clone());
                }
            }
        }

        if rrs_for_query.is_empty() {
            panic!("[ERROR] validate_nameserver_response: there should at least be CNAME RRs here")
        } else {
            // step 3.1 & 3.2: what sort of answer is this?
            if seen_final_record {
                // TODO: implement authority
                Some(NameserverResponse::Answer {
                    rrs: rrs_for_query,
                    authority: None,
                })
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
                RecordTypeWithData::Named {
                    rtype: RecordType::NS,
                    name,
                } if ns_names.contains(name) => nameserver_rrs.push(rr.clone()),
                RecordTypeWithData::Uninterpreted {
                    rtype: RecordType::A,
                    octets: _,
                } if ns_names.contains(&rr.name) => nameserver_rrs.push(rr.clone()),
                _ => (),
            }
        }
        for rr in &response.authority {
            match &rr.rtype_with_data {
                RecordTypeWithData::Named {
                    rtype: RecordType::NS,
                    name,
                } if ns_names.contains(name) => nameserver_rrs.push(rr.clone()),
                _ => (),
            }
        }
        for rr in &response.additional {
            match &rr.rtype_with_data {
                RecordTypeWithData::Uninterpreted {
                    rtype: RecordType::A,
                    octets: _,
                } if ns_names.contains(&rr.name) => nameserver_rrs.push(rr.clone()),
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
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Nameservers {
    /// Guaranteed to be non-empty.
    pub hostnames: Vec<HostOrIP>,
    pub name: DomainName,
}

impl Nameservers {
    pub fn match_count(&self) -> usize {
        self.name.labels.len()
    }
}

/// A hostname or an IP
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum HostOrIP {
    Host(DomainName),
    IP(Ipv4Addr),
}

/// A response from a remote nameserver
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NameserverResponse {
    Answer {
        rrs: Vec<ResourceRecord>,
        authority: Option<ResourceRecord>,
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
