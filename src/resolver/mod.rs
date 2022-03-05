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
                    if let RecordTypeWithData::CNAME { cname } = &rr.rtype_with_data {
                        if !cnames_followed.contains(cname) {
                            let mut new_question = question.clone();
                            new_question.name = cname.clone();
                            new_questions.push(new_question);
                            cnames_followed.insert(cname.clone());
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
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
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
                return Some(make_rr(RecordTypeWithData::CNAME {
                    cname: name.domain.clone(),
                }));
            } else if RecordType::A.matches(&question.qtype) {
                if let Some(address) = static_record.record_a {
                    return Some(make_rr(RecordTypeWithData::A { address }));
                }
            }
        }
    }

    // TODO: use a more efficient data structure (like a trie)
    for blocked_domain in &local_zone.blocked_domains {
        if blocked_domain.matches(&question.name) {
            // Return an A record pointing to 0.0.0.0 - copied from
            // what pi hole does.
            return Some(make_rr(RecordTypeWithData::A {
                address: Ipv4Addr::new(0, 0, 0, 0),
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
    let mut rrs = cache.get(&question.name, &question.qtype, &question.qclass);

    if rrs.is_empty() && question.qtype != QueryType::Record(RecordType::CNAME) {
        rrs = cache.get(
            &question.name,
            &QueryType::Record(RecordType::CNAME),
            &question.qclass,
        )
    }

    // TODO: implement authority record
    (rrs, None)
}

/// Get the best nameservers by non-recursively looking them up for
/// the domain and all its superdomains, in order.  If no nameservers
/// are found, the root hints are returned.
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
            let ns_q = Question {
                name: name.clone(),
                qtype: QueryType::Record(RecordType::NS),
                qclass: QueryClass::Record(RecordClass::IN),
            };

            let mut hostnames = Vec::new();

            if let Some(resolved) = resolve_nonrecursive(local_zone, cache, &ns_q) {
                for ns_rr in resolved.rrs() {
                    if let RecordTypeWithData::NS { nsdname } = &ns_rr.rtype_with_data {
                        hostnames.push(HostOrIP::Host(nsdname.clone()));
                    }
                }
            }

            if !hostnames.is_empty() {
                return Nameservers {
                    hostnames,
                    name: ns_q.name,
                };
            }
        }
    }

    Nameservers {
        hostnames: root_hints.iter().copied().map(HostOrIP::IP).collect(),
        name: DomainName::root_domain(),
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

        let mut rrs_for_query = Vec::<ResourceRecord>::with_capacity(response.answers.len());
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

#[cfg(test)]
mod tests {
    use super::cache::test_util::*;
    use super::*;
    use crate::protocol::wire_types::test_util::*;
    use crate::settings::*;

    #[test]
    fn resolve_nonrecursive_is_authoritative_for_local_zone() {
        assert_eq!(
            Some(ResolvedRecord::Authoritative {
                rrs: vec![a_record("a.example.com", Ipv4Addr::new(1, 1, 1, 1))]
            }),
            resolve_nonrecursive(
                &local_zone(),
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

        if let Some(ResolvedRecord::NonAuthoritative {
            rrs,
            authority: None,
        }) = resolve_nonrecursive(
            &local_zone(),
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
    fn resolve_nonrecursive_prefers_local_zone() {
        let rr = a_record("a.example.com", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&a_record("a.example.com", Ipv4Addr::new(8, 8, 8, 8)));

        assert_eq!(
            Some(ResolvedRecord::Authoritative { rrs: vec![rr] }),
            resolve_nonrecursive(
                &local_zone(),
                &cache,
                &Question {
                    name: domain("a.example.com"),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                }
            )
        )
    }

    #[test]
    fn resolve_nonrecursive_expands_cnames() {
        let cname_rr1 = cname_record("cname-1.example.com", "cname-2.example.com");
        let cname_rr2 = cname_record("cname-2.example.com", "a.example.com");
        let a_rr = a_record("a.example.com", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&cname_rr1);
        cache.insert(&cname_rr2);

        if let Some(ResolvedRecord::NonAuthoritative {
            rrs,
            authority: None,
        }) = resolve_nonrecursive(
            &local_zone(),
            &cache,
            &Question {
                name: domain("cname-1.example.com"),
                qtype: QueryType::Wildcard,
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
    fn authoritative_from_zone_finds_record() {
        assert_eq!(
            Some(a_record("a.example.com", Ipv4Addr::new(1, 1, 1, 1))),
            authoritative_from_zone(
                &local_zone(),
                &Question {
                    name: domain("a.example.com"),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard
                }
            )
        )
    }

    #[test]
    fn authoritative_from_zone_prefers_cname() {
        assert_eq!(
            Some(cname_record(
                "cname-and-a.example.com",
                "cname-target.example.com"
            )),
            authoritative_from_zone(
                &local_zone(),
                &Question {
                    name: domain("cname-and-a.example.com"),
                    qtype: QueryType::Record(RecordType::A),
                    qclass: QueryClass::Wildcard
                }
            )
        )
    }

    #[test]
    fn authoritative_from_zone_blocklists_to_a0000() {
        assert_eq!(
            Some(a_record("blocked.example.com", Ipv4Addr::new(0, 0, 0, 0))),
            authoritative_from_zone(
                &local_zone(),
                &Question {
                    name: domain("blocked.example.com"),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard
                }
            )
        )
    }

    #[test]
    fn nonauthoritative_from_cache_finds_record() {
        let rr = a_record("www.example.com", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&rr);

        let (actuals, _) = nonauthoritative_from_cache(
            &cache,
            &Question {
                name: domain("www.example.com"),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Wildcard,
            },
        );
        assert_cache_response(&rr, actuals);
    }

    #[test]
    fn nonauthoritative_from_cache_falls_back_to_cname() {
        let rr = cname_record("www.example.com", "cname-target.example.com");

        let cache = SharedCache::new();
        cache.insert(&rr);

        let (actuals, _) = nonauthoritative_from_cache(
            &cache,
            &Question {
                name: domain("www.example.com"),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Wildcard,
            },
        );
        assert_cache_response(&rr, actuals);
    }

    #[test]
    fn candidate_nameservers_gets_all_matches() {
        let qdomain = domain("com");
        assert_eq!(
            Nameservers {
                hostnames: vec![
                    HostOrIP::Host(domain("ns1.example.com")),
                    HostOrIP::Host(domain("ns2.example.com"))
                ],
                name: qdomain.clone(),
            },
            candidate_nameservers(
                &[],
                &local_zone(),
                &cache_with_nameservers(&["com"]),
                &qdomain
            )
        );
    }

    #[test]
    fn candidate_nameservers_returns_longest_match() {
        assert_eq!(
            Nameservers {
                hostnames: vec![
                    HostOrIP::Host(domain("ns1.example.com")),
                    HostOrIP::Host(domain("ns2.example.com"))
                ],
                name: domain("example.com"),
            },
            candidate_nameservers(
                &[],
                &local_zone(),
                &cache_with_nameservers(&["example.com", "com"]),
                &domain("www.example.com")
            )
        );
    }

    #[test]
    fn candidate_nameservers_returns_root_hints_on_failure() {
        let root_hints = vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];

        assert_eq!(
            Nameservers {
                hostnames: root_hints.iter().copied().map(HostOrIP::IP).collect(),
                name: DomainName::root_domain(),
            },
            candidate_nameservers(
                &root_hints,
                &local_zone(),
                &cache_with_nameservers(&["com"]),
                &domain("net")
            )
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
                authority: None,
            }),
            validate_nameserver_response(&request, response, 0)
        );
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
                authority: None,
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

    fn local_zone() -> Settings {
        let to_domain = |name| DomainWithOptionalSubdomains {
            name: Name {
                domain: domain(name),
            },
            include_subdomains: false,
        };

        Settings {
            root_hints: Vec::new(),
            blocked_domains: vec![to_domain("blocked.example.com")],
            static_records: vec![
                Record {
                    domain: to_domain("cname-and-a.example.com"),
                    record_a: Some(Ipv4Addr::new(1, 1, 1, 1)),
                    record_cname: Some(Name {
                        domain: domain("cname-target.example.com"),
                    }),
                },
                Record {
                    domain: to_domain("a.example.com"),
                    record_a: Some(Ipv4Addr::new(1, 1, 1, 1)),
                    record_cname: None,
                },
            ],
        }
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
