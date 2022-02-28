pub mod cache;

use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::net_util::read_tcp_bytes;
use crate::protocol::{
    ConsumableBuffer, DomainName, Message, QueryClass, QueryType, Question, Rcode, RecordClass,
    RecordType, RecordTypeWithData, ResourceRecord,
};
use crate::settings::Settings;

/// Resolve a question.  This may give more than one `ResolvedRecord`
/// if the question is for a record and the result is a CNAME but the
/// query was for some other record type: the CNAME will be resolved
/// using the same recursion approach, and all records returned.
///
/// This function gives up if the CNAMEs form a cycle.
///
/// If every returned record is authoritative, then the response as a
/// whole is authoritative.
pub async fn resolve(
    is_recursive: bool,
    upstream_nameservers: &[Ipv4Addr],
    local_zone: &Settings,
    cache: &(),
    initial_question: &Question,
) -> Vec<ResolvedRecord> {
    // TODO implement cache

    let mut questions = vec![initial_question.clone()];
    let mut out = Vec::with_capacity(1);
    let mut cnames_followed = HashSet::new();

    while !questions.is_empty() {
        let mut new_questions = Vec::new();

        for question in questions {
            if let Some(resolved_record) = if is_recursive {
                resolve_recursive(upstream_nameservers, local_zone, cache, &question).await
            } else {
                resolve_nonrecursive(local_zone, cache, &question)
            } {
                out.push(resolved_record.clone());

                if question.qtype != QueryType::Record(RecordType::CNAME) {
                    for rr in resolved_record.rrs() {
                        if let RecordTypeWithData::Named {
                            rtype: RecordType::CNAME,
                            name,
                        } = rr.rtype_with_data
                        {
                            if !cnames_followed.contains(&name) {
                                let mut new_question = question.clone();
                                new_question.name = name.clone();
                                new_questions.push(new_question);
                                cnames_followed.insert(name.clone());
                            }
                        }
                    }
                }
            }
        }

        questions = new_questions;
    }

    out
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
/// See section 4.3.2 of RFC 1034.
pub fn resolve_nonrecursive(
    local_zone: &Settings,
    cache: &(),
    question: &Question,
) -> Option<ResolvedRecord> {
    // TODO: implement reading from cache

    if let Some(authoritative) = authoritative_from_zone(local_zone, question) {
        return Some(ResolvedRecord::Authoritative {
            rrs: vec![authoritative],
        });
    }

    let (cached_rrs, cached_authority_rr) = nonauthoritative_from_cache(cache, question);
    if !cached_rrs.is_empty() {
        return Some(ResolvedRecord::NonAuthoritative {
            rrs: cached_rrs,
            authority: cached_authority_rr,
        });
    }

    None
}

/// Recursive DNS resolution.
///
/// This corresponds to the standard resolver algorithm.  If
/// information is not held locally, it will call out to remote
/// nameservers, starting with the given root hints.  Since it may
/// make network requests, this function is async.
///
/// See section 5.3.3 of RFC 1034.
pub async fn resolve_recursive(
    root_hints: &[Ipv4Addr],
    local_zone: &Settings,
    cache: &(),
    question: &Question,
) -> Option<ResolvedRecord> {
    // TODO: implement inserting into cache

    if let Some(resolved) = resolve_nonrecursive(local_zone, cache, question) {
        let rrs = resolved.clone().rrs();
        let authority = resolved.authority();
        return Some(ResolvedRecord::NonAuthoritative { rrs, authority });
    } else {
        // TODO: query nameservers concurrently
        let (mut match_count, mut nameservers) = {
            let candidates = candidate_nameservers(root_hints, local_zone, cache, &question.name);
            (candidates.match_count(), candidates.ips)
        };
        while !nameservers.is_empty() {
            let mut new_match_count = match_count + 1;
            let mut new_nameservers = Vec::new();
            'query: for ns in nameservers {
                match query_nameserver(&ns, question).await {
                    None => (),
                    Some(NameserverResponse::Answer { rrs }) => {
                        return Some(ResolvedRecord::NonAuthoritative {
                            rrs,
                            authority: None,
                        })
                    }
                    Some(NameserverResponse::Delegation { delegation }) => {
                        let d_match_count = delegation.match_count();
                        if d_match_count > match_count {
                            new_match_count = d_match_count;
                            new_nameservers = delegation.ips;
                            break 'query;
                        }
                    }
                }
            }
            nameservers = new_nameservers;
            match_count = new_match_count;
        }
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
///
/// TODO: implement
pub fn nonauthoritative_from_cache(
    _cache: &(),
    _question: &Question,
) -> (Vec<ResourceRecord>, Option<ResourceRecord>) {
    (Vec::new(), None)
}

/// Get the best nameservers.
///
/// This corresponds to step 2 of the standard resolver algorithm.
pub fn candidate_nameservers(
    root_hints: &[Ipv4Addr],
    local_zone: &Settings,
    cache: &(),
    question: &DomainName,
) -> Nameservers {
    for i in 0..question.labels.len() {
        let labels = &question.labels[i..];
        if let Some(name) = DomainName::from_labels(labels.into()) {
            if let Some(nameservers) = find_nameserver_ips(local_zone, cache, &name) {
                return nameservers;
            }
        }
    }

    Nameservers {
        ips: root_hints.into(),
        name: DomainName::root_domain(),
    }
}

/// Non-recursively look up nameservers for a domain and return their
/// IPv4 addresses.
pub fn find_nameserver_ips(
    local_zone: &Settings,
    cache: &(),
    name: &DomainName,
) -> Option<Nameservers> {
    let mut ips = Vec::new();

    let ns_q = Question {
        name: name.clone(),
        qtype: QueryType::Record(RecordType::NS),
        qclass: QueryClass::Record(RecordClass::IN),
    };

    if let Some(resolved) = resolve_nonrecursive(local_zone, cache, &ns_q) {
        for ns_rr in resolved.rrs() {
            let a_q = Question {
                name: ns_rr.name,
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Record(RecordClass::IN),
            };
            if let Some(resolved) = resolve_nonrecursive(local_zone, cache, &a_q) {
                for a_rr in resolved.rrs() {
                    if let Some(ip) = get_ip_from_a_rr(&a_rr) {
                        ips.push(ip);
                    }
                }
            }
        }
    }

    if ips.is_empty() {
        None
    } else {
        Some(Nameservers {
            ips,
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
) -> Option<NameserverResponse> {
    let request = Message::from_question(rand::thread_rng().gen(), question.clone());

    let udp_response = query_nameserver_udp(address, &request).await;
    if udp_response.is_some() {
        udp_response
    } else {
        query_nameserver_tcp(address, &request).await
    }
}

/// Send a message to a remote nameserver over UDP, returning the
/// response.  If the response does not match the query (header does
/// not match, question does not match, response is of the wrong type
/// or domain), `None` is returned.
///
/// This has a 15s timeout.
pub async fn query_nameserver_udp(
    address: &Ipv4Addr,
    request: &Message,
) -> Option<NameserverResponse> {
    match timeout(
        Duration::from_secs(15),
        query_nameserver_udp_notimeout(address, request),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => None,
    }
}

/// Timeout-less version of `query_nameserver_udp`.
///
/// TODO: implement
async fn query_nameserver_udp_notimeout(
    _address: &Ipv4Addr,
    _request: &Message,
) -> Option<NameserverResponse> {
    None
}

/// Send a message to a remote nameserver over TCP, returning the
/// response.  This does the same response validation as
/// `query_nameserver_udp`.
///
/// This has a 15s timeout.
pub async fn query_nameserver_tcp(
    address: &Ipv4Addr,
    request: &Message,
) -> Option<NameserverResponse> {
    match timeout(
        Duration::from_secs(15),
        query_nameserver_tcp_notimeout(address, request),
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
    request: &Message,
) -> Option<NameserverResponse> {
    match TcpStream::connect((*address, 53)).await {
        Ok(mut stream) => match stream.write_all(&request.clone().serialise_for_tcp()).await {
            Ok(_) => match read_tcp_bytes(&mut stream).await {
                Ok(bytes) => match Message::parse(&mut ConsumableBuffer::new(bytes.as_ref())) {
                    Ok(response) => validate_nameserver_response(request, response),
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
/// - Check that there is a response or an authority:
///
///   - the response, if any, must records of the right type and
///     domain.
///
///   - the authority, if any, must NS records for a suffix of the
///     domain, and corresponding A records in the additional section.
///
/// This makes the simplifying assumption that the question message
/// has a single question in it, because that is how this function is
/// used by this module.  If that assumption does not hold, a valid
/// answer may be reported as invalid.
pub fn validate_nameserver_response(
    request: &Message,
    response: Message,
) -> Option<NameserverResponse> {
    if request.questions.len() != 1 {
        panic!("validate_nameserver_response only works for single-question messages");
    }

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

    if response.header.ancount > 0 {
        for an in &response.answers {
            if an.name != question.name {
                return None;
            }
            if !an.rclass.matches(&question.qclass) {
                return None;
            }
            if !an.rtype_with_data.matches(&question.qtype) {
                return None;
            }
        }
        Some(NameserverResponse::Answer {
            rrs: response.answers,
        })
    } else if response.header.nscount > 0 {
        let mut ips = Vec::<Ipv4Addr>::new();
        let mut name = None;

        let mut additional_as = HashMap::with_capacity(response.header.arcount.into());
        for ar in &response.additional {
            if !ar.rclass.matches(&question.qclass) {
                continue;
            }
            if let Some(ip) = get_ip_from_a_rr(ar) {
                additional_as.insert(&ar.name.octets, ip);
            }
        }

        for ns in &response.authority {
            if let Some(ref found_name) = name {
                if ns.name != *found_name {
                    continue;
                }
            }
            if !ns.rclass.matches(&question.qclass) {
                continue;
            }
            if let Some(target) = get_target_from_ns_rr(ns) {
                if let Some(ip) = additional_as.get(&target.octets) {
                    ips.push(*ip);
                    name = Some(ns.name.clone());
                }
            }
        }

        if let Some(found_name) = name {
            if ips.is_empty() {
                None
            } else {
                Some(NameserverResponse::Delegation {
                    delegation: Nameservers {
                        ips,
                        name: found_name,
                    },
                })
            }
        } else {
            None
        }
    } else {
        None
    }
}

/// A set of nameservers for a domain
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Nameservers {
    /// Guaranteed to be non-empty.
    pub ips: Vec<Ipv4Addr>,
    pub name: DomainName,
}

impl Nameservers {
    pub fn match_count(&self) -> usize {
        self.name.labels.len()
    }
}

/// A response from a remote nameserver
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NameserverResponse {
    Answer { rrs: Vec<ResourceRecord> },
    Delegation { delegation: Nameservers },
}

/// Helper function to turn an A RR into an IP address
fn get_ip_from_a_rr(rr: &ResourceRecord) -> Option<Ipv4Addr> {
    if let RecordTypeWithData::Uninterpreted {
        rtype: RecordType::A,
        octets,
    } = &rr.rtype_with_data
    {
        if let [a, b, c, d] = octets[..] {
            return Some(Ipv4Addr::new(a, b, c, d));
        }
    }

    None
}

/// Helper function to turn an NS RR into a name
fn get_target_from_ns_rr(rr: &ResourceRecord) -> Option<DomainName> {
    if let RecordTypeWithData::Named {
        rtype: RecordType::NS,
        name,
    } = &rr.rtype_with_data
    {
        Some(name.clone())
    } else {
        None
    }
}
