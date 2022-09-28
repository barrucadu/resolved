use async_recursion::async_recursion;
use rand::Rng;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::Instrument;

use dns_types::protocol::types::*;
use dns_types::zones::types::*;

use crate::cache::SharedCache;
use crate::local::*;
use crate::metrics::Metrics;
use crate::util::nameserver::*;
use crate::util::types::*;

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
///
/// # Errors
///
/// See `ResolutionError`.
pub async fn resolve_recursive(
    recursion_limit: usize,
    metrics: &mut Metrics,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Result<ResolvedRecord, ResolutionError> {
    if let Ok(res) = timeout(
        Duration::from_secs(60),
        resolve_recursive_notimeout(recursion_limit, metrics, zones, cache, question),
    )
    .await
    {
        res
    } else {
        tracing::debug!("timed out");
        Err(ResolutionError::Timeout)
    }
}

/// Timeout-less version of `resolve_recursive`.
#[async_recursion]
async fn resolve_recursive_notimeout(
    recursion_limit: usize,
    metrics: &mut Metrics,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Result<ResolvedRecord, ResolutionError> {
    if recursion_limit == 0 {
        tracing::debug!("hit recursion limit");
        return Err(ResolutionError::RecursionLimit);
    }

    let mut candidates = None;
    let mut combined_rrs = Vec::new();

    match resolve_local(recursion_limit, metrics, zones, cache, question) {
        Ok(LocalResolutionResult::Done { resolved }) => return Ok(resolved),
        Ok(LocalResolutionResult::Partial { rrs }) => combined_rrs = rrs,
        Ok(LocalResolutionResult::Delegation { delegation, .. }) => candidates = Some(delegation),
        Ok(LocalResolutionResult::CNAME {
            rrs,
            cname_question,
            ..
        }) => {
            return resolve_combined_recursive(
                recursion_limit - 1,
                metrics,
                zones,
                cache,
                rrs,
                cname_question,
            )
            .await
        }
        Err(_) => (),
    }

    if candidates.is_none() {
        candidates =
            candidate_nameservers(recursion_limit - 1, metrics, zones, cache, &question.name);
    }

    if let Some(mut candidates) = candidates {
        'query_nameservers: while let Some(candidate) = candidates.hostnames.pop() {
            tracing::trace!(?candidate, "got candidate nameserver");
            if let Some(ip) =
                resolve_hostname_to_ip(recursion_limit - 1, metrics, zones, cache, candidate).await
            {
                if let Some(nameserver_answer) = query_nameserver(ip, question, candidates.match_count())
                    .instrument(tracing::error_span!("query_nameserver", address = %ip, match_count = %candidates.match_count()))
                    .await
                {
                    metrics.nameserver_hit();
                    match nameserver_answer {
                        NameserverResponse::Answer { rrs, .. } => {
                            tracing::trace!("got recursive answer");
                            cache.insert_all(&rrs);
                            prioritising_merge(&mut combined_rrs, rrs);
                            return Ok(ResolvedRecord::NonAuthoritative { rrs: combined_rrs });
                        }
                        NameserverResponse::Delegation { rrs, delegation, .. } => {
                            tracing::trace!("got recursive delegation - using as candidate");
                            cache.insert_all(&rrs);
                            candidates = delegation;
                            continue 'query_nameservers;
                        }
                        NameserverResponse::CNAME { rrs, cname, .. } => {
                            tracing::trace!("got recursive CNAME");
                            cache.insert_all(&rrs);
                            prioritising_merge(&mut combined_rrs, rrs);
                            let cname_question = Question {
                                name: cname,
                                qclass: question.qclass,
                                qtype: question.qtype,
                            };
                            return resolve_combined_recursive(recursion_limit - 1, metrics, zones, cache, combined_rrs, cname_question).await;
                        }
                    }
                } else {
                    metrics.nameserver_miss();
                    // TODO: should distinguish between timeouts and other
                    // failures here, and try the next nameserver after a
                    // timeout.
                    return Err(ResolutionError::DeadEnd {
                        question: question.clone(),
                    });
                }
            } else {
                // failed to get an IP for this candidate - loop and try the
                // next
            }
        }
    }

    tracing::trace!("out of candidates");
    Err(ResolutionError::DeadEnd {
        question: question.clone(),
    })
}

/// Helper function for resolving CNAMEs: resolve, and add some existing RRs to
/// the ANSWER section of the result.
async fn resolve_combined_recursive(
    recursion_limit: usize,
    metrics: &mut Metrics,
    zones: &Zones,
    cache: &SharedCache,
    mut rrs: Vec<ResourceRecord>,
    question: Question,
) -> Result<ResolvedRecord, ResolutionError> {
    match resolve_recursive_notimeout(recursion_limit - 1, metrics, zones, cache, &question)
        .instrument(tracing::error_span!("resolve_combined_recursive", %question))
        .await
    {
        Ok(resolved) => {
            rrs.append(&mut resolved.rrs());
            Ok(ResolvedRecord::NonAuthoritative { rrs })
        }
        Err(_) => Err(ResolutionError::DeadEnd { question }),
    }
}

/// Resolve a hostname into an IP address.
async fn resolve_hostname_to_ip(
    recursion_limit: usize,
    metrics: &mut Metrics,
    zones: &Zones,
    cache: &SharedCache,
    hostname: HostOrIP,
) -> Option<Ipv4Addr> {
    match hostname {
        HostOrIP::IP(ip) => Some(ip),
        HostOrIP::Host(name) => {
            let question = Question {
                name: name.clone(),
                qclass: QueryClass::Record(RecordClass::IN),
                qtype: QueryType::Record(RecordType::A),
            };
            if let Ok(result) =
                resolve_recursive_notimeout(recursion_limit - 1, metrics, zones, cache, &question)
                    .instrument(tracing::error_span!("resolve_hostname_to_ip", %question))
                    .await
            {
                get_ip(&result.rrs(), &name)
            } else {
                None
            }
        }
    }
}

/// Get the best nameservers by non-recursively looking them up for
/// the domain and all its superdomains, in order.  If no nameservers
/// are found, the root hints are returned.
///
/// This corresponds to step 2 of the standard resolver algorithm.
fn candidate_nameservers(
    recursion_limit: usize,
    metrics: &mut Metrics,
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

            if let Ok(LocalResolutionResult::Done { resolved }) =
                resolve_local(recursion_limit - 1, metrics, zones, cache, &ns_q)
            {
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
async fn query_nameserver(
    address: Ipv4Addr,
    question: &Question,
    current_match_count: usize,
) -> Option<NameserverResponse> {
    let request = Message::from_question(rand::thread_rng().gen(), question.clone());

    tracing::trace!("forwarding query to nameserver");

    match request.clone().to_octets() {
        Ok(mut serialised_request) => {
            let udp_response = query_nameserver_udp(address, &mut serialised_request)
                .await
                .and_then(|res| validate_nameserver_response(&request, &res, current_match_count));
            if udp_response.is_some() {
                udp_response
            } else {
                query_nameserver_tcp(address, &mut serialised_request)
                    .await
                    .and_then(|res| {
                        validate_nameserver_response(&request, &res, current_match_count)
                    })
            }
        }
        Err(error) => {
            tracing::warn!(message = ?request, ?error, "could not serialise message");
            None
        }
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
fn validate_nameserver_response(
    request: &Message,
    response: &Message,
    current_match_count: usize,
) -> Option<NameserverResponse> {
    // precondition
    if request.questions.len() != 1 {
        tracing::warn!(qdcount = %request.questions.len(), "expected only one question");
        return None;
    }
    let question = &request.questions[0];

    // step 1: validation
    if !response_matches_request(request, response) {
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
            tracing::warn!("expected RRs");
            None
        } else {
            // step 3.1 & 3.2: what sort of answer is this?
            if seen_final_record {
                Some(NameserverResponse::Answer {
                    rrs: rrs_for_query,
                    is_authoritative: false,
                    authority_rrs: Vec::new(),
                })
            } else {
                Some(NameserverResponse::CNAME {
                    rrs: rrs_for_query,
                    cname: final_name,
                    is_authoritative: false,
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
                    nameserver_rrs.push(rr.clone());
                }
                RecordTypeWithData::A { .. } if ns_names.contains(&rr.name) => {
                    nameserver_rrs.push(rr.clone());
                }
                _ => (),
            }
        }
        for rr in &response.authority {
            match &rr.rtype_with_data {
                RecordTypeWithData::NS { nsdname } if ns_names.contains(nsdname) => {
                    nameserver_rrs.push(rr.clone());
                }
                _ => (),
            }
        }
        for rr in &response.additional {
            match &rr.rtype_with_data {
                RecordTypeWithData::A { .. } if ns_names.contains(&rr.name) => {
                    nameserver_rrs.push(rr.clone());
                }
                _ => (),
            }
        }

        // step 3.3: this is a delegation
        Some(NameserverResponse::Delegation {
            rrs: nameserver_rrs,
            authority_rrs: Vec::new(),
            is_authoritative: false,
            delegation: Nameservers {
                hostnames: ns_names.into_iter().map(HostOrIP::Host).collect(),
                name: match_name,
            },
        })
    }
}

/// Given a set of RRs and a domain name we're looking for, follow
/// `CNAME`s in the response and return the final name (which is the
/// name that will have the non-`CNAME` records associated with it).
///
/// Returns `None` if CNAMEs form a loop, or there is no RR which
/// matches the target name (a CNAME or one with the right type).
pub fn follow_cnames(
    rrs: &[ResourceRecord],
    target: &DomainName,
    qtype: &QueryType,
) -> Option<(DomainName, HashMap<DomainName, DomainName>)> {
    let mut got_match = false;
    let mut cname_map = HashMap::<DomainName, DomainName>::new();
    for rr in rrs {
        if &rr.name == target && rr.rtype_with_data.matches(qtype) {
            got_match = true;
        }
        if let RecordTypeWithData::CNAME { cname } = &rr.rtype_with_data {
            cname_map.insert(rr.name.clone(), cname.clone());
        }
    }

    let mut seen = HashSet::new();
    let mut final_name = target.clone();
    while let Some(target) = cname_map.get(&final_name) {
        if seen.contains(target) {
            return None;
        }
        seen.insert(target.clone());
        final_name = target.clone();
    }

    if got_match || !seen.is_empty() {
        Some((final_name, cname_map))
    } else {
        None
    }
}

/// Given a set of RRs and a domain name we're looking for, look for
/// better matching NS RRs (by comparing the current match count).
/// Returns the new matching superdomain and the nameserver hostnames.
pub fn get_better_ns_names(
    rrs: &[ResourceRecord],
    target: &DomainName,
    current_match_count: usize,
) -> Option<(DomainName, HashSet<DomainName>)> {
    let mut ns_names = HashSet::new();
    let mut match_count = current_match_count;
    let mut match_name = None;

    for rr in rrs {
        if let RecordTypeWithData::NS { nsdname } = &rr.rtype_with_data {
            if target.is_subdomain_of(&rr.name) {
                match rr.name.labels.len().cmp(&match_count) {
                    Ordering::Greater => {
                        match_count = rr.name.labels.len();
                        match_name = Some(rr.name.clone());

                        ns_names.clear();
                        ns_names.insert(nsdname.clone());
                    }
                    Ordering::Equal => {
                        ns_names.insert(nsdname.clone());
                    }
                    Ordering::Less => (),
                }
            }
        }
    }

    match_name.map(|mn| (mn, ns_names))
}

/// Given a set of RRs and a domain name we're looking for, follow any
/// `CNAME`s in the response and get the address from the final `A`
/// record.
pub fn get_ip(rrs: &[ResourceRecord], target: &DomainName) -> Option<Ipv4Addr> {
    if let Some((final_name, _)) = follow_cnames(rrs, target, &QueryType::Record(RecordType::A)) {
        for rr in rrs {
            match &rr.rtype_with_data {
                RecordTypeWithData::A { address } if rr.name == final_name => {
                    return Some(*address);
                }
                _ => (),
            }
        }
    }

    None
}

/// A response from a remote nameserver
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NameserverResponse {
    Answer {
        rrs: Vec<ResourceRecord>,
        is_authoritative: bool,
        authority_rrs: Vec<ResourceRecord>,
    },
    CNAME {
        rrs: Vec<ResourceRecord>,
        cname: DomainName,
        is_authoritative: bool,
    },
    Delegation {
        rrs: Vec<ResourceRecord>,
        delegation: Nameservers,
        is_authoritative: bool,
        authority_rrs: Vec<ResourceRecord>,
    },
}

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;

    use super::*;
    use crate::util::nameserver::test_util::*;
    use crate::util::test_util::*;

    #[test]
    fn candidate_nameservers_gets_all_matches() {
        let qdomain = domain("com.");
        assert_eq!(
            Some(Nameservers {
                hostnames: vec![
                    HostOrIP::Host(domain("ns1.example.com.")),
                    HostOrIP::Host(domain("ns2.example.com."))
                ],
                name: qdomain.clone(),
            }),
            candidate_nameservers(
                10,
                &mut Metrics::new(),
                &zones(),
                &cache_with_nameservers(&["com."]),
                &qdomain
            )
        );
    }

    #[test]
    fn candidate_nameservers_returns_longest_match() {
        assert_eq!(
            Some(Nameservers {
                hostnames: vec![
                    HostOrIP::Host(domain("ns1.example.com.")),
                    HostOrIP::Host(domain("ns2.example.com."))
                ],
                name: domain("example.com."),
            }),
            candidate_nameservers(
                10,
                &mut Metrics::new(),
                &zones(),
                &cache_with_nameservers(&["example.com.", "com."]),
                &domain("www.example.com.")
            )
        );
    }

    #[test]
    fn candidate_nameservers_returns_none_on_failure() {
        assert_eq!(
            None,
            candidate_nameservers(
                10,
                &mut Metrics::new(),
                &zones(),
                &cache_with_nameservers(&["com."]),
                &domain("net.")
            )
        );
    }

    #[test]
    fn validate_nameserver_response_returns_answer() {
        let (request, response) = nameserver_response(
            "www.example.com.",
            &[a_record("www.example.com.", Ipv4Addr::new(127, 0, 0, 1))],
            &[],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::Answer {
                rrs: vec![a_record("www.example.com.", Ipv4Addr::new(127, 0, 0, 1))],
                is_authoritative: false,
                authority_rrs: Vec::new(),
            }),
            validate_nameserver_response(&request, &response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_drops_unknown_rrs() {
        let request = Message::from_question(
            1234,
            Question {
                name: domain("www.example.com."),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Record(RecordClass::IN),
            },
        );

        let mut response = request.make_response();
        response.answers = [
            unknown_record("www.example.com.", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            a_record("www.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
        ]
        .into();

        assert_eq!(
            Some(NameserverResponse::Answer {
                rrs: vec![a_record("www.example.com.", Ipv4Addr::new(1, 1, 1, 1))],
                is_authoritative: false,
                authority_rrs: Vec::new(),
            }),
            validate_nameserver_response(&request, &response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_returns_none_if_all_rrs_unknown() {
        let request = Message::from_question(
            1234,
            Question {
                name: domain("www.example.com."),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Record(RecordClass::IN),
            },
        );

        let mut response = request.make_response();
        response.answers = [unknown_record(
            "www.example.com.",
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        )]
        .into();

        assert_eq!(None, validate_nameserver_response(&request, &response, 0));
    }

    #[test]
    fn validate_nameserver_response_follows_cnames() {
        let (request, response) = nameserver_response(
            "www.example.com.",
            &[
                cname_record("www.example.com.", "cname-target.example.com."),
                a_record("cname-target.example.com.", Ipv4Addr::new(127, 0, 0, 1)),
            ],
            &[],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::Answer {
                rrs: vec![
                    cname_record("www.example.com.", "cname-target.example.com."),
                    a_record("cname-target.example.com.", Ipv4Addr::new(127, 0, 0, 1))
                ],
                is_authoritative: false,
                authority_rrs: Vec::new(),
            }),
            validate_nameserver_response(&request, &response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_returns_partial_answer() {
        let (request, response) = nameserver_response(
            "www.example.com.",
            &[cname_record(
                "www.example.com.",
                "cname-target.example.com.",
            )],
            &[],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::CNAME {
                rrs: vec![cname_record(
                    "www.example.com.",
                    "cname-target.example.com."
                )],
                cname: domain("cname-target.example.com."),
                is_authoritative: false,
            }),
            validate_nameserver_response(&request, &response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_gets_ns_from_answers_and_authority_but_not_additional() {
        let (request, response) = nameserver_response(
            "www.example.com.",
            &[ns_record("example.com.", "ns-an.example.net.")],
            &[ns_record("example.com.", "ns-ns.example.net.")],
            &[ns_record("example.com.", "ns-ar.example.net.")],
        );

        match validate_nameserver_response(&request, &response, 0) {
            Some(NameserverResponse::Delegation {
                rrs: mut actual_rrs,
                delegation: mut actual_delegation,
                is_authoritative,
                authority_rrs,
            }) => {
                assert!(!is_authoritative);
                assert!(authority_rrs.is_empty());

                let mut expected_rrs = vec![
                    ns_record("example.com.", "ns-an.example.net."),
                    ns_record("example.com.", "ns-ns.example.net."),
                ];

                expected_rrs.sort();
                actual_rrs.sort();

                assert_eq!(expected_rrs, actual_rrs);

                let mut expected_delegation = Nameservers {
                    hostnames: vec![
                        HostOrIP::Host(domain("ns-an.example.net.")),
                        HostOrIP::Host(domain("ns-ns.example.net.")),
                    ],
                    name: domain("example.com."),
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
            "long.subdomain.example.com.",
            &[ns_record("example.com.", "ns.example.net.")],
            &[],
            &[],
        );

        assert_eq!(
            None,
            validate_nameserver_response(
                &request,
                &response,
                domain("subdomain.example.com.").labels.len()
            )
        );
    }

    #[test]
    fn validate_nameserver_response_prefers_best_ns() {
        let (request, response1) = nameserver_response(
            "long.subdomain.example.com.",
            &[ns_record(
                "subdomain.example.com.",
                "ns-better.example.net.",
            )],
            &[ns_record("example.com.", "ns-worse.example.net.")],
            &[],
        );
        let (_, response2) = nameserver_response(
            "long.subdomain.example.com.",
            &[ns_record("example.com.", "ns-worse.example.net.")],
            &[ns_record(
                "subdomain.example.com.",
                "ns-better.example.net.",
            )],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::Delegation {
                rrs: vec![ns_record(
                    "subdomain.example.com.",
                    "ns-better.example.net."
                )],
                authority_rrs: Vec::new(),
                is_authoritative: false,
                delegation: Nameservers {
                    hostnames: vec![HostOrIP::Host(domain("ns-better.example.net."))],
                    name: domain("subdomain.example.com."),
                },
            }),
            validate_nameserver_response(&request, &response1, 0)
        );

        assert_eq!(
            Some(NameserverResponse::Delegation {
                rrs: vec![ns_record(
                    "subdomain.example.com.",
                    "ns-better.example.net."
                )],
                authority_rrs: Vec::new(),
                is_authoritative: false,
                delegation: Nameservers {
                    hostnames: vec![HostOrIP::Host(domain("ns-better.example.net."))],
                    name: domain("subdomain.example.com."),
                },
            }),
            validate_nameserver_response(&request, &response2, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_gets_ns_a_from_answers_and_additional_but_not_authority() {
        let (request, response) = nameserver_response(
            "www.example.com.",
            &[
                ns_record("example.com.", "ns-an.example.net."),
                a_record("ns-an.example.net.", Ipv4Addr::new(1, 1, 1, 1)),
                a_record("ns-ns.example.net.", Ipv4Addr::new(1, 1, 1, 1)),
            ],
            &[
                ns_record("example.com.", "ns-ns.example.net."),
                a_record("ns-an.example.net.", Ipv4Addr::new(2, 2, 2, 2)),
                a_record("ns-ns.example.net.", Ipv4Addr::new(2, 2, 2, 2)),
            ],
            &[
                a_record("ns-an.example.net.", Ipv4Addr::new(3, 3, 3, 3)),
                a_record("ns-ns.example.net.", Ipv4Addr::new(3, 3, 3, 3)),
            ],
        );

        match validate_nameserver_response(&request, &response, 0) {
            Some(NameserverResponse::Delegation {
                rrs: mut actual_rrs,
                delegation: _,
                authority_rrs,
                is_authoritative,
            }) => {
                assert!(!is_authoritative);
                assert!(authority_rrs.is_empty());

                let mut expected_rrs = vec![
                    ns_record("example.com.", "ns-an.example.net."),
                    ns_record("example.com.", "ns-ns.example.net."),
                    a_record("ns-an.example.net.", Ipv4Addr::new(1, 1, 1, 1)),
                    a_record("ns-ns.example.net.", Ipv4Addr::new(1, 1, 1, 1)),
                    a_record("ns-an.example.net.", Ipv4Addr::new(3, 3, 3, 3)),
                    a_record("ns-ns.example.net.", Ipv4Addr::new(3, 3, 3, 3)),
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

    #[test]
    fn follow_cnames_empty() {
        assert_eq!(
            None,
            follow_cnames(&[], &domain("www.example.com."), &QueryType::Wildcard)
        );
    }

    #[test]
    fn follow_cnames_no_name_match() {
        assert_eq!(
            None,
            follow_cnames(
                &[a_record("www.example.net.", Ipv4Addr::new(1, 1, 1, 1))],
                &domain("www.example.com."),
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_no_type_match() {
        assert_eq!(
            None,
            follow_cnames(
                &[a_record("www.example.net.", Ipv4Addr::new(1, 1, 1, 1))],
                &domain("www.example.com."),
                &QueryType::Record(RecordType::NS)
            )
        );
    }

    #[test]
    fn follow_cnames_no_cname() {
        let rr_a = a_record("www.example.com.", Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            Some((domain("www.example.com."), HashMap::new())),
            follow_cnames(&[rr_a], &domain("www.example.com."), &QueryType::Wildcard)
        );
    }

    #[test]
    fn follow_cnames_chain() {
        let rr_cname1 = cname_record("www.example.com.", "www2.example.com.");
        let rr_cname2 = cname_record("www2.example.com.", "www3.example.com.");
        let rr_a = a_record("www3.example.com.", Ipv4Addr::new(127, 0, 0, 1));

        let mut expected_map = HashMap::new();
        expected_map.insert(domain("www.example.com."), domain("www2.example.com."));
        expected_map.insert(domain("www2.example.com."), domain("www3.example.com."));

        // order of records does not matter, so pick the "worst"
        // order: the records are in the opposite order to what we'd
        // expect
        assert_eq!(
            Some((domain("www3.example.com."), expected_map)),
            follow_cnames(
                &[rr_a, rr_cname2, rr_cname1],
                &domain("www.example.com."),
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn follow_cnames_loop() {
        let rr_cname1 = cname_record("www.example.com.", "bad.example.com.");
        let rr_cname2 = cname_record("bad.example.com.", "www.example.com.");

        assert_eq!(
            None,
            follow_cnames(
                &[rr_cname1, rr_cname2],
                &domain("www.example.com."),
                &QueryType::Wildcard
            )
        );
    }

    #[test]
    fn get_better_ns_names_no_match() {
        let rr_ns = ns_record("example.", "ns1.icann.org.");
        assert_eq!(
            None,
            get_better_ns_names(&[rr_ns], &domain("www.example.com."), 0)
        );
    }

    #[test]
    fn get_better_ns_names_no_better() {
        let rr_ns = ns_record("com.", "ns1.icann.org.");
        assert_eq!(
            None,
            get_better_ns_names(&[rr_ns], &domain("www.example.com."), 2)
        );
    }

    #[test]
    fn get_better_ns_names_better() {
        let rr_ns = ns_record("example.com.", "ns2.icann.org.");
        assert_eq!(
            Some((
                domain("example.com."),
                [domain("ns2.icann.org.")].into_iter().collect()
            )),
            get_better_ns_names(&[rr_ns], &domain("www.example.com."), 0)
        );
    }

    #[test]
    fn get_better_ns_names_better_better() {
        let rr_ns1 = ns_record("example.com.", "ns2.icann.org.");
        let rr_ns2 = ns_record("www.example.com.", "ns3.icann.org.");
        assert_eq!(
            Some((
                domain("www.example.com."),
                [domain("ns3.icann.org.")].into_iter().collect()
            )),
            get_better_ns_names(&[rr_ns1, rr_ns2], &domain("www.example.com."), 0)
        );
    }

    #[test]
    fn get_ip_no_match() {
        let a_rr = a_record("www.example.net.", Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(None, get_ip(&[a_rr], &domain("www.example.com.")));
    }

    #[test]
    fn get_ip_direct_match() {
        let a_rr = a_record("www.example.com.", Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            get_ip(&[a_rr], &domain("www.example.com."))
        );
    }

    #[test]
    fn get_ip_cname_match() {
        let cname_rr = cname_record("www.example.com.", "www.example.net.");
        let a_rr = a_record("www.example.net.", Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            get_ip(&[cname_rr, a_rr], &domain("www.example.com."))
        );
    }

    fn cache_with_nameservers(names: &[&str]) -> SharedCache {
        let cache = SharedCache::new();

        for name in names {
            cache.insert(&ns_record(name, "ns1.example.com."));
            cache.insert(&ns_record(name, "ns2.example.com."));
        }

        cache
    }
}
