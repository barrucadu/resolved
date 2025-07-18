use async_recursion::async_recursion;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::Instrument;

use dns_types::protocol::types::*;

use crate::context::Context;
use crate::local::{resolve_local, LocalResolutionResult};
use crate::util::nameserver::*;
use crate::util::types::*;

pub struct RecursiveContextInner {
    pub protocol_mode: ProtocolMode,
    pub upstream_dns_port: u16,
}

pub type RecursiveContext<'a> = Context<'a, RecursiveContextInner>;

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
pub async fn resolve_recursive<'a>(
    context: &mut RecursiveContext<'a>,
    question: &Question,
) -> Result<ResolvedRecord, ResolutionError> {
    if let Ok(res) = timeout(
        Duration::from_secs(60),
        resolve_recursive_notimeout(context, question),
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
async fn resolve_recursive_notimeout<'a>(
    context: &mut RecursiveContext<'a>,
    question: &Question,
) -> Result<ResolvedRecord, ResolutionError> {
    if context.at_recursion_limit() {
        tracing::debug!("hit recursion limit");
        return Err(ResolutionError::RecursionLimit);
    }
    if context.is_duplicate_question(question) {
        tracing::debug!("hit duplicate question");
        return Err(ResolutionError::DuplicateQuestion {
            question: question.clone(),
        });
    }

    let mut candidates = None;
    let mut combined_rrs = Vec::new();

    match resolve_local(context, question) {
        Ok(LocalResolutionResult::Done { resolved }) => return Ok(resolved),
        Ok(LocalResolutionResult::Partial { rrs }) => combined_rrs = rrs,
        Ok(LocalResolutionResult::Delegation { delegation, .. }) => candidates = Some(delegation),
        Ok(LocalResolutionResult::CNAME {
            rrs,
            cname_question,
            ..
        }) => {
            context.push_question(question);
            let answer = resolve_combined_recursive(context, rrs, cname_question).await;
            context.pop_question();
            return answer;
        }
        Err(_) => (),
    }

    context.push_question(question);

    if candidates.is_none() {
        candidates = candidate_nameservers(context, &question.name);
    }

    if let Some(candidates) = candidates {
        let mut match_count = candidates.match_count();
        let mut candidate_hostnames = candidates.hostnames;
        let mut next_candidate_hostnames = Vec::with_capacity(candidate_hostnames.len());
        let mut resolve_candidates_locally = true;

        while let Some(candidate) = candidate_hostnames.pop() {
            tracing::trace!(?candidate, "got candidate nameserver");
            if let Some(ip) =
                resolve_hostname_to_ip(context, resolve_candidates_locally, candidate.clone()).await
            {
                if let Some(nameserver_response) = query_nameserver(
                    (ip, context.r.upstream_dns_port).into(),
                    question.clone(),
                    false,
                )
                .instrument(tracing::error_span!("query_nameserver", address = %ip, %match_count))
                .await
                .and_then(|res| validate_nameserver_response(question, &res, match_count))
                {
                    if resolve_candidates_locally {
                        tracing::trace!(?candidate, "resolved fast candidate");
                    } else {
                        tracing::trace!(?candidate, "resolved slow candidate");
                    }
                    context.metrics().nameserver_hit();
                    match resolve_with_nameserver_response(
                        context,
                        combined_rrs.clone(),
                        nameserver_response,
                        question,
                    )
                    .await
                    {
                        Ok(result) => {
                            context.pop_question();
                            return result;
                        }
                        Err(delegation) => {
                            match_count = delegation.match_count();
                            candidate_hostnames = delegation.hostnames;
                            next_candidate_hostnames =
                                Vec::with_capacity(candidate_hostnames.len());
                            resolve_candidates_locally = true;
                        }
                    }
                } else {
                    context.metrics().nameserver_miss();
                    // TODO: should distinguish between timeouts and other
                    // failures here, and try the next nameserver after a
                    // timeout.
                    context.pop_question();
                    return Err(ResolutionError::DeadEnd {
                        question: question.clone(),
                    });
                }
            } else if resolve_candidates_locally {
                tracing::trace!(?candidate, "skipping slow candidate");
                next_candidate_hostnames.push(candidate.clone());
                // try slow candidates if out of fast ones
                if candidate_hostnames.is_empty() {
                    tracing::trace!("restarting with slow candidates");
                    candidate_hostnames = next_candidate_hostnames;
                    next_candidate_hostnames = Vec::new();
                    resolve_candidates_locally = false;
                }
            } else {
                // failed to resolve the candidate recursively, just drop it.
                tracing::trace!(?candidate, "dropping unresolvable candidate");
            }
        }
    }

    tracing::trace!("out of candidates");
    context.pop_question();
    Err(ResolutionError::DeadEnd {
        question: question.clone(),
    })
}

/// Helper function for answering a question given a response from an upstream
/// nameserver: this will only do further querying if the response is a CNAME.
#[async_recursion]
async fn resolve_with_nameserver_response<'a>(
    context: &mut RecursiveContext<'a>,
    mut combined_rrs: Vec<ResourceRecord>,
    nameserver_response: NameserverResponse,
    question: &Question,
) -> Result<Result<ResolvedRecord, ResolutionError>, Nameservers> {
    match nameserver_response {
        NameserverResponse::Answer { rrs, soa_rr, .. } => {
            tracing::trace!("got recursive answer");
            context.cache.insert_all(&rrs);
            prioritising_merge(&mut combined_rrs, rrs);
            Ok(Ok(ResolvedRecord::NonAuthoritative {
                rrs: combined_rrs,
                soa_rr,
            }))
        }
        NameserverResponse::Delegation {
            rrs, delegation, ..
        } => {
            context.cache.insert_all(&rrs);
            if question.qtype == QueryType::Record(RecordType::A) {
                if let Some(rr) = get_record(&rrs, &question.name, RecordType::A) {
                    tracing::trace!("got recursive delegation - using glue A record");
                    prioritising_merge(&mut combined_rrs, vec![rr.clone()]);
                    return Ok(Ok(ResolvedRecord::NonAuthoritative {
                        rrs: combined_rrs,
                        soa_rr: None,
                    }));
                }
            } else if question.qtype == QueryType::Record(RecordType::AAAA) {
                if let Some(rr) = get_record(&rrs, &question.name, RecordType::AAAA) {
                    tracing::trace!("got recursive delegation - using glue AAAA record");
                    prioritising_merge(&mut combined_rrs, vec![rr.clone()]);
                    return Ok(Ok(ResolvedRecord::NonAuthoritative {
                        rrs: combined_rrs,
                        soa_rr: None,
                    }));
                }
            }
            tracing::trace!("got recursive delegation - using as candidate");
            Err(delegation)
        }
        NameserverResponse::CNAME { rrs, cname, .. } => {
            tracing::trace!("got recursive CNAME");
            context.cache.insert_all(&rrs);
            prioritising_merge(&mut combined_rrs, rrs);
            let cname_question = Question {
                name: cname,
                qclass: question.qclass,
                qtype: question.qtype,
            };
            let cname_answer =
                resolve_combined_recursive(context, combined_rrs, cname_question).await;
            Ok(cname_answer)
        }
    }
}

/// Helper function for resolving CNAMEs: resolve, and add some existing RRs to
/// the ANSWER section of the result.
async fn resolve_combined_recursive<'a>(
    context: &mut RecursiveContext<'a>,
    mut rrs: Vec<ResourceRecord>,
    question: Question,
) -> Result<ResolvedRecord, ResolutionError> {
    match resolve_recursive_notimeout(context, &question)
        .instrument(tracing::error_span!("resolve_combined_recursive", %question))
        .await
    {
        Ok(resolved) => {
            let soa_rr = resolved.soa_rr().cloned();
            rrs.append(&mut resolved.rrs());
            Ok(ResolvedRecord::NonAuthoritative { rrs, soa_rr })
        }
        Err(_) => Err(ResolutionError::DeadEnd { question }),
    }
}

/// Resolve a hostname into an IP address, optionally only doing local
/// resolution.
async fn resolve_hostname_to_ip<'a>(
    context: &mut RecursiveContext<'a>,
    resolve_locally: bool,
    hostname: DomainName,
) -> Option<IpAddr> {
    let rtypes = match context.r.protocol_mode {
        ProtocolMode::OnlyV4 => vec![RecordType::A],
        ProtocolMode::PreferV4 => vec![RecordType::A, RecordType::AAAA],
        ProtocolMode::PreferV6 => vec![RecordType::AAAA, RecordType::A],
        ProtocolMode::OnlyV6 => vec![RecordType::AAAA],
    };

    let mut question = Question {
        name: hostname,
        qclass: QueryClass::Record(RecordClass::IN),
        // immediately replaced in the loop
        qtype: QueryType::AXFR,
    };
    for rtype in rtypes {
        question.qtype = QueryType::Record(rtype);
        if resolve_locally {
            if let Ok(LocalResolutionResult::Done { resolved }) = resolve_local(context, &question)
            {
                let address = get_ip(&resolved.rrs(), &question.name, rtype);
                if address.is_some() {
                    return address;
                }
            }
        } else if let Ok(result) = resolve_recursive_notimeout(context, &question).await {
            let address = get_ip(&result.rrs(), &question.name, rtype);
            if address.is_some() {
                return address;
            }
        }
    }

    None
}

/// Get the best nameservers by non-recursively looking them up for
/// the domain and all its superdomains, in order.  If no nameservers
/// are found, the root hints are returned.
///
/// This corresponds to step 2 of the standard resolver algorithm.
fn candidate_nameservers(
    context: &mut RecursiveContext<'_>,
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

            if let Ok(LocalResolutionResult::Done { resolved }) = resolve_local(context, &ns_q) {
                for ns_rr in resolved.rrs() {
                    if let RecordTypeWithData::NS { nsdname } = &ns_rr.rtype_with_data {
                        hostnames.push(nsdname.clone());
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

/// Validate a nameserver response against the question by only keeping valid
/// RRs:
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
    question: &Question,
    response: &Message,
    current_match_count: usize,
) -> Option<NameserverResponse> {
    if let Some((final_name, cname_map)) =
        follow_cnames(&response.answers, &question.name, question.qtype)
    {
        // get RRs matching the query name or the names it `CNAME`s to

        let mut rrs_for_query = Vec::<ResourceRecord>::with_capacity(response.answers.len());
        let mut seen_final_record = false;
        let mut all_unknown = true;
        for an in &response.answers {
            if an.is_unknown() {
                continue;
            }

            let rtype = an.rtype_with_data.rtype();
            all_unknown = false;

            if rtype.matches(question.qtype) && an.name == final_name {
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
            // what sort of answer is this?
            if seen_final_record {
                Some(NameserverResponse::Answer {
                    rrs: rrs_for_query,
                    soa_rr: None,
                })
            } else {
                Some(NameserverResponse::CNAME {
                    rrs: rrs_for_query,
                    cname: final_name,
                })
            }
        }
    } else {
        // get NS RRs and their associated A RRs.
        //
        // NOTE: `NS` RRs may be in the ANSWER *or* AUTHORITY sections.

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
                (None, None) => {
                    // No records and no delegation - check if this is an
                    // NXDOMAIN / NODATA response and if so propagate the SOA RR
                    return get_nxdomain_nodata_soa(question, response, current_match_count).map(
                        |soa_rr| NameserverResponse::Answer {
                            rrs: Vec::new(),
                            soa_rr: Some(soa_rr).cloned(),
                        },
                    );
                }
            }
        };

        // you never know, the upstream nameserver may have been kind enough to
        // give an A record along with each NS record, if we're lucky.
        let mut nameserver_rrs = Vec::<ResourceRecord>::with_capacity(ns_names.len() * 2);
        for rr in &response.answers {
            match &rr.rtype_with_data {
                RecordTypeWithData::NS { nsdname } if ns_names.contains(nsdname) => {
                    nameserver_rrs.push(rr.clone());
                }
                RecordTypeWithData::A { .. } if ns_names.contains(&rr.name) => {
                    nameserver_rrs.push(rr.clone());
                }
                RecordTypeWithData::AAAA { .. } if ns_names.contains(&rr.name) => {
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
                RecordTypeWithData::AAAA { .. } if ns_names.contains(&rr.name) => {
                    nameserver_rrs.push(rr.clone());
                }
                _ => (),
            }
        }

        // this is a delegation
        Some(NameserverResponse::Delegation {
            rrs: nameserver_rrs,
            delegation: Nameservers {
                hostnames: ns_names.into_iter().collect(),
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
fn follow_cnames(
    rrs: &[ResourceRecord],
    target: &DomainName,
    qtype: QueryType,
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
fn get_better_ns_names(
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
/// `CNAME`s in the response and get the address from the final `A` / `AAAA`
/// record.
fn get_ip(rrs: &[ResourceRecord], target: &DomainName, rtype: RecordType) -> Option<IpAddr> {
    if let Some((final_name, _)) = follow_cnames(rrs, target, QueryType::Wildcard) {
        if let Some(rr) = get_record(rrs, &final_name, rtype) {
            match rr.rtype_with_data {
                RecordTypeWithData::A { address } => Some(IpAddr::V4(address)),
                RecordTypeWithData::AAAA { address } => Some(IpAddr::V6(address)),
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    }
}

/// Given a set of RRs and a domain we're looking for, return the record we're
/// looking for (if any).
///
/// Unlike `get_ip` this does not follow `CNAME`s.
fn get_record<'a>(
    rrs: &'a [ResourceRecord],
    target: &DomainName,
    rtype: RecordType,
) -> Option<&'a ResourceRecord> {
    rrs.iter()
        .find(|&rr| rr.rtype_with_data.rtype() == rtype && rr.name == *target)
}

/// A response from a remote nameserver
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NameserverResponse {
    Answer {
        rrs: Vec<ResourceRecord>,
        soa_rr: Option<ResourceRecord>,
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use dns_types::protocol::types::test_util::*;
    use dns_types::zones::types::*;

    use super::*;
    use crate::cache::SharedCache;
    use crate::util::nameserver::test_util::*;

    #[test]
    fn candidate_nameservers_gets_all_matches() {
        let qdomain = domain("com.");
        assert_eq!(
            Some(Nameservers {
                hostnames: vec![domain("ns1.example.com."), domain("ns2.example.com.")],
                name: qdomain.clone(),
            }),
            candidate_nameservers(
                &mut Context::new(
                    RecursiveContextInner {
                        protocol_mode: ProtocolMode::PreferV4,
                        upstream_dns_port: 53,
                    },
                    &Zones::new(),
                    &cache_with_nameservers(&["com."]),
                    10,
                ),
                &qdomain
            )
        );
    }

    #[test]
    fn candidate_nameservers_returns_longest_match() {
        assert_eq!(
            Some(Nameservers {
                hostnames: vec![domain("ns1.example.com."), domain("ns2.example.com.")],
                name: domain("example.com."),
            }),
            candidate_nameservers(
                &mut Context::new(
                    RecursiveContextInner {
                        protocol_mode: ProtocolMode::PreferV4,
                        upstream_dns_port: 53,
                    },
                    &Zones::new(),
                    &cache_with_nameservers(&["example.com.", "com."]),
                    10,
                ),
                &domain("www.example.com.")
            )
        );
    }

    #[test]
    fn candidate_nameservers_returns_none_on_failure() {
        assert_eq!(
            None,
            candidate_nameservers(
                &mut Context::new(
                    RecursiveContextInner {
                        protocol_mode: ProtocolMode::PreferV4,
                        upstream_dns_port: 53,
                    },
                    &Zones::new(),
                    &cache_with_nameservers(&["com."]),
                    10,
                ),
                &domain("net.")
            )
        );
    }

    #[test]
    fn validate_nameserver_response_returns_answer() {
        let (request, response) = nameserver_response(
            "www.example.com.",
            &[a_record("www.example.com.", Ipv4Addr::LOCALHOST)],
            &[],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::Answer {
                rrs: vec![a_record("www.example.com.", Ipv4Addr::LOCALHOST)],
                soa_rr: None,
            }),
            validate_nameserver_response(&request.questions[0], &response, 0)
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
                soa_rr: None,
            }),
            validate_nameserver_response(&request.questions[0], &response, 0)
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

        assert_eq!(
            None,
            validate_nameserver_response(&request.questions[0], &response, 0)
        );
    }

    #[test]
    fn validate_nameserver_response_follows_cnames() {
        let (request, response) = nameserver_response(
            "www.example.com.",
            &[
                cname_record("www.example.com.", "cname-target.example.com."),
                a_record("cname-target.example.com.", Ipv4Addr::LOCALHOST),
            ],
            &[],
            &[],
        );

        assert_eq!(
            Some(NameserverResponse::Answer {
                rrs: vec![
                    cname_record("www.example.com.", "cname-target.example.com."),
                    a_record("cname-target.example.com.", Ipv4Addr::LOCALHOST)
                ],
                soa_rr: None,
            }),
            validate_nameserver_response(&request.questions[0], &response, 0)
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
            }),
            validate_nameserver_response(&request.questions[0], &response, 0)
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

        match validate_nameserver_response(&request.questions[0], &response, 0) {
            Some(NameserverResponse::Delegation {
                rrs: mut actual_rrs,
                delegation: mut actual_delegation,
            }) => {
                let mut expected_rrs = vec![
                    ns_record("example.com.", "ns-an.example.net."),
                    ns_record("example.com.", "ns-ns.example.net."),
                ];

                expected_rrs.sort();
                actual_rrs.sort();

                assert_eq!(expected_rrs, actual_rrs);

                let mut expected_delegation = Nameservers {
                    hostnames: vec![domain("ns-an.example.net."), domain("ns-ns.example.net.")],
                    name: domain("example.com."),
                };

                expected_delegation.hostnames.sort();
                actual_delegation.hostnames.sort();

                assert_eq!(expected_delegation, actual_delegation);
            }
            actual => panic!("Expected delegation, got {actual:?}"),
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
                &request.questions[0],
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
                delegation: Nameservers {
                    hostnames: vec![domain("ns-better.example.net.")],
                    name: domain("subdomain.example.com."),
                },
            }),
            validate_nameserver_response(&request.questions[0], &response1, 0)
        );

        assert_eq!(
            Some(NameserverResponse::Delegation {
                rrs: vec![ns_record(
                    "subdomain.example.com.",
                    "ns-better.example.net."
                )],
                delegation: Nameservers {
                    hostnames: vec![domain("ns-better.example.net.")],
                    name: domain("subdomain.example.com."),
                },
            }),
            validate_nameserver_response(&request.questions[0], &response2, 0)
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

        match validate_nameserver_response(&request.questions[0], &response, 0) {
            Some(NameserverResponse::Delegation {
                rrs: mut actual_rrs,
                delegation: _,
            }) => {
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
            actual => panic!("Expected delegation, got {actual:?}"),
        }
    }

    #[test]
    fn validate_nameserver_response_propagates_nodata() {
        let soa_record = ResourceRecord {
            name: domain("com."),
            rtype_with_data: RecordTypeWithData::SOA {
                mname: domain("mname."),
                rname: domain("rname."),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            },
            rclass: RecordClass::IN,
            ttl: 300,
        };

        let (request, response) = nameserver_response(
            "www.example.com.",
            &[],
            std::slice::from_ref(&soa_record),
            &[],
        );

        assert_eq!(
            validate_nameserver_response(&request.questions[0], &response, 0),
            Some(NameserverResponse::Answer {
                rrs: Vec::new(),
                soa_rr: Some(soa_record)
            }),
        );
    }

    #[test]
    fn validate_nameserver_response_rejects_nodata_if_soa_too_generic() {
        let soa_record = ResourceRecord {
            name: domain("com."),
            rtype_with_data: RecordTypeWithData::SOA {
                mname: domain("mname."),
                rname: domain("rname."),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            },
            rclass: RecordClass::IN,
            ttl: 300,
        };

        let (request, response) = nameserver_response("www.example.com.", &[], &[soa_record], &[]);

        // pretend we're querying the nameserver for example.com
        let current_match_count = domain("example.com.").labels.len();

        assert_eq!(
            validate_nameserver_response(&request.questions[0], &response, current_match_count),
            None,
        );
    }

    #[test]
    fn validate_nameserver_response_rejects_nodata_if_soa_too_specific() {
        let soa_record = ResourceRecord {
            name: domain("foo.example.com."),
            rtype_with_data: RecordTypeWithData::SOA {
                mname: domain("mname."),
                rname: domain("rname."),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            },
            rclass: RecordClass::IN,
            ttl: 300,
        };

        let (request, response) = nameserver_response("www.example.com.", &[], &[soa_record], &[]);

        assert_eq!(
            validate_nameserver_response(&request.questions[0], &response, 0),
            None,
        );
    }

    #[test]
    fn follow_cnames_empty() {
        assert_eq!(
            None,
            follow_cnames(&[], &domain("www.example.com."), QueryType::Wildcard)
        );
    }

    #[test]
    fn follow_cnames_no_name_match() {
        assert_eq!(
            None,
            follow_cnames(
                &[a_record("www.example.net.", Ipv4Addr::new(1, 1, 1, 1))],
                &domain("www.example.com."),
                QueryType::Wildcard
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
                QueryType::Record(RecordType::NS)
            )
        );
    }

    #[test]
    fn follow_cnames_no_cname() {
        let rr_a = a_record("www.example.com.", Ipv4Addr::LOCALHOST);
        assert_eq!(
            Some((domain("www.example.com."), HashMap::new())),
            follow_cnames(&[rr_a], &domain("www.example.com."), QueryType::Wildcard)
        );
    }

    #[test]
    fn follow_cnames_chain() {
        let rr_cname1 = cname_record("www.example.com.", "www2.example.com.");
        let rr_cname2 = cname_record("www2.example.com.", "www3.example.com.");
        let rr_a = a_record("www3.example.com.", Ipv4Addr::LOCALHOST);

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
                QueryType::Wildcard
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
                QueryType::Wildcard
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
    fn get_ip_domain_mismatch() {
        let a_rr = a_record("www.example.net.", Ipv4Addr::LOCALHOST);
        assert_eq!(
            None,
            get_ip(&[a_rr], &domain("www.example.com."), RecordType::A)
        );
    }

    #[test]
    fn get_ip_type_mismatch() {
        let aaaa_rr = aaaa_record("www.example.com.", Ipv6Addr::LOCALHOST);
        assert_eq!(
            None,
            get_ip(&[aaaa_rr], &domain("www.example.com."), RecordType::A,)
        );
    }

    #[test]
    fn get_ip_domain_and_type_match() {
        let a_rr = a_record("www.example.com.", Ipv4Addr::LOCALHOST);
        let aaaa_rr = aaaa_record("www.example.com.", Ipv6Addr::LOCALHOST);
        let rrs = [a_rr, aaaa_rr];
        assert_eq!(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            get_ip(&rrs, &domain("www.example.com."), RecordType::A)
        );
        assert_eq!(
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            get_ip(&rrs, &domain("www.example.com."), RecordType::AAAA)
        );
    }

    #[test]
    fn get_ip_cname_match() {
        let cname_rr = cname_record("www.example.com.", "www.example.net.");
        let a_rr = a_record("www.example.net.", Ipv4Addr::LOCALHOST);
        assert_eq!(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            get_ip(
                &[cname_rr, a_rr],
                &domain("www.example.com."),
                RecordType::A,
            )
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
