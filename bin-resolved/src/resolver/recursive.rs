use async_recursion::async_recursion;
use rand::Rng;
use std::cmp::Ordering;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use dns_types::protocol::types::*;
use dns_types::zones::types::*;

use crate::net_util::{read_tcp_bytes, send_tcp_bytes, send_udp_bytes};

use super::cache::SharedCache;
use super::nonrecursive::resolve_nonrecursive;
use super::util::*;

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

    let mut candidate_delegation = None;
    let mut combined_rrs = Vec::new();

    match resolve_nonrecursive(zones, cache, question) {
        Some(Ok(NameserverResponse::Answer {
            rrs,
            authority_rrs,
            is_authoritative,
        })) => {
            if is_authoritative || question.qtype != QueryType::Wildcard {
                println!("[DEBUG] got response to current query (non-recursive)");
                return Some(
                    NameserverResponse::Answer {
                        rrs,
                        authority_rrs,
                        is_authoritative,
                    }
                    .into(),
                );
            } else {
                println!("[DEBUG] got non-authoritative response to current wildcard query - continuing (non-recursive)");
                combined_rrs = rrs;
            }
        }
        Some(Ok(NameserverResponse::Delegation { delegation, .. })) => {
            println!("[DEBUG] found better nameserver - restarting current query (non-recursive)");
            candidate_delegation = Some(delegation);
        }
        Some(Ok(NameserverResponse::CNAME { rrs, cname, .. })) => {
            let cname_question = Question {
                name: cname,
                qclass: question.qclass,
                qtype: question.qtype,
            };
            println!(
                "[DEBUG] current query is a CNAME - restarting with CNAME target (non-recursive)"
            );
            if let Some(resolved) = resolve_recursive_notimeout(zones, cache, &cname_question).await
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
        Some(Err(error)) => {
            println!("[DEBUG] got error response to current query (non-recursive)");
            return Some(error.into());
        }
        None => (),
    }

    if candidate_delegation.is_none() {
        candidate_delegation = candidate_nameservers(zones, cache, &question.name);
    }

    if let Some(mut candidates) = candidate_delegation {
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
                    Some(NameserverResponse::Answer { rrs, .. }) => {
                        for rr in &rrs {
                            cache.insert(rr);
                        }
                        println!("[DEBUG] got response to current query (recursive)");
                        prioritising_merge(&mut combined_rrs, rrs);
                        return Some(ResolvedRecord::NonAuthoritative { rrs: combined_rrs });
                    }
                    Some(NameserverResponse::Delegation { rrs, delegation }) => {
                        for rr in &rrs {
                            cache.insert(rr);
                        }
                        candidates = delegation;
                        println!("[DEBUG] found better nameserver - restarting current query (recursive)");
                        continue 'query_nameservers;
                    }
                    Some(NameserverResponse::CNAME { rrs, cname, .. }) => {
                        for rr in &rrs {
                            cache.insert(rr);
                        }
                        let cname_question = Question {
                            name: cname,
                            qclass: question.qclass,
                            qtype: question.qtype,
                        };
                        println!("[DEBUG] current query is a CNAME - restarting with CNAME target (recursive)");
                        if let Some(resolved) =
                            resolve_recursive_notimeout(zones, cache, &cname_question).await
                        {
                            prioritising_merge(&mut combined_rrs, rrs);
                            prioritising_merge(&mut combined_rrs, resolved.rrs());
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

/// Get the best nameservers by non-recursively looking them up for
/// the domain and all its superdomains, in order.  If no nameservers
/// are found, the root hints are returned.
///
/// This corresponds to step 2 of the standard resolver algorithm.
fn candidate_nameservers(
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

            if let Some(Ok(NameserverResponse::Answer { rrs, .. })) =
                resolve_nonrecursive(zones, cache, &ns_q)
            {
                for ns_rr in rrs {
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
async fn query_nameserver_udp(
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
async fn query_nameserver_tcp(
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
fn validate_nameserver_response(
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

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;

    use super::*;
    use crate::resolver::util::test_util::*;

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
            candidate_nameservers(&zones(), &cache_with_nameservers(&["com."]), &qdomain)
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
                &zones(),
                &cache_with_nameservers(&["com."]),
                &domain("net.")
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
            validate_nameserver_response(&request, response, 0)
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
            validate_nameserver_response(&request, response, 0)
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

        assert_eq!(None, validate_nameserver_response(&request, response, 0));
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
            validate_nameserver_response(&request, response, 0)
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
            validate_nameserver_response(&request, response, 0)
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

        match validate_nameserver_response(&request, response, 0) {
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
                response,
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
                    hostnames: vec![HostOrIP::Host(domain("ns-better.example.net."))],
                    name: domain("subdomain.example.com."),
                },
            }),
            validate_nameserver_response(&request, response1, 0)
        );

        assert_eq!(
            Some(NameserverResponse::Delegation {
                rrs: vec![ns_record(
                    "subdomain.example.com.",
                    "ns-better.example.net."
                )],
                delegation: Nameservers {
                    hostnames: vec![HostOrIP::Host(domain("ns-better.example.net."))],
                    name: domain("subdomain.example.com."),
                },
            }),
            validate_nameserver_response(&request, response2, 0)
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

        match validate_nameserver_response(&request, response, 0) {
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
            actual => panic!("Expected delegation, got {:?}", actual),
        }
    }

    #[test]
    fn validate_nameserver_response_returns_none_if_no_matching_records() {}

    fn cache_with_nameservers(names: &[&str]) -> SharedCache {
        let cache = SharedCache::new();

        for name in names {
            cache.insert(&ns_record(name, "ns1.example.com."));
            cache.insert(&ns_record(name, "ns2.example.com."));
        }

        cache
    }

    fn matching_nameserver_response() -> (Message, Message) {
        nameserver_response(
            "www.example.com.",
            &[a_record("www.example.com.", Ipv4Addr::new(1, 1, 1, 1))],
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
