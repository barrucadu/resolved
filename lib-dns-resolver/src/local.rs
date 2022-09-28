use tracing;

use dns_types::protocol::types::*;
use dns_types::zones::types::*;

use crate::cache::SharedCache;
use crate::metrics::Metrics;
use crate::util::types::*;

/// Query type for CNAMEs - used for cache lookups.
const CNAME_QTYPE: QueryType = QueryType::Record(RecordType::CNAME);

/// Local DNS resolution.
///
/// This acts like a pseudo-nameserver, returning a `NameserverResponse` which
/// is either consumed by another resolver, or converted directly into a
/// `ResolvedRecord` to return to the client.
///
/// This corresponds to steps 2, 3, and 4 of the standard nameserver algorithm:
///
/// - check if there is a zone which matches the QNAME
///
/// - search through it for a match (either an answer, a CNAME, or a delegation)
///
/// - search through the cache if we didn't get an authoritative match
///
/// This function gives up if the CNAMEs form a cycle.
///
/// See section 4.3.2 of RFC 1034.
///
/// # Errors
///
/// See `ResolutionError`.
pub fn resolve_local(
    recursion_limit: usize,
    metrics: &mut Metrics,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Result<Result<NameserverResponse, AuthoritativeNameError>, ResolutionError> {
    let _span = tracing::error_span!("resolve_local", %question).entered();

    if recursion_limit == 0 {
        tracing::debug!("hit recursion limit");
        return Err(ResolutionError::RecursionLimit);
    }

    let mut rrs_from_zone = Vec::new();

    if let Some(zone) = zones.get(&question.name) {
        let _zone_span = tracing::error_span!("zone", apex = %zone.get_apex().to_dotted_string(), is_authoritative = %zone.is_authoritative()).entered();

        // `zone.resolve` implements the non-recursive part of step 3 of the
        // standard resolver algorithm: matching down through the zone and
        // returning what sort of end state is reached.
        match zone.resolve(&question.name, question.qtype) {
            // If we get an answer:
            //
            // - if the zone is authoritative: we're done.
            //
            // - if the zone is not authoritative: check if this is a wildcard
            // query or not:
            //
            //    - if it's not a wildcard query, return these results as a
            //    non-authoritative answer (non-authoritative zone records
            //    effectively override the wider domain name system).
            //
            //    - if it is a wildcard query, save these results and continue
            //    to the cache (handled below), and use a prioritising merge to
            //    combine the RR sets, preserving the override behaviour.
            Some(ZoneResult::Answer { rrs }) => {
                tracing::trace!("got answer");
                metrics.zoneresult_answer(&rrs, zone, question);

                if let Some(soa_rr) = zone.soa_rr() {
                    return Ok(Ok(NameserverResponse::Answer {
                        rrs,
                        is_authoritative: true,
                        authority_rrs: vec![soa_rr],
                    }));
                } else if question.qtype != QueryType::Wildcard && !rrs.is_empty() {
                    return Ok(Ok(NameserverResponse::Answer {
                        rrs,
                        is_authoritative: false,
                        authority_rrs: Vec::new(),
                    }));
                }
                rrs_from_zone = rrs;
            }
            // If the name is a CNAME, try resolving it, then:
            //
            // - if resolving it only touches authoritative zones: return the
            // response, which is authoritative if and only if this starting
            // zone is authoritative, without consulting the cache for
            // additional records.
            //
            // - if resolving it touches non-authoritative zones or the cache:
            // return the response, which is not authoritative.
            //
            // - if resolving it fails: return the response, which is
            // authoritative if and only if this starting zone is authoritative.
            Some(ZoneResult::CNAME { cname, rr }) => {
                tracing::trace!("got cname");
                metrics.zoneresult_cname(zone);

                let mut rrs = vec![rr];
                return Ok(Ok(
                    match resolve_local(
                        recursion_limit - 1,
                        metrics,
                        zones,
                        cache,
                        &Question {
                            name: cname.clone(),
                            qtype: question.qtype,
                            qclass: question.qclass,
                        },
                    ) {
                        Ok(Ok(NameserverResponse::Answer {
                            rrs: mut cname_rrs,
                            is_authoritative,
                            ..
                        })) => {
                            rrs.append(&mut cname_rrs);

                            NameserverResponse::Answer {
                                rrs,
                                is_authoritative: is_authoritative && zone.is_authoritative(),
                                authority_rrs: Vec::new(),
                            }
                        }
                        Ok(Ok(NameserverResponse::CNAME {
                            rrs: mut cname_rrs,
                            cname,
                            is_authoritative,
                            ..
                        })) => {
                            rrs.append(&mut cname_rrs);

                            NameserverResponse::CNAME {
                                rrs,
                                cname,
                                is_authoritative: is_authoritative && zone.is_authoritative(),
                            }
                        }
                        _ => NameserverResponse::CNAME {
                            rrs,
                            cname,
                            is_authoritative: zone.is_authoritative(),
                        },
                    },
                ));
            }
            // If the name is delegated:
            //
            // - if this zone is authoritative, return the response with the NS
            // RRs in the AUTHORITY section.
            //
            // - otherwise ignore and proceed to cache.
            Some(ZoneResult::Delegation { ns_rrs }) => {
                tracing::trace!("got delegation");
                metrics.zoneresult_delegation(zone);

                if let Some(soa_rr) = zone.soa_rr() {
                    if ns_rrs.is_empty() {
                        tracing::warn!("got empty RRset from delegation");
                        return Err(ResolutionError::LocalDelegationMissingNS {
                            apex: zone.get_apex().clone(),
                            domain: question.name.clone(),
                        });
                    }

                    let name = ns_rrs[0].name.clone();
                    let mut hostnames = Vec::with_capacity(ns_rrs.len());
                    for rr in &ns_rrs {
                        if let RecordTypeWithData::NS { nsdname } = &rr.rtype_with_data {
                            hostnames.push(HostOrIP::Host(nsdname.clone()));
                        } else {
                            tracing::warn!(rtype = %rr.rtype_with_data.rtype(), "got non-NS RR in a delegation");
                        }
                    }

                    return Ok(Ok(NameserverResponse::Delegation {
                        delegation: Nameservers { hostnames, name },
                        rrs: ns_rrs,
                        is_authoritative: true,
                        authority_rrs: vec![soa_rr],
                    }));
                }
            }
            // If the name could not be resolved:
            //
            // - if this zone is authoritative, a NXDOMAIN response
            // (todo)
            //
            // - otherwise ignore and proceed to cache.
            Some(ZoneResult::NameError) => {
                tracing::trace!("got name error");
                metrics.zoneresult_nameerror(zone);

                if let Some(soa_rr) = zone.soa_rr() {
                    return Ok(Err(AuthoritativeNameError { soa_rr }));
                }
            }
            // This shouldn't happen
            None => {
                tracing::warn!("zone apex / domain mismatch");
                return Err(ResolutionError::ZoneApexDomainMismatch {
                    apex: zone.get_apex().clone(),
                    domain: question.name.clone(),
                });
            }
        }
    }

    // If we get here, either:
    //
    // - there is no zone for this question (in practice this will be unlikely,
    // as the root hints get put into a non-authoritative root zone - and
    // without root hints, we can't do much)
    //
    // - the query was answered by a non-authoritative zone, which means we may
    // have other relevant RRs in the cache
    //
    // - the query could not be answered, because the non-authoritative zone
    // responsible for the name either doesn't contain the name, or only has NS
    // records (and the query is not for NS records - if it were, that would be
    // a non-authoritative answer).
    //
    // In all cases, consult the cache for an answer to the question, and
    // combine with the RRs we already have.

    let mut rrs_from_cache = cache.get(&question.name, &question.qtype);
    if rrs_from_cache.is_empty() {
        tracing::trace!(qtype = %question.qtype, "cache MISS");
        metrics.cache_miss();
    } else {
        tracing::trace!(qtype = %question.qtype, "cache HIT");
        metrics.cache_hit();
    }

    let mut final_cname = None;
    if rrs_from_cache.is_empty() && question.qtype != CNAME_QTYPE {
        let cache_cname_rrs = cache.get(&question.name, &CNAME_QTYPE);
        if cache_cname_rrs.is_empty() {
            tracing::trace!(qtype = %CNAME_QTYPE, "cache MISS");
            metrics.cache_miss();
        } else {
            tracing::trace!(qtype = %CNAME_QTYPE, "cache HIT");
            metrics.cache_hit();
        }

        if !cache_cname_rrs.is_empty() {
            let cname_rr = cache_cname_rrs[0].clone();
            rrs_from_cache = vec![cname_rr.clone()];

            if let RecordTypeWithData::CNAME { cname } = cname_rr.rtype_with_data {
                let resolved_cname = resolve_local(
                    recursion_limit - 1,
                    metrics,
                    zones,
                    cache,
                    &Question {
                        name: cname.clone(),
                        qtype: question.qtype,
                        qclass: question.qclass,
                    },
                );
                match resolved_cname {
                    Ok(Ok(NameserverResponse::Answer { mut rrs, .. })) => {
                        rrs_from_cache.append(&mut rrs);
                    }
                    Ok(Ok(NameserverResponse::CNAME { mut rrs, cname, .. })) => {
                        rrs_from_cache.append(&mut rrs);
                        final_cname = Some(cname);
                    }
                    _ => {
                        final_cname = Some(cname);
                    }
                }
            } else {
                tracing::warn!(rtype = %cname_rr.rtype_with_data.rtype(), "got non-CNAME RR from cache");
                return Err(ResolutionError::CacheTypeMismatch {
                    query: CNAME_QTYPE,
                    result: cname_rr.rtype_with_data.rtype(),
                });
            };
        }
    }

    let mut rrs = rrs_from_zone;
    prioritising_merge(&mut rrs, rrs_from_cache);

    if rrs.is_empty() {
        Err(ResolutionError::DeadEnd {
            question: question.clone(),
        })
    } else if let Some(cname) = final_cname {
        Ok(Ok(NameserverResponse::CNAME {
            rrs,
            cname,
            is_authoritative: false,
        }))
    } else {
        Ok(Ok(NameserverResponse::Answer {
            rrs,
            is_authoritative: false,
            authority_rrs: Vec::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::cache::test_util::*;
    use crate::util::test_util::*;

    #[test]
    fn resolve_local_is_authoritative_for_zones_with_soa() {
        let soa_rr = zones_soa_rr();
        let mut expected = vec![
            a_record("authoritative.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
            soa_rr.clone(),
        ];
        expected.sort();

        if let Ok(Ok(NameserverResponse::Answer {
            mut rrs,
            authority_rrs,
            is_authoritative: true,
        })) = resolve_local(
            10,
            &mut Metrics::new(),
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("authoritative.example.com."),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            rrs.sort();

            assert_eq!(vec![soa_rr], authority_rrs);
            assert_eq!(expected, rrs);
        } else {
            panic!("expected authoritative answer");
        }
    }

    #[test]
    fn resolve_local_is_nonauthoritative_for_zones_without_soa() {
        if let Ok(Ok(NameserverResponse::Answer {
            rrs,
            is_authoritative: false,
            ..
        })) = resolve_local(
            10,
            &mut Metrics::new(),
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("a.example.com."),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_eq!(
                vec![a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1))],
                rrs
            );
        } else {
            panic!("expected non-authoritative answer");
        }
    }

    #[test]
    fn resolve_local_is_nonauthoritative_for_cache() {
        let rr = a_record("cached.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&rr);

        if let Ok(Ok(NameserverResponse::Answer {
            rrs,
            is_authoritative: false,
            ..
        })) = resolve_local(
            10,
            &mut Metrics::new(),
            &zones(),
            &cache,
            &Question {
                name: domain("cached.example.com."),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_cache_response(&rr, &rrs);
        } else {
            panic!("expected non-authoritative answer");
        }
    }

    #[test]
    fn resolve_local_prefers_authoritative_zones() {
        let soa_rr = zones_soa_rr();
        let mut expected = vec![
            a_record("authoritative.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
            soa_rr.clone(),
        ];
        expected.sort();

        let cache = SharedCache::new();
        cache.insert(&a_record(
            "authoritative.example.com.",
            Ipv4Addr::new(8, 8, 8, 8),
        ));

        if let Ok(Ok(NameserverResponse::Answer {
            mut rrs,
            authority_rrs,
            is_authoritative: true,
        })) = resolve_local(
            10,
            &mut Metrics::new(),
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("authoritative.example.com."),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            rrs.sort();

            assert_eq!(vec![soa_rr], authority_rrs);
            assert_eq!(expected, rrs);
        } else {
            panic!("expected authoritative answer");
        }
    }

    #[test]
    fn resolve_local_combines_nonauthoritative_zones_with_cache() {
        let zone_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));
        let cache_rr_dropped = a_record("a.example.com.", Ipv4Addr::new(8, 8, 8, 8));
        let cache_rr_kept = cname_record("a.example.com.", "b.example.com.");

        let cache = SharedCache::new();
        cache.insert(&cache_rr_dropped);
        cache.insert(&cache_rr_kept);

        if let Ok(Ok(NameserverResponse::Answer {
            rrs,
            is_authoritative: false,
            ..
        })) = resolve_local(
            10,
            &mut Metrics::new(),
            &zones(),
            &cache,
            &Question {
                name: domain("a.example.com."),
                qtype: QueryType::Wildcard,
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_eq!(2, rrs.len());
            assert_eq!(zone_rr, rrs[0]);
            assert_cache_response(&cache_rr_kept, &[rrs[1].clone()]);
        } else {
            panic!("expected non-authoritative answer");
        }
    }

    #[test]
    fn resolve_local_expands_cnames_from_zone() {
        let cname_rr = cname_record(
            "cname-a.authoritative.example.com.",
            "authoritative.example.com.",
        );
        let a_rr = a_record("authoritative.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        if let Ok(Ok(NameserverResponse::Answer {
            rrs,
            authority_rrs,
            is_authoritative: true,
        })) = resolve_local(
            10,
            &mut Metrics::new(),
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("cname-a.authoritative.example.com."),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert!(authority_rrs.is_empty());
            assert_eq!(2, rrs.len());
            assert_cache_response(&cname_rr, &[rrs[0].clone()]);
            assert_cache_response(&a_rr, &[rrs[1].clone()]);
        } else {
            panic!("expected authoritative answer");
        }
    }

    #[test]
    fn resolve_local_expands_cnames_from_cache() {
        let cname_rr1 = cname_record("cname-1.example.com.", "cname-2.example.com.");
        let cname_rr2 = cname_record("cname-2.example.com.", "a.example.com.");
        let a_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&cname_rr1);
        cache.insert(&cname_rr2);

        if let Ok(Ok(NameserverResponse::Answer {
            rrs,
            is_authoritative: false,
            ..
        })) = resolve_local(
            10,
            &mut Metrics::new(),
            &zones(),
            &cache,
            &Question {
                name: domain("cname-1.example.com."),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_eq!(3, rrs.len());
            assert_cache_response(&cname_rr1, &[rrs[0].clone()]);
            assert_cache_response(&cname_rr2, &[rrs[1].clone()]);
            assert_cache_response(&a_rr, &[rrs[2].clone()]);
        } else {
            panic!("expected non-authoritative answer");
        }
    }

    #[test]
    fn resolve_local_propagates_cname_nonauthority() {
        let cname_rr = cname_record("cname-na.authoritative.example.com.", "a.example.com.");
        let a_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        if let Ok(Ok(NameserverResponse::Answer {
            rrs,
            is_authoritative: false,
            ..
        })) = resolve_local(
            10,
            &mut Metrics::new(),
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("cname-na.authoritative.example.com."),
                qtype: QueryType::Record(RecordType::A),
                qclass: QueryClass::Wildcard,
            },
        ) {
            assert_eq!(2, rrs.len());
            assert_cache_response(&cname_rr, &[rrs[0].clone()]);
            assert_cache_response(&a_rr, &[rrs[1].clone()]);
        } else {
            panic!("expected non-authoritative answer");
        }
    }

    #[test]
    fn resolve_local_returns_cname_response_if_unable_to_fully_resolve() {
        assert_eq!(
            Ok(Ok(NameserverResponse::CNAME {
                rrs: vec![cname_record(
                    "trailing-cname.example.com.",
                    "somewhere-else.example.com."
                )],
                cname: domain("somewhere-else.example.com."),
                is_authoritative: false,
            })),
            resolve_local(
                10,
                &mut Metrics::new(),
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("trailing-cname.example.com."),
                    qtype: QueryType::Record(RecordType::A),
                    qclass: QueryClass::Wildcard,
                }
            )
        );
    }

    #[test]
    fn resolve_local_delegates_from_authoritative_zone() {
        assert_eq!(
            Ok(Ok(NameserverResponse::Delegation {
                rrs: vec![ns_record(
                    "delegated.authoritative.example.com.",
                    "ns.delegated.authoritative.example.com."
                )],
                authority_rrs: vec![zones_soa_rr()],
                is_authoritative: true,
                delegation: Nameservers {
                    name: domain("delegated.authoritative.example.com."),
                    hostnames: vec![HostOrIP::Host(domain(
                        "ns.delegated.authoritative.example.com."
                    ))],
                }
            })),
            resolve_local(
                10,
                &mut Metrics::new(),
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("www.delegated.authoritative.example.com."),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                }
            )
        );
    }

    #[test]
    fn resolve_local_does_not_delegate_from_nonauthoritative_zone() {
        let question = Question {
            name: domain("www.delegated.example.com."),
            qtype: QueryType::Wildcard,
            qclass: QueryClass::Wildcard,
        };

        assert_eq!(
            Err(ResolutionError::DeadEnd {
                question: question.clone()
            }),
            resolve_local(
                10,
                &mut Metrics::new(),
                &zones(),
                &SharedCache::new(),
                &question
            )
        );
    }

    #[test]
    fn resolve_local_nameerrors_from_authoritative_zone() {
        assert_eq!(
            Ok(Err(AuthoritativeNameError {
                soa_rr: zones_soa_rr()
            })),
            resolve_local(
                10,
                &mut Metrics::new(),
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("no.such.name.authoritative.example.com."),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                },
            )
        );
    }

    #[test]
    fn resolve_local_does_not_nameerror_from_nonauthoritative_zone() {
        let question = Question {
            name: domain("no.such.name.example.com."),
            qtype: QueryType::Wildcard,
            qclass: QueryClass::Wildcard,
        };

        assert_eq!(
            Err(ResolutionError::DeadEnd {
                question: question.clone()
            }),
            resolve_local(
                10,
                &mut Metrics::new(),
                &zones(),
                &SharedCache::new(),
                &question,
            )
        );
    }

    pub fn zones_soa_rr() -> ResourceRecord {
        zones()
            .get(&domain("authoritative.example.com."))
            .unwrap()
            .soa_rr()
            .unwrap()
    }
}
