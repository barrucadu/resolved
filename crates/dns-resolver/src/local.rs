use dns_types::protocol::types::*;
use dns_types::zones::types::*;

use crate::context::Context;
use crate::util::types::*;

/// Query type for CNAMEs - used for cache lookups.
const CNAME_QTYPE: QueryType = QueryType::Record(RecordType::CNAME);

/// Local DNS resolution.
///
/// This acts like a pseudo-nameserver, returning a `LocalResolutionResult`
/// which is either consumed by another resolver, or converted directly into a
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
pub fn resolve_local<CT>(
    context: &mut Context<'_, CT>,
    question: &Question,
) -> Result<LocalResolutionResult, ResolutionError> {
    let _span = tracing::error_span!("resolve_local", %question).entered();

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

    let mut rrs_from_zone = Vec::new();

    // `zones.resolve` implements the non-recursive part of step 3 of the
    // standard resolver algorithm: matching down through the zone and returning
    // what sort of end state is reached.
    if let Some((zone, zone_result)) = context.zones.resolve(&question.name, question.qtype) {
        let _zone_span = tracing::error_span!("zone", apex = %zone.get_apex().to_dotted_string(), is_authoritative = %zone.is_authoritative()).entered();

        match zone_result {
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
            ZoneResult::Answer { rrs } => {
                context.metrics().zoneresult_answer(&rrs, zone, question);

                if let Some(soa_rr) = zone.soa_rr() {
                    tracing::trace!("got authoritative answer");
                    return Ok(LocalResolutionResult::Done {
                        resolved: ResolvedRecord::Authoritative { rrs, soa_rr },
                    });
                } else if question.qtype != QueryType::Wildcard && !rrs.is_empty() {
                    tracing::trace!("got non-authoritative answer");
                    return Ok(LocalResolutionResult::Done {
                        resolved: ResolvedRecord::NonAuthoritative { rrs, soa_rr: None },
                    });
                } else {
                    tracing::trace!("got partial answer");
                    rrs_from_zone = rrs;
                }
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
            ZoneResult::CNAME { cname, rr } => {
                context.metrics().zoneresult_cname(zone);

                let mut rrs = vec![rr];
                let cname_question = Question {
                    name: cname,
                    qtype: question.qtype,
                    qclass: question.qclass,
                };

                context.push_question(question);
                let answer = match resolve_local(context, &cname_question) {
                    Ok(LocalResolutionResult::Done { resolved }) => match resolved {
                        ResolvedRecord::Authoritative {
                            rrs: mut cname_rrs,
                            soa_rr,
                        } => {
                            rrs.append(&mut cname_rrs);
                            tracing::trace!("got authoritative cname answer");
                            LocalResolutionResult::Done {
                                resolved: ResolvedRecord::Authoritative { rrs, soa_rr },
                            }
                        }
                        ResolvedRecord::AuthoritativeNameError { soa_rr } => {
                            tracing::trace!("got authoritative cname answer");
                            LocalResolutionResult::Done {
                                resolved: ResolvedRecord::Authoritative { rrs, soa_rr },
                            }
                        }
                        ResolvedRecord::NonAuthoritative {
                            rrs: mut cname_rrs,
                            soa_rr,
                        } => {
                            tracing::trace!("got non-authoritative cname answer");
                            rrs.append(&mut cname_rrs);
                            LocalResolutionResult::Done {
                                resolved: ResolvedRecord::NonAuthoritative { rrs, soa_rr },
                            }
                        }
                    },
                    Ok(LocalResolutionResult::Partial { rrs: mut cname_rrs }) => {
                        tracing::trace!("got partial cname answer");
                        rrs.append(&mut cname_rrs);
                        LocalResolutionResult::Partial { rrs }
                    }
                    Ok(LocalResolutionResult::CNAME {
                        rrs: mut cname_rrs,
                        cname_question,
                    }) => {
                        tracing::trace!("got incomplete cname answer");
                        rrs.append(&mut cname_rrs);
                        LocalResolutionResult::CNAME {
                            rrs,
                            cname_question,
                        }
                    }
                    _ => {
                        tracing::trace!("got incomplete cname answer");
                        LocalResolutionResult::CNAME {
                            rrs,
                            cname_question,
                        }
                    }
                };
                context.pop_question();
                return Ok(answer);
            }
            // If the name is delegated:
            //
            // - if this zone is authoritative, return the response with the NS
            // RRs in the AUTHORITY section.
            //
            // - otherwise ignore and proceed to cache.
            ZoneResult::Delegation { ns_rrs } => {
                tracing::trace!("got delegation");
                context.metrics().zoneresult_delegation(zone);

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
                            hostnames.push(nsdname.clone());
                        } else {
                            tracing::warn!(rtype = %rr.rtype_with_data.rtype(), "got non-NS RR in a delegation");
                        }
                    }

                    return Ok(LocalResolutionResult::Delegation {
                        delegation: Nameservers { hostnames, name },
                        rrs: ns_rrs,
                        soa_rr: Some(soa_rr),
                    });
                }
            }
            // If the name could not be resolved:
            //
            // - if this zone is authoritative, a NXDOMAIN response
            // (todo)
            //
            // - otherwise ignore and proceed to cache.
            ZoneResult::NameError => {
                tracing::trace!("got name error");
                context.metrics().zoneresult_nameerror(zone);

                if let Some(soa_rr) = zone.soa_rr() {
                    return Ok(LocalResolutionResult::Done {
                        resolved: ResolvedRecord::AuthoritativeNameError { soa_rr },
                    });
                }
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

    let mut rrs_from_cache = context.cache.get(&question.name, question.qtype);
    if rrs_from_cache.is_empty() {
        tracing::trace!(qtype = %question.qtype, "cache MISS");
        context.metrics().cache_miss();
    } else {
        tracing::trace!(qtype = %question.qtype, "cache HIT");
        context.metrics().cache_hit();
    }

    let mut final_cname = None;
    if rrs_from_cache.is_empty() && question.qtype != CNAME_QTYPE {
        let cache_cname_rrs = context.cache.get(&question.name, CNAME_QTYPE);
        if cache_cname_rrs.is_empty() {
            tracing::trace!(qtype = %CNAME_QTYPE, "cache MISS");
            context.metrics().cache_miss();
        } else {
            tracing::trace!(qtype = %CNAME_QTYPE, "cache HIT");
            context.metrics().cache_hit();
        }

        if !cache_cname_rrs.is_empty() {
            let cname_rr = cache_cname_rrs[0].clone();
            rrs_from_cache = vec![cname_rr.clone()];

            if let RecordTypeWithData::CNAME { cname } = cname_rr.rtype_with_data {
                context.push_question(question);
                let resolved_cname = resolve_local(
                    context,
                    &Question {
                        name: cname.clone(),
                        qtype: question.qtype,
                        qclass: question.qclass,
                    },
                );
                context.pop_question();
                match resolved_cname {
                    Ok(LocalResolutionResult::Done { resolved }) => {
                        rrs_from_cache.append(&mut resolved.rrs());
                    }
                    Ok(LocalResolutionResult::Partial { mut rrs }) => {
                        rrs_from_cache.append(&mut rrs);
                    }
                    Ok(LocalResolutionResult::CNAME {
                        mut rrs,
                        cname_question,
                    }) => {
                        rrs_from_cache.append(&mut rrs);
                        final_cname = Some(cname_question.name);
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
            }
        }
    }

    let mut rrs = rrs_from_zone;
    prioritising_merge(&mut rrs, rrs_from_cache);

    if rrs.is_empty() {
        Err(ResolutionError::DeadEnd {
            question: question.clone(),
        })
    } else if let Some(cname) = final_cname {
        Ok(LocalResolutionResult::CNAME {
            rrs,
            cname_question: Question {
                name: cname,
                qtype: question.qtype,
                qclass: question.qclass,
            },
        })
    } else if question.qtype == QueryType::Wildcard {
        Ok(LocalResolutionResult::Partial { rrs })
    } else {
        Ok(LocalResolutionResult::Done {
            resolved: ResolvedRecord::NonAuthoritative { rrs, soa_rr: None },
        })
    }
}

/// Result of resolving a name using only zones and cache.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum LocalResolutionResult {
    Done {
        resolved: ResolvedRecord,
    },
    Partial {
        rrs: Vec<ResourceRecord>,
    },
    Delegation {
        rrs: Vec<ResourceRecord>,
        soa_rr: Option<ResourceRecord>,
        delegation: Nameservers,
    },
    CNAME {
        rrs: Vec<ResourceRecord>,
        cname_question: Question,
    },
}

impl From<LocalResolutionResult> for ResolvedRecord {
    fn from(lsr: LocalResolutionResult) -> Self {
        match lsr {
            LocalResolutionResult::Done { resolved } => resolved,
            LocalResolutionResult::Partial { rrs } => {
                ResolvedRecord::NonAuthoritative { rrs, soa_rr: None }
            }
            LocalResolutionResult::Delegation { rrs, soa_rr, .. } => {
                if let Some(soa_rr) = soa_rr {
                    ResolvedRecord::Authoritative { rrs, soa_rr }
                } else {
                    ResolvedRecord::NonAuthoritative { rrs, soa_rr: None }
                }
            }
            LocalResolutionResult::CNAME { rrs, .. } => {
                ResolvedRecord::NonAuthoritative { rrs, soa_rr: None }
            }
        }
    }
}

/// An authoritative name error response, returned by the
/// non-recursive resolver.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AuthoritativeNameError {
    pub soa_rr: ResourceRecord,
}

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;
    use dns_types::zones::types::*;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::cache::test_util::*;
    use crate::cache::SharedCache;

    #[test]
    fn resolve_local_is_authoritative_for_zones_with_soa() {
        assert_eq!(
            test_resolve_local("www.authoritative.example.com.", QueryType::Wildcard),
            Ok(LocalResolutionResult::Done {
                resolved: ResolvedRecord::Authoritative {
                    rrs: vec![a_record(
                        "www.authoritative.example.com.",
                        Ipv4Addr::new(1, 1, 1, 1)
                    )],
                    soa_rr: soa_rr(),
                },
            })
        );
    }

    #[test]
    fn resolve_local_is_partial_for_zones_without_soa() {
        assert_eq!(
            test_resolve_local("a.example.com.", QueryType::Wildcard),
            Ok(LocalResolutionResult::Partial {
                rrs: vec![a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1))],
            })
        );
    }

    #[test]
    fn resolve_local_is_partial_for_cache() {
        let rr = a_record("cached.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&rr);

        if let Ok(LocalResolutionResult::Partial { rrs }) =
            test_resolve_local_with_cache("cached.example.com.", &cache, QueryType::Wildcard)
        {
            assert_cache_response(&rr, &rrs);
        } else {
            panic!("expected non-authoritative answer");
        }
    }

    #[test]
    fn resolve_local_returns_all_record_types() {
        if let Ok(LocalResolutionResult::Done {
            resolved:
                ResolvedRecord::Authoritative {
                    rrs: mut actual_rrs,
                    soa_rr: actual_soa_rr,
                },
        }) = test_resolve_local(
            "cname-and-a.authoritative.example.com.",
            QueryType::Wildcard,
        ) {
            // sometimes these can be returned in a different order (hashmap
            // shenanigans?) so explicitly sort in the test
            actual_rrs.sort();

            assert_eq!(
                actual_rrs,
                vec![
                    a_record(
                        "cname-and-a.authoritative.example.com.",
                        Ipv4Addr::new(1, 1, 1, 1)
                    ),
                    cname_record(
                        "cname-and-a.authoritative.example.com.",
                        "www.authoritative.example.com."
                    ),
                ]
            );
            assert_eq!(actual_soa_rr, soa_rr());
        } else {
            panic!("expected authoritative answer");
        }
    }

    #[test]
    fn resolve_local_prefers_authoritative_zones() {
        let cache = SharedCache::new();
        cache.insert(&a_record(
            "www.authoritative.example.com.",
            Ipv4Addr::new(8, 8, 8, 8),
        ));

        assert_eq!(
            test_resolve_local_with_cache(
                "www.authoritative.example.com.",
                &cache,
                QueryType::Wildcard
            ),
            Ok(LocalResolutionResult::Done {
                resolved: ResolvedRecord::Authoritative {
                    rrs: vec![a_record(
                        "www.authoritative.example.com.",
                        Ipv4Addr::new(1, 1, 1, 1)
                    )],
                    soa_rr: soa_rr(),
                },
            })
        );
    }

    #[test]
    fn resolve_local_combines_nonauthoritative_zones_with_cache() {
        let zone_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));
        let cache_rr = cname_record("a.example.com.", "b.example.com.");

        let cache = SharedCache::new();
        cache.insert(&cache_rr);

        if let Ok(LocalResolutionResult::Partial { rrs }) =
            test_resolve_local_with_cache("a.example.com.", &cache, QueryType::Wildcard)
        {
            assert_eq!(2, rrs.len());
            assert_eq!(zone_rr, rrs[0]);
            assert_cache_response(&cache_rr, &[rrs[1].clone()]);
        } else {
            panic!("expected non-authoritative answer");
        }
    }

    #[test]
    fn resolve_local_overrides_cache_with_nonauthoritative_zones() {
        let zone_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));
        let cache_rr = a_record("a.example.com.", Ipv4Addr::new(8, 8, 8, 8));

        let cache = SharedCache::new();
        cache.insert(&cache_rr);

        assert_eq!(
            test_resolve_local("a.example.com.", QueryType::Wildcard),
            Ok(LocalResolutionResult::Partial { rrs: vec![zone_rr] })
        );
    }

    #[test]
    fn resolve_local_expands_cnames_from_zone() {
        assert_eq!(
            test_resolve_local(
                "cname-authoritative.authoritative.example.com.",
                QueryType::Record(RecordType::A)
            ),
            Ok(LocalResolutionResult::Done {
                resolved: ResolvedRecord::Authoritative {
                    rrs: vec![
                        cname_record(
                            "cname-authoritative.authoritative.example.com.",
                            "www.authoritative.example.com."
                        ),
                        a_record("www.authoritative.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
                    ],
                    soa_rr: soa_rr(),
                },
            }),
        );
    }

    #[test]
    fn resolve_local_expands_cnames_from_cache() {
        let cname_rr1 = cname_record("cname-1.example.com.", "cname-2.example.com.");
        let cname_rr2 = cname_record("cname-2.example.com.", "a.example.com.");
        let a_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&cname_rr1);
        cache.insert(&cname_rr2);

        if let Ok(LocalResolutionResult::Done {
            resolved: ResolvedRecord::NonAuthoritative { rrs, soa_rr: None },
        }) = test_resolve_local_with_cache(
            "cname-1.example.com.",
            &cache,
            QueryType::Record(RecordType::A),
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
    fn resolve_local_handles_cname_cycle() {
        let qtype = QueryType::Record(RecordType::A);

        assert_eq!(
            test_resolve_local("cname-cycle-a.example.com.", qtype),
            Ok(LocalResolutionResult::CNAME {
                rrs: vec![
                    cname_record("cname-cycle-a.example.com.", "cname-cycle-b.example.com."),
                    cname_record("cname-cycle-b.example.com.", "cname-cycle-a.example.com."),
                ],
                cname_question: Question {
                    name: domain("cname-cycle-a.example.com."),
                    qclass: QueryClass::Wildcard,
                    qtype,
                },
            }),
        );
    }

    #[test]
    fn resolve_local_propagates_cname_nonauthority() {
        assert_eq!(
            test_resolve_local(
                "cname-nonauthoritative.authoritative.example.com.",
                QueryType::Record(RecordType::A)
            ),
            Ok(LocalResolutionResult::Done {
                resolved: ResolvedRecord::NonAuthoritative {
                    rrs: vec![
                        cname_record(
                            "cname-nonauthoritative.authoritative.example.com.",
                            "a.example.com."
                        ),
                        a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
                    ],
                    soa_rr: None,
                },
            }),
        );
    }

    #[test]
    fn resolve_local_uses_most_specific_cname_authority() {
        assert_eq!(
            test_resolve_local(
                "cname.authoritative-2.example.com.",
                QueryType::Record(RecordType::A)
            ),
            Ok(LocalResolutionResult::Done {
                resolved: ResolvedRecord::Authoritative {
                    rrs: vec![
                        cname_record(
                            "cname.authoritative-2.example.com.",
                            "www.authoritative.example.com."
                        ),
                        a_record("www.authoritative.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
                    ],
                    soa_rr: soa_rr(),
                },
            }),
        );
    }

    #[test]
    fn resolve_local_returns_cname_response_if_unable_to_fully_resolve() {
        let qtype = QueryType::Record(RecordType::A);

        assert_eq!(
            test_resolve_local("trailing-cname.example.com.", qtype),
            Ok(LocalResolutionResult::CNAME {
                rrs: vec![cname_record(
                    "trailing-cname.example.com.",
                    "somewhere-else.example.com."
                )],
                cname_question: Question {
                    name: domain("somewhere-else.example.com."),
                    qclass: QueryClass::Wildcard,
                    qtype,
                },
            })
        );
    }

    #[test]
    fn resolve_local_delegates_from_authoritative_zone() {
        assert_eq!(
            test_resolve_local(
                "www.delegated.authoritative.example.com.",
                QueryType::Wildcard
            ),
            Ok(LocalResolutionResult::Delegation {
                rrs: vec![ns_record(
                    "delegated.authoritative.example.com.",
                    "ns.delegated.authoritative.example.com."
                )],
                soa_rr: Some(soa_rr()),
                delegation: Nameservers {
                    name: domain("delegated.authoritative.example.com."),
                    hostnames: vec![domain("ns.delegated.authoritative.example.com.")],
                }
            })
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
            resolve_local(
                &mut Context::new((), &zones(), &SharedCache::new(), 10),
                &question
            ),
            Err(ResolutionError::DeadEnd {
                question: question.clone()
            })
        );
    }

    #[test]
    fn resolve_local_nameerrors_from_authoritative_zone() {
        assert_eq!(
            test_resolve_local(
                "no.such.name.authoritative.example.com.",
                QueryType::Wildcard
            ),
            Ok(LocalResolutionResult::Done {
                resolved: ResolvedRecord::AuthoritativeNameError { soa_rr: soa_rr() },
            }),
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
            resolve_local(
                &mut Context::new((), &zones(), &SharedCache::new(), 10),
                &question,
            ),
            Err(ResolutionError::DeadEnd {
                question: question.clone()
            }),
        );
    }

    fn test_resolve_local(
        name: &str,
        qtype: QueryType,
    ) -> Result<LocalResolutionResult, ResolutionError> {
        test_resolve_local_with_cache(name, &SharedCache::new(), qtype)
    }

    fn test_resolve_local_with_cache(
        name: &str,
        cache: &SharedCache,
        qtype: QueryType,
    ) -> Result<LocalResolutionResult, ResolutionError> {
        resolve_local(
            &mut Context::new((), &zones(), cache, 10),
            &Question {
                name: domain(name),
                qclass: QueryClass::Wildcard,
                qtype,
            },
        )
    }

    fn soa_rr() -> ResourceRecord {
        zones()
            .get(&domain("authoritative.example.com."))
            .unwrap()
            .soa_rr()
            .unwrap()
    }

    #[allow(clippy::missing_panics_doc)]
    fn zones() -> Zones {
        // use TTL 300 for all records because that's what the other spec
        // helpers have
        let mut zones = Zones::new();

        zones.insert(
            Zone::deserialise(
                r"
$ORIGIN example.com.

a              300 IN A     1.1.1.1
blocked        300 IN A     0.0.0.0
cname-cycle-a  300 IN CNAME cname-cycle-b
cname-cycle-b  300 IN CNAME cname-cycle-a
delegated      300 IN NS    ns.delegated
trailing-cname 300 IN CNAME somewhere-else
",
            )
            .unwrap(),
        );

        zones.insert(
            Zone::deserialise(
                r"
$ORIGIN authoritative.example.com.

@ IN SOA mname rname 1 30 30 30 30

www                    300 IN A     1.1.1.1
cname-and-a            300 IN A     1.1.1.1
cname-and-a            300 IN CNAME www
cname-authoritative    300 IN CNAME www
cname-nonauthoritative 300 IN CNAME a.example.com.
delegated              300 IN NS    ns.delegated
",
            )
            .unwrap(),
        );

        zones.insert(
            Zone::deserialise(
                r"
$ORIGIN authoritative-2.example.com.

@ IN SOA mname rname 1 30 30 30 30

cname 300 IN CNAME www.authoritative.example.com.
",
            )
            .unwrap(),
        );

        zones
    }
}
