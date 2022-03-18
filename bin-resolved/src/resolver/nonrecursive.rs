use dns_types::protocol::types::*;
use dns_types::zones::types::*;

use super::cache::SharedCache;
use super::util::*;

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

#[cfg(test)]
mod tests {
    use dns_types::protocol::types::test_util::*;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::resolver::cache::test_util::*;
    use crate::resolver::util::test_util::*;

    #[test]
    fn resolve_nonrecursive_is_authoritative_for_zones_with_soa() {
        let soa_rr = zones_soa_rr();
        let mut expected = vec![
            a_record("authoritative.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
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
                name: domain("authoritative.example.com."),
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
                rrs: vec![a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1))],
            }),
            resolve_nonrecursive(
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("a.example.com."),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                }
            )
        )
    }

    #[test]
    fn resolve_nonrecursive_is_nonauthoritative_for_cache() {
        let rr = a_record("cached.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&rr);

        if let Some(ResolvedRecord::NonAuthoritative { rrs }) = resolve_nonrecursive(
            &zones(),
            &cache,
            &Question {
                name: domain("cached.example.com."),
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
            a_record("authoritative.example.com.", Ipv4Addr::new(1, 1, 1, 1)),
            soa_rr.clone(),
        ];
        expected.sort();

        let cache = SharedCache::new();
        cache.insert(&a_record(
            "authoritative.example.com.",
            Ipv4Addr::new(8, 8, 8, 8),
        ));

        if let Some(ResolvedRecord::Authoritative {
            mut rrs,
            authority_rrs,
        }) = resolve_nonrecursive(
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
            panic!("expected authoritative response");
        }
    }

    #[test]
    fn resolve_nonrecursive_combines_nonauthoritative_zones_with_cache() {
        let zone_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));
        let cache_rr = a_record("a.example.com.", Ipv4Addr::new(8, 8, 8, 8));

        let cache = SharedCache::new();
        cache.insert(&cache_rr);

        if let Some(ResolvedRecord::NonAuthoritative { rrs }) = resolve_nonrecursive(
            &zones(),
            &cache,
            &Question {
                name: domain("a.example.com."),
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
            "cname-a.authoritative.example.com.",
            "authoritative.example.com.",
        );
        let a_rr = a_record("authoritative.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        if let Some(ResolvedRecord::Authoritative { rrs, authority_rrs }) = resolve_nonrecursive(
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
            assert_cache_response(&cname_rr, vec![rrs[0].clone()]);
            assert_cache_response(&a_rr, vec![rrs[1].clone()]);
        } else {
            panic!("expected Some response");
        }
    }

    #[test]
    fn resolve_nonrecursive_expands_cnames_from_cache() {
        let cname_rr1 = cname_record("cname-1.example.com.", "cname-2.example.com.");
        let cname_rr2 = cname_record("cname-2.example.com.", "a.example.com.");
        let a_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        let cache = SharedCache::new();
        cache.insert(&cname_rr1);
        cache.insert(&cname_rr2);

        if let Some(ResolvedRecord::NonAuthoritative { rrs }) = resolve_nonrecursive(
            &zones(),
            &cache,
            &Question {
                name: domain("cname-1.example.com."),
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
        let cname_rr = cname_record("cname-na.authoritative.example.com.", "a.example.com.");
        let a_rr = a_record("a.example.com.", Ipv4Addr::new(1, 1, 1, 1));

        if let Some(ResolvedRecord::NonAuthoritative { rrs }) = resolve_nonrecursive(
            &zones(),
            &SharedCache::new(),
            &Question {
                name: domain("cname-na.authoritative.example.com."),
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
                    "delegated.authoritative.example.com.",
                    "ns.delegated.authoritative.example.com."
                )]
            }),
            resolve_nonrecursive(
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
    fn resolve_nonrecursive_does_not_delegate_from_nonauthoritative_zone() {
        assert_eq!(
            None,
            resolve_nonrecursive(
                &zones(),
                &SharedCache::new(),
                &Question {
                    name: domain("www.delegated.example.com."),
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
                    name: domain("no.such.name.authoritative.example.com."),
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
                    name: domain("no.such.name.example.com."),
                    qtype: QueryType::Wildcard,
                    qclass: QueryClass::Wildcard,
                },
            )
        );
    }
}
