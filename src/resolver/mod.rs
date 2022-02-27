use std::cmp::Ordering;
use std::net::Ipv4Addr;

use crate::protocol::{
    DomainName, QueryClass, QueryType, Question, RecordClass, RecordType, RecordTypeWithData,
    ResourceRecord,
};
use crate::settings::Settings;

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
/// information is not held locally, it will call out to remove
/// nameservers, starting with the given upstream nameservers.  Since
/// it may make network requests, this function is async.
///
/// See section 5.3.3 of RFC 1034.
pub async fn resolve_recursive(
    upstream_nameservers: &[Ipv4Addr],
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
        let (mut nameservers, mut match_count) =
            ordered_nameservers(upstream_nameservers, local_zone, cache, &question.name);
        while !nameservers.is_empty() {
            let mut new_match_count = match_count + 1;
            let mut new_nameservers = Vec::new();
            'query: for ns in nameservers {
                match query_nameserver(&ns.ip, question).await {
                    None => (),
                    Some(NameserverResponse::Answer { rrs }) => {
                        return Some(ResolvedRecord::NonAuthoritative {
                            rrs,
                            authority: ns.rr,
                        })
                    }
                    Some(NameserverResponse::Delegation { authorities }) => {
                        let mut found_better = false;
                        for (authority, authority_match_count) in authorities {
                            match authority_match_count.cmp(&new_match_count) {
                                Ordering::Greater => {
                                    new_match_count = match_count;
                                    new_nameservers = vec![authority];
                                    found_better = true;
                                }
                                Ordering::Equal => {
                                    new_nameservers.push(authority);
                                    found_better = true;
                                }
                                Ordering::Less => (),
                            }
                        }
                        if found_better {
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
///
/// TODO: implement
pub fn ordered_nameservers(
    _upstream_nameservers: &[Ipv4Addr],
    _local_zone: &Settings,
    _cache: &(),
    _question: &DomainName,
) -> (Vec<Authority>, usize) {
    (Vec::new(), 0)
}

/// Query a remove nameserver, recursively, to answer a question.
///
/// This corresponds to step 3 of the standard resolver algorithm.
///
/// TODO: implement
pub async fn query_nameserver(
    _address: &Ipv4Addr,
    _question: &Question,
) -> Option<NameserverResponse> {
    None
}

/// A response from a remote nameserver
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NameserverResponse {
    Answer {
        rrs: Vec<ResourceRecord>,
    },
    Delegation {
        authorities: Vec<(Authority, usize)>,
    },
}

/// An authority to answer a query
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Authority {
    ip: Ipv4Addr,
    rr: Option<ResourceRecord>,
}
