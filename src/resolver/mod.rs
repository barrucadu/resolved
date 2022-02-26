use crate::protocol::{
    QueryClass, QueryType, Question, RecordClass, RecordType, RecordTypeWithData, ResourceRecord,
};
use crate::settings::Settings;

/// Non-recursive DNS resolution.
///
/// This corresponds to steps 2, 3, and 4 of the standard resolution
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
    if let Some(authoritative) = authoritative_from_zone(local_zone, question) {
        return Some(ResolvedRecord::Authoritative {
            rrs: vec![authoritative],
        });
    }

    let (cached_rrs, cached_authority_rrs) = nonauthoritative_from_cache(cache, question);
    if !cached_rrs.is_empty() {
        return Some(ResolvedRecord::Cached {
            rrs: cached_rrs,
            authority: cached_authority_rrs,
        });
    }

    None
}

/// The result of a name resolution attempt.
///
/// If this is a `CNAME`, it should be added to the answer section of
/// the response message, and resolution repeated for the CNAME.  This
/// may build up a chain of `CNAME`s for some names.
///
///
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResolvedRecord {
    Authoritative {
        rrs: Vec<ResourceRecord>,
    },
    Cached {
        rrs: Vec<ResourceRecord>,
        authority: Vec<ResourceRecord>,
    },
}

impl ResolvedRecord {
    pub fn rrs(self) -> Vec<ResourceRecord> {
        match self {
            ResolvedRecord::Authoritative { rrs } => rrs,
            ResolvedRecord::Cached { rrs, authority: _ } => rrs,
        }
    }
}

/// Locally-defined records for DNS blocklisting and LAN DNS.
///
/// This corresponds to steps 3.a and 3.c of the standard resolution
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
/// This corresponds to step 4 of the standard resolution algorithm.
///
/// TODO: implement
pub fn nonauthoritative_from_cache(
    _cache: &(),
    _question: &Question,
) -> (Vec<ResourceRecord>, Vec<ResourceRecord>) {
    (Vec::new(), Vec::new())
}
