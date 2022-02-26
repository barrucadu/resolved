use crate::protocol::{Question, ResourceRecord};

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
    local_zone: &(),
    cache: &(),
    question: &Question,
) -> Option<ResolvedRecord> {
    let authoritative_rrs = authoritative_from_zone(local_zone, question);
    if !authoritative_rrs.is_empty() {
        return Some(ResolvedRecord::Authoritative {
            rrs: authoritative_rrs,
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
pub enum ResolvedRecord {
    Authoritative {
        rrs: Vec<ResourceRecord>,
    },
    Cached {
        rrs: Vec<ResourceRecord>,
        authority: Vec<ResourceRecord>,
    },
}

/// Locally-defined records for DNS blocklisting and LAN DNS.
///
/// This corresponds to steps 3.a and 3.c of the standard resolution
/// algorithm.  Since this program is intended for just simple local
/// resolution, and in particular it does not support delegating to
/// another zone: all local records are in the same zone.
///
/// TODO: implement
pub fn authoritative_from_zone(_local_zone: &(), _question: &Question) -> Vec<ResourceRecord> {
    Vec::new()
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
