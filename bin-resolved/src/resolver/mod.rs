pub mod cache;
pub mod forwarding;
pub mod nonrecursive;
pub mod recursive;
pub mod util;

use std::net::Ipv4Addr;

use dns_types::protocol::types::Question;
use dns_types::zones::types::Zones;

use self::cache::SharedCache;
use self::forwarding::resolve_forwarding;
use self::nonrecursive::resolve_nonrecursive;
use self::recursive::resolve_recursive;
use self::util::ResolvedRecord;

/// Maximum recursion depth.  Recursion is used to resolve CNAMEs, so
/// a chain of CNAMEs longer than this cannot be resolved.
///
/// This is to protect against a maliciously-configured upstream
/// nameserver which returns an infinite stream of CNAME records when
/// trying to resolve some other record type.
pub const RECURSION_LIMIT: usize = 32;

/// Resolve a question using the standard DNS algorithms.
pub async fn resolve(
    is_recursive: bool,
    forward_address: Option<Ipv4Addr>,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    if is_recursive {
        if let Some(address) = forward_address {
            resolve_forwarding(RECURSION_LIMIT, address, zones, cache, question).await
        } else {
            resolve_recursive(RECURSION_LIMIT, zones, cache, question).await
        }
    } else {
        resolve_nonrecursive(RECURSION_LIMIT, zones, cache, question).map(ResolvedRecord::from)
    }
}
