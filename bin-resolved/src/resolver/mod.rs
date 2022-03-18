pub mod cache;
pub mod nonrecursive;
pub mod recursive;
pub mod util;

use dns_types::protocol::types::Question;
use dns_types::zones::types::Zones;

use self::cache::SharedCache;
use self::nonrecursive::resolve_nonrecursive;
use self::recursive::resolve_recursive;
use self::util::ResolvedRecord;

/// Resolve a question using the standard DNS algorithms.
pub async fn resolve(
    is_recursive: bool,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    if is_recursive {
        resolve_recursive(zones, cache, question).await
    } else {
        resolve_nonrecursive(zones, cache, question).map(ResolvedRecord::from)
    }
}
