#![warn(clippy::pedantic)]
// TODO: fix
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::semicolon_if_nothing_returned)]
// Don't care enough to fix
#![allow(clippy::match_same_arms)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::wildcard_imports)]

pub mod cache;
pub mod forwarding;
pub mod metrics;
pub mod nonrecursive;
pub mod recursive;
pub mod util;

use std::net::Ipv4Addr;
use tracing::Instrument;

use dns_types::protocol::types::Question;
use dns_types::zones::types::Zones;

use self::cache::SharedCache;
use self::forwarding::resolve_forwarding;
use self::metrics::Metrics;
use self::nonrecursive::resolve_nonrecursive;
use self::recursive::resolve_recursive;
use self::util::types::ResolvedRecord;

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
) -> (Metrics, Option<ResolvedRecord>) {
    let mut metrics = Metrics::new();

    let rr = if is_recursive {
        if let Some(address) = forward_address {
            resolve_forwarding(
                RECURSION_LIMIT,
                &mut metrics,
                address,
                zones,
                cache,
                question,
            )
            .instrument(tracing::error_span!("resolve_forwarding", %address, %question))
            .await
        } else {
            resolve_recursive(RECURSION_LIMIT, &mut metrics, zones, cache, question)
                .instrument(tracing::error_span!("resolve_recursive", %question))
                .await
        }
    } else {
        resolve_nonrecursive(RECURSION_LIMIT, &mut metrics, zones, cache, question)
            .map(ResolvedRecord::from)
    };

    (metrics, rr)
}
