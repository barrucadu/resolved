#![warn(clippy::pedantic)]
// Sometimes a redundant else is clearer
#![allow(clippy::redundant_else)]
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
pub mod context;
pub mod forwarding;
pub mod local;
pub mod metrics;
pub mod recursive;
pub mod util;

use std::net::SocketAddr;
use tracing::Instrument;

use dns_types::protocol::types::Question;
use dns_types::zones::types::Zones;

use self::cache::SharedCache;
use self::context::Context;
use self::forwarding::{resolve_forwarding, ForwardingContextInner};
use self::local::resolve_local;
use self::metrics::Metrics;
use self::recursive::{resolve_recursive, RecursiveContextInner};
use self::util::types::{ProtocolMode, ResolutionError, ResolvedRecord};

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
    protocol_mode: ProtocolMode,
    upstream_dns_port: u16,
    forward_address: Option<SocketAddr>,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> (Metrics, Result<ResolvedRecord, ResolutionError>) {
    match (is_recursive, forward_address) {
        (true, Some(address)) => {
            let mut context = Context::new(
                ForwardingContextInner {
                    forward_address: address,
                },
                zones,
                cache,
                RECURSION_LIMIT,
            );
            let result = resolve_forwarding(&mut context, question)
                .instrument(tracing::error_span!("resolve_forwarding", %address, %question))
                .await;
            (context.done(), result)
        }
        (true, None) => {
            let mut context = Context::new(
                RecursiveContextInner {
                    protocol_mode,
                    upstream_dns_port,
                },
                zones,
                cache,
                RECURSION_LIMIT,
            );
            let result = resolve_recursive(&mut context, question)
                .instrument(tracing::error_span!("resolve_recursive", %question))
                .await;
            (context.done(), result)
        }
        (false, _) => {
            let mut context = Context::new((), zones, cache, RECURSION_LIMIT);
            let result = resolve_local(&mut context, question).map(ResolvedRecord::from);
            (context.done(), result)
        }
    }
}
