use async_recursion::async_recursion;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::Instrument;

use dns_types::protocol::types::*;
use dns_types::zones::types::*;

use crate::cache::SharedCache;
use crate::local::*;
use crate::metrics::Metrics;
use crate::util::nameserver::*;
use crate::util::types::*;

/// Forwarding DNS resolution.
///
/// Attempts to resolve a query locally and, if it cannot, calls out
/// to another nameserver and returns its response.  As this other
/// nameserver can spoof any records it wants, very little validation
/// is done of its responses.
///
/// This has a 60s timeout.
///
/// # Errors
///
/// See `ResolutionError`.
pub async fn resolve_forwarding(
    question_stack: &mut Vec<Question>,
    metrics: &mut Metrics,
    forward_address: SocketAddr,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Result<ResolvedRecord, ResolutionError> {
    if let Ok(res) = timeout(
        Duration::from_secs(60),
        resolve_forwarding_notimeout(
            question_stack,
            metrics,
            forward_address,
            zones,
            cache,
            question,
        ),
    )
    .await
    {
        res
    } else {
        tracing::debug!("timed out");
        Err(ResolutionError::Timeout)
    }
}

/// Timeout-less version of `resolve_forwarding`.
#[async_recursion]
async fn resolve_forwarding_notimeout(
    question_stack: &mut Vec<Question>,
    metrics: &mut Metrics,
    forward_address: SocketAddr,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Result<ResolvedRecord, ResolutionError> {
    if question_stack.len() == question_stack.capacity() {
        tracing::debug!("hit recursion limit");
        return Err(ResolutionError::RecursionLimit);
    }
    if question_stack.contains(question) {
        tracing::debug!("hit duplicate question");
        return Err(ResolutionError::DuplicateQuestion {
            question: question.clone(),
        });
    }

    let mut combined_rrs = Vec::new();

    // this is almost the same as in the recursive resolver, but:
    //
    // - delegations are ignored (we just forward to the upstream nameserver)
    // - CNAMEs are resolved by calling the forwarding resolver recursively
    match resolve_local(question_stack, metrics, zones, cache, question) {
        Ok(LocalResolutionResult::Done { resolved }) => return Ok(resolved),
        Ok(LocalResolutionResult::Partial { rrs }) => combined_rrs = rrs,
        Ok(LocalResolutionResult::Delegation { .. }) => (),
        Ok(LocalResolutionResult::CNAME {
            mut rrs,
            cname_question,
            ..
        }) => {
            question_stack.push(question.clone());
            let answer = match resolve_forwarding_notimeout(
                question_stack,
                metrics,
                forward_address,
                zones,
                cache,
                &cname_question,
            )
            .instrument(tracing::error_span!("resolve_forwarding", %cname_question))
            .await
            {
                Ok(resolved) => {
                    let soa_rr = resolved.soa_rr();
                    let mut r_rrs = resolved.rrs();
                    let mut combined_rrs = Vec::with_capacity(rrs.len() + r_rrs.len());
                    combined_rrs.append(&mut rrs);
                    combined_rrs.append(&mut r_rrs);
                    Ok(ResolvedRecord::NonAuthoritative {
                        rrs: combined_rrs,
                        soa_rr,
                    })
                }
                Err(_) => Err(ResolutionError::DeadEnd {
                    question: cname_question,
                }),
            };
            question_stack.pop();
            return answer;
        }
        Err(_) => (),
    }

    if let Some(response) = query_nameserver(forward_address, question, true)
        .instrument(tracing::error_span!("query_nameserver"))
        .await
    {
        metrics.nameserver_hit();
        tracing::trace!("nameserver HIT");
        // Propagate SOA RR for NXDOMAIN / NODATA responses
        let soa_rr = get_nxdomain_nodata_soa(question, &response, 0);
        let rrs = response.answers;
        cache.insert_all(&rrs);
        prioritising_merge(&mut combined_rrs, rrs);
        Ok(ResolvedRecord::NonAuthoritative {
            rrs: combined_rrs,
            soa_rr,
        })
    } else {
        metrics.nameserver_miss();
        tracing::trace!("nameserver MISS");
        Err(ResolutionError::DeadEnd {
            question: question.clone(),
        })
    }
}
