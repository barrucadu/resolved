use async_recursion::async_recursion;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::Instrument;

use dns_types::protocol::types::*;

use crate::context::Context;
use crate::local::{resolve_local, LocalResolutionResult};
use crate::util::nameserver::*;
use crate::util::types::*;

pub struct ForwardingContextInner {
    pub forward_address: SocketAddr,
}

pub type ForwardingContext<'a> = Context<'a, ForwardingContextInner>;

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
pub async fn resolve_forwarding<'a>(
    context: &mut ForwardingContext<'a>,
    question: &Question,
) -> Result<ResolvedRecord, ResolutionError> {
    if let Ok(res) = timeout(
        Duration::from_secs(60),
        resolve_forwarding_notimeout(context, question),
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
async fn resolve_forwarding_notimeout<'a>(
    context: &mut ForwardingContext<'a>,
    question: &Question,
) -> Result<ResolvedRecord, ResolutionError> {
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

    let mut combined_rrs = Vec::new();

    // this is almost the same as in the recursive resolver, but:
    //
    // - delegations are ignored (we just forward to the upstream nameserver)
    // - CNAMEs are resolved by calling the forwarding resolver recursively
    match resolve_local(context, question) {
        Ok(LocalResolutionResult::Done { resolved }) => return Ok(resolved),
        Ok(LocalResolutionResult::Partial { rrs }) => combined_rrs = rrs,
        Ok(LocalResolutionResult::Delegation { .. }) => (),
        Ok(LocalResolutionResult::CNAME {
            mut rrs,
            cname_question,
            ..
        }) => {
            context.push_question(question);
            let answer = match resolve_forwarding_notimeout(context, &cname_question)
                .instrument(tracing::error_span!("resolve_forwarding", %cname_question))
                .await
            {
                Ok(resolved) => {
                    let soa_rr = resolved.soa_rr().cloned();
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
            context.pop_question();
            return answer;
        }
        Err(_) => (),
    }

    if let Some(response) = query_nameserver(context.r.forward_address, question.clone(), true)
        .instrument(tracing::error_span!("query_nameserver"))
        .await
    {
        context.metrics().nameserver_hit();
        tracing::trace!("nameserver HIT");
        // Propagate SOA RR for NXDOMAIN / NODATA responses
        let soa_rr = get_nxdomain_nodata_soa(question, &response, 0).cloned();
        let rrs = response.answers;
        context.cache.insert_all(&rrs);
        prioritising_merge(&mut combined_rrs, rrs);
        Ok(ResolvedRecord::NonAuthoritative {
            rrs: combined_rrs,
            soa_rr,
        })
    } else {
        context.metrics().nameserver_miss();
        tracing::trace!("nameserver MISS");
        Err(ResolutionError::DeadEnd {
            question: question.clone(),
        })
    }
}
