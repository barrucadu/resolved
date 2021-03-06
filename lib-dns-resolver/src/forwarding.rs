use async_recursion::async_recursion;
use rand::Rng;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::Instrument;

use dns_types::protocol::types::*;
use dns_types::zones::types::*;

use crate::cache::SharedCache;
use crate::metrics::Metrics;
use crate::nonrecursive::resolve_nonrecursive;
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
pub async fn resolve_forwarding(
    recursion_limit: usize,
    metrics: &mut Metrics,
    forward_address: Ipv4Addr,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    if let Ok(res) = timeout(
        Duration::from_secs(60),
        resolve_forwarding_notimeout(
            recursion_limit,
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
        None
    }
}

/// Timeout-less version of `resolve_forwarding`.
#[async_recursion]
async fn resolve_forwarding_notimeout(
    recursion_limit: usize,
    metrics: &mut Metrics,
    forward_address: Ipv4Addr,
    zones: &Zones,
    cache: &SharedCache,
    question: &Question,
) -> Option<ResolvedRecord> {
    if recursion_limit == 0 {
        tracing::debug!("hit recursion limit");
        return None;
    }

    let mut combined_rrs = Vec::new();

    match resolve_nonrecursive(recursion_limit - 1, metrics, zones, cache, question) {
        Some(Ok(NameserverResponse::Answer {
            rrs,
            authority_rrs,
            is_authoritative,
        })) => {
            if is_authoritative || question.qtype != QueryType::Wildcard {
                tracing::trace!("got non-recursive answer");
                return Some(
                    NameserverResponse::Answer {
                        rrs,
                        authority_rrs,
                        is_authoritative,
                    }
                    .into(),
                );
            }
            tracing::trace!(
                "got non-recursive non-authoritative answer to current wildcard query - continuing"
            );
            combined_rrs = rrs;
        }
        Some(Ok(NameserverResponse::Delegation { .. })) => {
            tracing::trace!(
                "got non-recursive delegation - ignoring in favour of forwarding nameserver"
            );
        }
        Some(Ok(NameserverResponse::CNAME { rrs, cname, .. })) => {
            tracing::trace!("got non-recursive CNAME - restarting with CNAME target");
            let cname_question = Question {
                name: cname,
                qclass: question.qclass,
                qtype: question.qtype,
            };
            if let Some(resolved) = resolve_forwarding_notimeout(
                recursion_limit - 1,
                metrics,
                forward_address,
                zones,
                cache,
                &cname_question,
            )
            .instrument(tracing::error_span!("resolve_forwarding", %cname_question))
            .await
            {
                let mut r_rrs = resolved.rrs();
                let mut combined_rrs = Vec::with_capacity(rrs.len() + r_rrs.len());
                combined_rrs.append(&mut rrs.clone());
                combined_rrs.append(&mut r_rrs);
                return Some(ResolvedRecord::NonAuthoritative { rrs: combined_rrs });
            }
            return None;
        }
        Some(Err(error)) => {
            tracing::trace!("got non-recursive error response");
            return Some(error.into());
        }
        None => (),
    }

    if let Some(rrs) = query_nameserver(forward_address, question)
        .instrument(tracing::error_span!("query_nameserver"))
        .await
    {
        metrics.nameserver_hit();
        for rr in &rrs {
            cache.insert(rr);
        }
        tracing::trace!("nameserver HIT");
        prioritising_merge(&mut combined_rrs, rrs);
        Some(ResolvedRecord::NonAuthoritative { rrs: combined_rrs })
    } else {
        metrics.nameserver_miss();
        tracing::trace!("nameserver MISS");
        None
    }
}
/// Query a remote nameserver to answer a question.
///
/// This does a recursive query.
async fn query_nameserver(address: Ipv4Addr, question: &Question) -> Option<Vec<ResourceRecord>> {
    let mut request = Message::from_question(rand::thread_rng().gen(), question.clone());
    request.header.recursion_desired = true;

    tracing::trace!("forwarding query to nameserver");

    match request.clone().to_octets() {
        Ok(mut serialised_request) => {
            if let Some(response) = query_nameserver_udp(address, &mut serialised_request).await {
                if response_matches_request(&request, &response) {
                    return Some(response.answers);
                }
            }
            if let Some(response) = query_nameserver_tcp(address, &mut serialised_request).await {
                if response_matches_request(&request, &response) {
                    return Some(response.answers);
                }
            }
            None
        }
        Err(error) => {
            tracing::warn!(message = ?request, ?error, "could not serialise message");
            None
        }
    }
}
