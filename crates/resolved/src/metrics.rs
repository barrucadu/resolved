use axum::{http::StatusCode, routing};
use prometheus::{
    opts, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, HistogramVec, IntCounter, IntCounterVec, IntGauge, TextEncoder,
};
use std::net::SocketAddr;

pub const RESPONSE_TIME_BUCKETS: &[f64] = &[
    0.0001, // 0.1 ms
    0.0005, // 0.5 ms
    0.0010, // 1   ms
    0.0025, // 2.5 ms
    0.0050, // 5   ms
    0.0075, // 7.5 ms
    0.0100, // 10  ms
    0.0250, // 25  ms
    0.0500, // 50  ms
    0.0750, // 75  ms
    0.1000, // 100 ms
    0.2500, // 250 ms
    0.5000, // 500 ms
    0.7500, // 750 ms
    1.0000, // 1    s
];

// separate const because we may want to change this in the future to
// get more granularity on the lower end
pub const PROCESSING_TIME_BUCKETS: &[f64] = RESPONSE_TIME_BUCKETS;

pub const REFUSED_FOR_MULTIPLE_QUESTIONS: &str = "multiple_questions";
pub const REFUSED_FOR_UNKNOWN_QTYPE_OR_QCLASS: &str = "unknown_qtype_or_qclass";

pub static DNS_REQUESTS_TOTAL: std::sync::LazyLock<IntCounterVec> =
    std::sync::LazyLock::new(|| {
        register_int_counter_vec!(
            opts!(
                "dns_requests_total",
                "Total number of DNS requests received, whether valid or invalid."
            ),
            &["protocol"]
        )
        .unwrap()
    });

pub static DNS_REQUESTS_REFUSED_TOTAL: std::sync::LazyLock<IntCounterVec> =
    std::sync::LazyLock::new(|| {
        register_int_counter_vec!(
            opts!(
                "dns_requests_refused_total",
                "Total number of DNS requests refused."
            ),
            &["reason"]
        )
        .unwrap()
    });

pub static DNS_RESPONSES_TOTAL: std::sync::LazyLock<IntCounterVec> =
    std::sync::LazyLock::new(|| {
        register_int_counter_vec!(
            opts!("dns_responses_total", "Total number of DNS responses sent."),
            &["aa", "tc", "rd", "ra", "rcode"]
        )
        .unwrap()
    });

pub static DNS_RESPONSE_TIME_SECONDS: std::sync::LazyLock<HistogramVec> =
    std::sync::LazyLock::new(|| {
        register_histogram_vec!(
            "dns_response_time_seconds",
            "Response time of DNS requests, whether valid or invalid.",
            &["protocol"],
            RESPONSE_TIME_BUCKETS.to_vec()
        )
        .unwrap()
    });

pub static DNS_QUESTIONS_TOTAL: std::sync::LazyLock<IntCounterVec> =
    std::sync::LazyLock::new(|| {
        register_int_counter_vec!(
            opts!(
                "dns_questions_total",
                "Total number of DNS questions received (a request may have multiple questions)."
            ),
            &["rd", "qtype", "qclass"]
        )
        .unwrap()
    });

pub static DNS_QUESTION_PROCESSING_TIME_SECONDS: std::sync::LazyLock<HistogramVec> =
    std::sync::LazyLock::new(|| {
        register_histogram_vec!(
            "dns_question_processing_time_seconds",
            "Time spent processing a DNS question (a request may have multiple questions).",
            &["rd", "qtype", "class"],
            PROCESSING_TIME_BUCKETS.to_vec()
        )
        .unwrap()
    });

pub static DNS_RESOLVER_AUTHORITATIVE_HIT_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(opts!(
            "dns_resolver_authoritative_hit_total",
            "Total number of hits of local authoritative data (not including blocked domains)."
        ),)
        .unwrap()
    });

pub static DNS_RESOLVER_OVERRIDE_HIT_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(opts!(
            "dns_resolver_override_hit_total",
            "Total number of hits of local override data (not including blocked domains)."
        ),)
        .unwrap()
    });

pub static DNS_RESOLVER_BLOCKED_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(opts!(
            "dns_resolver_blocked_total",
            "Total number of queries which have been blocked."
        ),)
        .unwrap()
    });

pub static DNS_RESOLVER_CACHE_HIT_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(opts!(
            "dns_resolver_cache_hit_total",
            "Total number of cache hits."
        ),)
        .unwrap()
    });

pub static DNS_RESOLVER_CACHE_MISS_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(opts!(
            "dns_resolver_cache_miss_total",
            "Total number of cache misses."
        ),)
        .unwrap()
    });

pub static DNS_RESOLVER_NAMESERVER_HIT_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(opts!(
            "dns_resolver_nameserver_hit_total",
            "Total number of hits when calling an upstream nameserver."
        ),)
        .unwrap()
    });

pub static DNS_RESOLVER_NAMESERVER_MISS_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(opts!(
            "dns_resolver_nameserver_miss_total",
            "Total number of misses when calling an upstream nameserver."
        ),)
        .unwrap()
    });

pub static CACHE_SIZE: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!(opts!("cache_size", "Number of records in the cache.")).unwrap()
});

pub static CACHE_OVERFLOW_COUNT: std::sync::LazyLock<IntCounter> = std::sync::LazyLock::new(|| {
    register_int_counter!(opts!(
        "cache_overflow_count",
        "Number of times the cache has overflowed."
    ))
    .unwrap()
});

pub static CACHE_EXPIRED_TOTAL: std::sync::LazyLock<IntCounter> = std::sync::LazyLock::new(|| {
    register_int_counter!(opts!(
        "cache_expired_total",
        "Number of records which have been expired from the cache."
    ))
    .unwrap()
});

pub static CACHE_PRUNED_TOTAL: std::sync::LazyLock<IntCounter> = std::sync::LazyLock::new(|| {
    register_int_counter!(opts!(
        "cache_pruned_total",
        "Number of records which have been pruned from the cache due to overflow."
    ))
    .unwrap()
});

async fn get_metrics() -> (StatusCode, String) {
    match TextEncoder::new().encode_to_string(&prometheus::gather()) {
        Ok(metrics_str) => (StatusCode::OK, metrics_str),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

pub async fn serve_prometheus_endpoint_task(address: SocketAddr) -> std::io::Result<()> {
    let app = axum::Router::new().route("/metrics", routing::get(get_metrics));
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
