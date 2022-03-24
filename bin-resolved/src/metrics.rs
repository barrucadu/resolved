use actix_web::{get, http::header::ContentType, App, HttpResponse, HttpServer, Responder};
use lazy_static::lazy_static;
use prometheus::{
    opts, register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec,
    TextEncoder,
};
use std::net::Ipv4Addr;

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

lazy_static! {
    pub static ref DNS_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!(
            "dns_requests_total",
            "Total number of DNS requests received, whether valid or invalid."
        ),
        &["protocol"]
    )
    .unwrap();
    pub static ref DNS_RESPONSE_TIME_SECONDS: HistogramVec = register_histogram_vec!(
        "dns_response_time_seconds",
        "Response time of DNS requests, whether valid or invalid.",
        &["protocol"],
        RESPONSE_TIME_BUCKETS.to_vec()
    )
    .unwrap();
}

#[get("/metrics")]
async fn get_metrics() -> impl Responder {
    match TextEncoder::new().encode_to_string(&prometheus::gather()) {
        Ok(metrics_str) => {
            println!("[WEB] metrics request ok");
            HttpResponse::Ok()
                .content_type(ContentType::plaintext())
                .body(metrics_str)
        }
        Err(err) => {
            println!(
                "[WEB] [INTERNAL ERROR] could not serialise metrics: \"{:?}\"",
                err
            );
            HttpResponse::InternalServerError()
                .content_type(ContentType::plaintext())
                .body(err.to_string())
        }
    }
}

pub async fn serve_prometheus_endpoint_task(address: Ipv4Addr, port: u16) -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(get_metrics))
        .bind((address, port))?
        .run()
        .await
}
