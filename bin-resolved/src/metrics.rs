use actix_web::{get, http::header::ContentType, App, HttpResponse, HttpServer, Responder};
use lazy_static::lazy_static;
use prometheus::TextEncoder;
use std::net::Ipv4Addr;

lazy_static! {}

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
