//! api-fn: the authenticated HTTP API and the web client's static files.

mod app;
mod handlers;
mod reply;
mod routes;
mod web;

use std::sync::Arc;

use lambda_http::{Error, run, service_fn, tracing};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();
    let state = Arc::new(app::State::from_env().await?);
    run(service_fn(move |req| {
        let state = Arc::clone(&state);
        async move { app::handle(&state, req).await }
    }))
    .await
}
