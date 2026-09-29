use lambda_http::{Body, Error, Request, Response, run, service_fn, tracing};

async fn handler(_req: Request) -> Result<Response<Body>, Error> {
    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"service":"ingest","status":"ok"}"#))?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();
    run(service_fn(handler)).await
}
