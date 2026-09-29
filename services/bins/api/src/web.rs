//! The web client's static files and its public config, served from the API's own URL (same
//! origin, so no CORS).

use lambda_http::http::StatusCode;
use lambda_http::{Body, Response};
use serde_json::json;

use crate::app::State;
use crate::reply;
use crate::routes::RouteId;

const INDEX_HTML: &str = include_str!("../../../web/index.html");
const APP_JS: &str = include_str!("../../../web/app.js");
const STYLE_CSS: &str = include_str!("../../../web/style.css");

const CSP: &str = "default-src 'self'; connect-src 'self' https://cognito-idp.ap-southeast-2.amazonaws.com; \
                   img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; \
                   base-uri 'none'; form-action 'none'";

fn asset(content_type: &str, body: &'static str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", content_type)
        .header("cache-control", "no-cache")
        .header("content-security-policy", CSP)
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("x-frame-options", "DENY")
        .body(Body::from(body))
        .expect("static headers are valid")
}

pub fn serve(state: &State, id: RouteId) -> Response<Body> {
    match id {
        RouteId::WebIndex => asset("text/html; charset=utf-8", INDEX_HTML),
        RouteId::WebJs => asset("text/javascript; charset=utf-8", APP_JS),
        RouteId::WebCss => asset("text/css; charset=utf-8", STYLE_CSS),
        RouteId::WebConfig => reply::json(
            StatusCode::OK,
            &json!({
                "region": state.web.region,
                "userPoolId": state.web.user_pool_id,
                "clientId": state.web.client_id,
            }),
        ),
        _ => reply::error(StatusCode::NOT_FOUND, "not_found"),
    }
}
