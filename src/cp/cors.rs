use super::CpState;
use axum::{
    extract::{Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

pub async fn cors_middleware(
    State(state): State<Arc<CpState>>,
    req: Request,
    next: Next,
) -> Response {
    cors_with_origin(&state.config.web_origin, req, next).await
}

async fn cors_with_origin(allowed_origin: &str, req: Request, next: Next) -> Response {
    let request_origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let method = req.method().clone();

    // 1. Handle preflight (OPTIONS)
    if method == Method::OPTIONS {
        if let Some(origin) = &request_origin {
            if origin == allowed_origin {
                return Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed_origin)
                    .header(
                        header::ACCESS_CONTROL_ALLOW_METHODS,
                        "GET, POST, PUT, DELETE, OPTIONS",
                    )
                    .header(
                        header::ACCESS_CONTROL_ALLOW_HEADERS,
                        "Authorization, Content-Type",
                    )
                    .header(header::ACCESS_CONTROL_MAX_AGE, "86400")
                    .header(header::VARY, "Origin")
                    .body(axum::body::Body::empty())
                    .unwrap()
                    .into_response();
            }
        }
        return StatusCode::BAD_REQUEST.into_response();
    }

    // 2. Normal request
    let mut response = next.run(req).await;

    if let Some(origin) = &request_origin {
        if origin == allowed_origin {
            let headers = response.headers_mut();
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                header::HeaderValue::from_str(allowed_origin).unwrap(),
            );
            headers.append(header::VARY, header::HeaderValue::from_static("Origin"));
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware, routing::get, Router};
    use tower::ServiceExt;

    async fn test_cors(
        State(origin): State<Arc<String>>,
        request: Request,
        next: Next,
    ) -> Response {
        cors_with_origin(origin.as_str(), request, next).await
    }

    fn create_test_router(web_origin: &str) -> Router {
        let origin = Arc::new(web_origin.to_string());
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&origin),
                test_cors,
            ))
            .with_state(origin)
    }

    #[tokio::test]
    async fn preflight_options_allowed_origin_gets_cors_headers() {
        let router = create_test_router("https://kiokuu.com");
        let req = axum::http::Request::builder()
            .method(Method::OPTIONS)
            .uri("/test")
            .header(header::ORIGIN, "https://kiokuu.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://kiokuu.com"
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap(),
            "GET, POST, PUT, DELETE, OPTIONS"
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .unwrap(),
            "Authorization, Content-Type"
        );
        assert_eq!(resp.headers().get(header::VARY).unwrap(), "Origin");
    }

    #[tokio::test]
    async fn get_with_allowed_origin_echoes_origin_and_vary() {
        let router = create_test_router("https://kiokuu.com");
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::ORIGIN, "https://kiokuu.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://kiokuu.com"
        );
        assert_eq!(resp.headers().get(header::VARY).unwrap(), "Origin");
    }

    #[tokio::test]
    async fn disallowed_origin_gets_no_cors_headers() {
        let router = create_test_router("https://kiokuu.com");
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::ORIGIN, "https://evil.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }

    #[tokio::test]
    async fn delete_and_authorization_header_allowed_in_preflight() {
        let router = create_test_router("https://kiokuu.com");
        let req = axum::http::Request::builder()
            .method(Method::OPTIONS)
            .uri("/test")
            .header(header::ORIGIN, "https://kiokuu.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "DELETE")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://kiokuu.com"
        );
        assert!(resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("DELETE"));
        assert!(resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Authorization"));
    }

    #[tokio::test]
    async fn put_allowed_in_preflight() {
        let router = create_test_router("https://kiokuu.com");
        let req = axum::http::Request::builder()
            .method(Method::OPTIONS)
            .uri("/test")
            .header(header::ORIGIN, "https://kiokuu.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
            .header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization,content-type",
            )
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap()
            .split(',')
            .any(|method| method.trim() == "PUT"));
    }
}
