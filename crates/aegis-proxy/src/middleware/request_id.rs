//! Request ID extraction and injection middleware.

use aegis_core::RequestId;
use hyper::header::HeaderValue;
use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Header key for request tracking (`x-request-id`).
pub const X_REQUEST_ID: &str = "x-request-id";

/// Tower layer for generating or extracting request IDs.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestIdLayer;

impl RequestIdLayer {
    /// Creates a new `RequestIdLayer`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService { inner }
    }
}

/// Tower service wrapping inner handler with request ID extraction/injection.
#[derive(Debug, Clone)]
pub struct RequestIdService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequestIdService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let req_id_str = req
            .headers()
            .get(X_REQUEST_ID)
            .and_then(|v| v.to_str().ok())
            .map_or_else(|| RequestId::new().to_string(), ToOwned::to_owned);

        let header_val =
            HeaderValue::from_str(&req_id_str).unwrap_or_else(|_| HeaderValue::from_static("req-fallback"));

        req.headers_mut().insert(X_REQUEST_ID, header_val.clone());

        let fut = self.inner.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            res.headers_mut().insert(X_REQUEST_ID, header_val);
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_request_id_injection() {
        let service = tower::service_fn(|req: Request<String>| async move {
            assert!(req.headers().contains_key(X_REQUEST_ID));
            Ok::<_, std::convert::Infallible>(Response::new(String::new()))
        });

        let mut layer = RequestIdLayer::new().layer(service);
        let req = Request::builder().body(String::new()).unwrap();

        let res = layer.ready().await.unwrap().call(req).await.unwrap();
        assert!(res.headers().contains_key(X_REQUEST_ID));
    }
}
