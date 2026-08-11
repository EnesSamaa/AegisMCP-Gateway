//! OpenTelemetry/Tracing context propagation middleware.

use super::request_id::X_REQUEST_ID;
use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tracing::Instrument;

/// Tower layer for instrumenting requests with tracing spans.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingLayer;

impl TracingLayer {
    /// Creates a new `TracingLayer`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for TracingLayer {
    type Service = TracingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TracingService { inner }
    }
}

/// Tower service for span instrumentation.
#[derive(Debug, Clone)]
pub struct TracingService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for TracingService<S>
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

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let req_id = req
            .headers()
            .get(X_REQUEST_ID)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_owned();

        let span = tracing::info_span!(
            "mcp_request",
            method = %req.method(),
            uri = %req.uri(),
            version = ?req.version(),
            request_id = %req_id,
        );

        let fut = self.inner.call(req);

        Box::pin(async move { fut.instrument(span).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_tracing_layer() {
        let service = tower::service_fn(|_req: Request<String>| async move {
            Ok::<_, std::convert::Infallible>(Response::new(String::new()))
        });

        let mut layer = TracingLayer::new().layer(service);
        let req = Request::builder().body(String::new()).unwrap();

        let res = layer.ready().await.unwrap().call(req).await;
        assert!(res.is_ok());
    }
}
