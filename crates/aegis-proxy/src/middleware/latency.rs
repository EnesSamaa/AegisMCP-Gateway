//! Response latency tracking middleware.

use hyper::header::HeaderValue;
use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tower::{Layer, Service};

/// Header key for response latency in microseconds (`x-response-time-us`).
pub const X_RESPONSE_TIME_US: &str = "x-response-time-us";

/// Tower layer for recording microsecond response latency.
#[derive(Debug, Clone, Copy, Default)]
pub struct LatencyTrackingLayer;

impl LatencyTrackingLayer {
    /// Creates a new `LatencyTrackingLayer`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for LatencyTrackingLayer {
    type Service = LatencyTrackingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LatencyTrackingService { inner }
    }
}

/// Tower service for calculating and appending latency headers.
#[derive(Debug, Clone)]
pub struct LatencyTrackingService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for LatencyTrackingService<S>
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
        let start = Instant::now();
        let fut = self.inner.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            let elapsed_us = start.elapsed().as_micros();
            if let Ok(header_val) = HeaderValue::from_str(&elapsed_us.to_string()) {
                res.headers_mut().insert(X_RESPONSE_TIME_US, header_val);
            }
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_latency_tracking_header() {
        let service = tower::service_fn(|_req: Request<String>| async move {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            Ok::<_, std::convert::Infallible>(Response::new(String::new()))
        });

        let mut layer = LatencyTrackingLayer::new().layer(service);
        let req = Request::builder().body(String::new()).unwrap();

        let res = layer.ready().await.unwrap().call(req).await.unwrap();
        assert!(res.headers().contains_key(X_RESPONSE_TIME_US));
    }
}
