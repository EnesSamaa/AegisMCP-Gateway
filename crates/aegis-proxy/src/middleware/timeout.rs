//! Configurable request timeout middleware.

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{header::CONTENT_TYPE, Request, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{Layer, Service};

/// Tower layer for enforcing request execution timeouts.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutLayer {
    timeout_duration: Duration,
}

impl TimeoutLayer {
    /// Creates a new `TimeoutLayer` with the specified duration.
    #[must_use]
    pub const fn new(timeout_duration: Duration) -> Self {
        Self { timeout_duration }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = TimeoutService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimeoutService {
            inner,
            timeout_duration: self.timeout_duration,
        }
    }
}

/// Tower service wrapping handler in `tokio::time::timeout`.
#[derive(Debug, Clone)]
pub struct TimeoutService<S> {
    inner: S,
    timeout_duration: Duration,
}

impl<S, ReqBody> Service<Request<ReqBody>> for TimeoutService<S>
where
    S: Service<Request<ReqBody>, Response = Response<BoxBody<Bytes, hyper::Error>>>
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<crate::error::ProxyError> + Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = crate::error::ProxyError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let timeout_dur = self.timeout_duration;
        let fut = self.inner.call(req);

        Box::pin(async move {
            match tokio::time::timeout(timeout_dur, fut).await {
                Ok(Ok(res)) => Ok(res),
                Ok(Err(err)) => Err(err.into()),
                Err(_) => {
                    let err_payload = r#"{"jsonrpc":"2.0","error":{"code":-32011,"message":"Upstream request timeout exceeded"},"id":null}"#;
                    let body = Full::new(Bytes::from(err_payload))
                        .map_err(|_| -> hyper::Error { unreachable!() })
                        .boxed();

                    let resp = Response::builder()
                        .status(StatusCode::GATEWAY_TIMEOUT)
                        .header(CONTENT_TYPE, "application/json")
                        .body(body)
                        .map_err(crate::error::ProxyError::from)?;

                    Ok(resp)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_timeout_layer_success() {
        let service = tower::service_fn(|_req: Request<String>| async move {
            let body = Full::new(Bytes::from("ok"))
                .map_err(|_| -> hyper::Error { unreachable!() })
                .boxed();
            Ok::<_, crate::error::ProxyError>(Response::new(body))
        });

        let mut layer = TimeoutLayer::new(Duration::from_secs(1)).layer(service);
        let req = Request::builder().body(String::new()).unwrap();

        let res = layer.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_timeout_layer_expiry() {
        let service = tower::service_fn(|_req: Request<String>| async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let body = Full::new(Bytes::from("ok"))
                .map_err(|_| -> hyper::Error { unreachable!() })
                .boxed();
            Ok::<_, crate::error::ProxyError>(Response::new(body))
        });

        let mut layer = TimeoutLayer::new(Duration::from_millis(10)).layer(service);
        let req = Request::builder().body(String::new()).unwrap();

        let res = layer.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);
    }
}
