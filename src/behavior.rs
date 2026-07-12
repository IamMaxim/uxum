//! Trait used to customize application behaviors.

use std::{convert::Infallible, future::Future};

use axum::{
    BoxError,
    body::{Body, HttpBody},
    http::{Request, Response, StatusCode},
    response::IntoResponse,
    routing::MethodRouter,
};
use tower::{Layer, Service, layer::util::Identity};
use tracing::error;

use crate::{
    errors,
    layers::{rate::RateLimitError, timeout::TimeoutError},
};

/// Trait for customizing behaviors within [`crate::AppBuilder`].
///
/// Any trait element has a default implementation. You should implement only ones that
/// you need changed.
pub trait AppBehavior: Clone + Send + Sync + 'static {
    /// Customizable global layer for all handler services.
    fn layer<InSvc, InResp>(
        self,
    ) -> impl Layer<
        InSvc,
        Service = impl Service<
            Request<Body>,
            Response = Response<impl HttpBody<Data = bytes::Bytes, Error = BoxError> + Send>,
            Error = Infallible,
            Future = impl Send,
        > + Clone
                  + Send
                  + Sync,
    > + Clone
    + Send
    + Sync
    where
        InSvc: Service<Request<Body>, Response = Response<InResp>, Error = Infallible>
            + Clone
            + Send
            + Sync,
        InSvc::Future: Send,
        InResp: HttpBody<Data = bytes::Bytes, Error = BoxError> + Send,
        InResp::Data: Send,
    {
        // XXX: consider moving to `BoxLayer` in future versions.
        Identity::new()
    }

    /// Customizable code for readiness probe.
    fn readiness_probe(&self) -> impl Future<Output = impl IntoResponse> + Send {
        async { StatusCode::OK }
    }

    /// Customizable code for liveness probe.
    fn liveness_probe(&self) -> impl Future<Output = impl IntoResponse> + Send {
        async { StatusCode::OK }
    }

    /// Convert fallible handler service into error response.
    fn error_layer(rtr: MethodRouter<(), BoxError>) -> MethodRouter<(), Infallible> {
        rtr.handle_error(default_error_handler)
    }
}

/// Error handler for uxum-specific error types.
pub async fn default_error_handler(err: BoxError) -> Response<Body> {
    error!(error = err.to_string(), "error in handler");
    if let Some(rate_err) = err.downcast_ref::<RateLimitError>().cloned() {
        return rate_err.into_response();
    }
    if let Some(timeo_err) = err.downcast_ref::<TimeoutError>().cloned() {
        return timeo_err.into_response();
    }
    problemdetails::new(StatusCode::INTERNAL_SERVER_ERROR)
        .with_type(errors::TAG_UXUM_ERROR)
        .with_title(err.to_string())
        .into_response()
}

/// Standard application behavior, used by default.
#[derive(Clone)]
pub struct StandardAppBehavior;

impl AppBehavior for StandardAppBehavior {}
