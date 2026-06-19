//! Instrumented HTTP client.
//!
//! Uses [`reqwest`] internally.

mod cb;
mod config;
mod errors;
mod metrics;
mod middleware;
mod retry;
mod tracing;

pub use self::{
    cb::{CircuitBreakerMiddleware, CircuitBreakerRejection},
    config::HttpClientConfig,
    errors::HttpClientError,
    metrics::MetricsMiddleware,
    retry::{
        BaseBackoffPolicy, BaseRetryMiddleware, ExponentialBackoffPolicy,
        ExponentialRetryMiddleware, RetryPolicyKind,
    },
    tracing::{DisableOtelPropagation, TracingMiddleware},
};
pub use reqwest_middleware::ClientWithMiddleware;
pub use reqwest_middleware::Error as ReqwestMiddlewareError;
pub use reqwest_middleware::reqwest::Error as ReqwestError;
