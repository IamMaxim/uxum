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

pub use reqwest_middleware::{
    ClientWithMiddleware, Error as ReqwestMiddlewareError, reqwest::Error as ReqwestError,
};

pub use self::{
    cb::{CircuitBreakerMiddleware, CircuitBreakerRejection},
    config::HttpClientConfig,
    errors::HttpClientError,
    metrics::MetricsMiddleware,
    retry::{
        BaseRetryMiddleware, ExponentialBackoffPolicy, ExponentialRetryMiddleware,
        FixedIntervalPolicy, RetryPolicyKind,
    },
    tracing::{DisableOtelPropagation, TracingMiddleware},
};
use crate::{builder::app::AppBuilderError, config::AppConfig, metrics::MetricsState};

impl AppConfig {
    /// Build and return configured [`reqwest`] HTTP client with distributed tracing support.
    ///
    /// # Errors
    ///
    /// Returns `Err` if metrics registry or HTTP client could not be initialized.
    pub async fn http_client(
        &self,
        name: impl AsRef<str>,
        metrics: Option<&MetricsState>,
    ) -> Result<reqwest_middleware::ClientWithMiddleware, AppBuilderError> {
        let name = name.as_ref();
        match self.http_clients.get(name).cloned() {
            Some(mut cfg) => {
                if let Some(app_name) = &self.app_name {
                    cfg.with_app_name(app_name);
                }
                if let Some(app_version) = &self.app_version {
                    cfg.with_app_version(app_version);
                }
                let metrics = metrics
                    .or(self.metrics_state.as_ref())
                    .map(|m| m.client_metrics(name));
                cfg.to_client(metrics).await.map_err(Into::into)
            }
            None => Err(AppBuilderError::HttpClientAbsent(name.to_string())),
        }
    }

    /// Same as [`Self::http_client`], but returns default client if there is no configuration
    /// available.
    ///
    /// # Errors
    ///
    /// Returns `Err` if metrics registry or HTTP client could not be initialized.
    pub async fn http_client_or_default(
        &self,
        name: impl AsRef<str>,
        metrics: Option<&MetricsState>,
    ) -> Result<reqwest_middleware::ClientWithMiddleware, AppBuilderError> {
        let name = name.as_ref();
        match self.http_client(name, metrics).await {
            Ok(client) => Ok(client),
            Err(AppBuilderError::HttpClientAbsent(_)) => {
                let mut cfg = HttpClientConfig::default();
                if let Some(app_name) = &self.app_name {
                    cfg.with_app_name(app_name);
                }
                if let Some(app_version) = &self.app_version {
                    cfg.with_app_version(app_version);
                }
                let metrics = metrics
                    .or(self.metrics_state.as_ref())
                    .map(|m| m.client_metrics(name));
                cfg.to_client(metrics).await.map_err(Into::into)
            }
            Err(err) => Err(err),
        }
    }
}
