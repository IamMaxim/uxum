//! Generic service lifecycle participation API.
//!
//! Companion crates (e.g. `uxum-tasks`) implement [`LifecycleParticipant`] to have
//! their startup and shutdown orchestrated by [`crate::Handle`], ordered around the
//! HTTP server's listen and drain points.
//!
//! Orchestrated sequence, as driven by [`crate::Handle::run`]:
//!
//! 1. [`LifecycleParticipant::start_pre_listen`] (registration order)
//! 2. HTTP server starts listening
//! 3. [`LifecycleParticipant::start_post_listen`] (registration order)
//! 4. … service runs until shutdown is requested …
//! 5. [`LifecycleParticipant::shutdown_pre_drain`] (reverse registration order)
//! 6. HTTP server graceful drain
//! 7. [`LifecycleParticipant::shutdown_post_drain`] (reverse registration order)

use async_trait::async_trait;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Error type returned by lifecycle participants.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LifecycleError {
    /// Participant failed to start.
    #[error("Lifecycle participant failed to start: {0}")]
    Start(Box<dyn std::error::Error + Send + Sync>),
    /// Participant failed to shut down cleanly.
    #[error("Lifecycle participant failed to shut down: {0}")]
    Shutdown(Box<dyn std::error::Error + Send + Sync>),
}

impl LifecycleError {
    /// Wrap a custom startup error.
    #[must_use]
    pub fn start<T>(err: T) -> Self
    where
        T: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Start(err.into())
    }

    /// Wrap a custom shutdown error.
    #[must_use]
    pub fn shutdown<T>(err: T) -> Self
    where
        T: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Shutdown(err.into())
    }
}

/// Context passed to lifecycle participants during startup.
#[derive(Clone, Debug)]
pub struct LifecycleContext {
    /// Root cancellation token of the service.
    root_token: CancellationToken,
    /// Trigger used to request service-wide graceful shutdown.
    shutdown_trigger: CancellationToken,
    /// Application name, if configured.
    app_name: Option<String>,
    /// Application version, if configured.
    app_version: Option<String>,
}

impl LifecycleContext {
    /// Create a new lifecycle context.
    ///
    /// Normally constructed by [`crate::Handle`]. Public so participants can be
    /// driven directly in tests or from other frameworks.
    #[must_use]
    pub fn new(root_token: CancellationToken, shutdown_trigger: CancellationToken) -> Self {
        Self {
            root_token,
            shutdown_trigger,
            app_name: None,
            app_version: None,
        }
    }

    /// Set application name.
    #[must_use]
    pub fn with_app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = Some(name.into());
        self
    }

    /// Set application version.
    #[must_use]
    pub fn with_app_version(mut self, version: impl Into<String>) -> Self {
        self.app_version = Some(version.into());
        self
    }

    /// Root cancellation token; cancelled when the service is torn down.
    #[must_use]
    pub fn root_token(&self) -> &CancellationToken {
        &self.root_token
    }

    /// Request service-wide graceful shutdown.
    ///
    /// Idempotent; safe to call from any task at any time after startup.
    pub fn request_shutdown(&self) {
        self.shutdown_trigger.cancel();
    }

    /// Whether service-wide shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_trigger.is_cancelled()
    }

    /// Application name, if configured.
    #[must_use]
    pub fn app_name(&self) -> Option<&str> {
        self.app_name.as_deref()
    }

    /// Application version, if configured.
    #[must_use]
    pub fn app_version(&self) -> Option<&str> {
        self.app_version.as_deref()
    }
}

/// A component whose startup and shutdown is orchestrated by [`crate::Handle`].
///
/// All methods have default no-op implementations. Implementations must tolerate
/// shutdown stages being invoked after a partial start (e.g. when another
/// participant failed during startup and the already-started ones are unwound):
/// `shutdown_pre_drain` and `shutdown_post_drain` may run even if only
/// `start_pre_listen` succeeded.
///
/// Shutdown-stage errors are logged by the orchestrator and do not stop the
/// shutdown sequence.
#[async_trait]
pub trait LifecycleParticipant: Send + Sync + 'static {
    /// Participant name, used in logs.
    fn name(&self) -> &str;

    /// Called before the HTTP server starts listening.
    async fn start_pre_listen(&self, ctx: &LifecycleContext) -> Result<(), LifecycleError> {
        let _ = ctx;
        Ok(())
    }

    /// Called after the HTTP server is accepting connections.
    async fn start_post_listen(&self, ctx: &LifecycleContext) -> Result<(), LifecycleError> {
        let _ = ctx;
        Ok(())
    }

    /// Called when shutdown begins, before the HTTP server graceful drain.
    async fn shutdown_pre_drain(&self) -> Result<(), LifecycleError> {
        Ok(())
    }

    /// Called after the HTTP server finished draining, before telemetry flush.
    async fn shutdown_post_drain(&self) -> Result<(), LifecycleError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Minimal;

    #[async_trait]
    impl LifecycleParticipant for Minimal {
        fn name(&self) -> &str {
            "minimal"
        }
    }

    #[tokio::test]
    async fn default_methods_are_noop_ok() {
        let p = Minimal;
        let ctx = LifecycleContext::new(CancellationToken::new(), CancellationToken::new());
        assert!(p.start_pre_listen(&ctx).await.is_ok());
        assert!(p.start_post_listen(&ctx).await.is_ok());
        assert!(p.shutdown_pre_drain().await.is_ok());
        assert!(p.shutdown_post_drain().await.is_ok());
    }

    #[test]
    fn request_shutdown_cancels_trigger() {
        let trigger = CancellationToken::new();
        let ctx = LifecycleContext::new(CancellationToken::new(), trigger.clone())
            .with_app_name("app")
            .with_app_version("1.0");
        assert!(!ctx.is_shutdown_requested());
        ctx.request_shutdown();
        assert!(trigger.is_cancelled());
        assert!(ctx.is_shutdown_requested());
        assert_eq!(ctx.app_name(), Some("app"));
        assert_eq!(ctx.app_version(), Some("1.0"));
    }
}
