//! Service probe and maintenance mode API endpoints.

use std::{
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{
    error_handling::HandleErrorLayer,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{self, Router},
};
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tracing::{debug_span, info};

use crate::{
    auth::{AuthExtractor, AuthLayer, AuthProvider},
    behavior::{AppBehavior, StandardAppBehavior},
    builder::app::error_handler,
    watchdog::{Watchdog, WatchdogConfig},
};

/// Pluggable health source feeding service probes.
///
/// Register implementations via `AppBuilder::with_health_source`. All registered
/// sources are AND-ed together with the built-in maintenance flag (readiness) and
/// runtime watchdog (liveness).
pub trait HealthSource: std::fmt::Debug + Send + Sync + 'static {
    /// Source name, used in logs.
    fn name(&self) -> &str;

    /// Whether the component is ready to serve traffic (readiness probe).
    fn is_ready(&self) -> bool {
        true
    }

    /// Whether the component is functioning at all (liveness probe).
    fn is_alive(&self) -> bool {
        true
    }
}

/// Configuration for service probes and management mode API.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ProbeConfig {
    /// URL path for readiness probe.
    #[serde(default = "ProbeConfig::default_readiness_path")]
    readiness_path: String,
    /// URL path for liveness probe.
    #[serde(default = "ProbeConfig::default_liveness_path")]
    liveness_path: String,
    /// URL path to enable maintenance mode.
    #[serde(default = "ProbeConfig::default_maintenance_on_path")]
    maintenance_on_path: String,
    /// URL path to disable maintenance mode.
    #[serde(default = "ProbeConfig::default_maintenance_off_path")]
    maintenance_off_path: String,
    /// Runtime watchdog configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    watchdog: Option<WatchdogConfig>,
    #[serde(default)]
    start_in_maintenance: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            readiness_path: Self::default_readiness_path(),
            liveness_path: Self::default_liveness_path(),
            maintenance_on_path: Self::default_maintenance_on_path(),
            maintenance_off_path: Self::default_maintenance_off_path(),
            watchdog: Some(WatchdogConfig::default()),
            start_in_maintenance: false,
        }
    }
}

impl ProbeConfig {
    /// Default value for [`Self::readiness_path`].
    #[must_use]
    #[inline]
    fn default_readiness_path() -> String {
        "/probe/ready".into()
    }

    /// Default value for [`Self::liveness_path`].
    #[must_use]
    #[inline]
    fn default_liveness_path() -> String {
        "/probe/live".into()
    }

    /// Default value for [`Self::maintenance_on_path`].
    #[must_use]
    #[inline]
    fn default_maintenance_on_path() -> String {
        "/maintenance/on".into()
    }

    /// Default value for [`Self::maintenance_off_path`].
    #[must_use]
    #[inline]
    fn default_maintenance_off_path() -> String {
        "/maintenance/off".into()
    }

    /// Build Axum router containing all probe and maintenance methods.
    pub fn build_router<B: AppBehavior>(
        &self,
        behavior: B,
        auth_provider: Box<dyn AuthProvider>,
        auth_extractor: Box<dyn AuthExtractor>,
        health_sources: Vec<Arc<dyn HealthSource>>,
    ) -> Router {
        // TODO: add toggle for probes, and possibly for maintenance mode.
        let _span = debug_span!("build_probes").entered();
        let state = ProbeState::new(
            behavior,
            self.start_in_maintenance,
            self.watchdog.as_ref(),
            health_sources,
        );
        Router::new()
            .route(&self.readiness_path, routing::get(readiness_probe))
            .route(&self.liveness_path, routing::get(liveness_probe))
            .merge(
                Router::new()
                    .route(&self.maintenance_on_path, routing::post(maintenance_on))
                    .route(&self.maintenance_off_path, routing::post(maintenance_off))
                    .layer(
                        ServiceBuilder::new()
                            .layer(HandleErrorLayer::new(error_handler))
                            .layer(AuthLayer::new(
                                &["maintenance"],
                                auth_provider,
                                auth_extractor,
                            )),
                    ),
            )
            .with_state(state)
    }
}

/// Shared state for probes and maintenance mode API.
#[derive(Clone)]
pub struct ProbeState<B>(Arc<ProbeStateInner<B>>);

impl<B> Deref for ProbeState<B> {
    type Target = ProbeStateInner<B>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for ProbeState<StandardAppBehavior> {
    fn default() -> Self {
        Self(Arc::new(ProbeStateInner {
            behavior: StandardAppBehavior,
            in_maintenance: AtomicBool::new(true),
            watchdog: None,
            health_sources: Vec::new(),
        }))
    }
}

impl<B> ProbeState<B> {
    /// Create new [`ProbeState`] with optional [`WatchdogConfig`] and external health sources.
    #[must_use]
    pub fn new(
        behavior: B,
        in_maint: bool,
        watchdog: Option<&WatchdogConfig>,
        health_sources: Vec<Arc<dyn HealthSource>>,
    ) -> Self {
        Self(Arc::new(ProbeStateInner {
            behavior,
            in_maintenance: AtomicBool::new(in_maint),
            watchdog: watchdog.map(|wc| {
                let mut watchdog: Watchdog = wc.clone().into();
                watchdog.start();
                watchdog
            }),
            health_sources,
        }))
    }
}

/// Inner struct for probes/maintenance shared state.
pub struct ProbeStateInner<B> {
    behavior: B,
    /// Maintenance mode flag.
    in_maintenance: AtomicBool,
    /// Optional runtime watchdog for use in liveness probes.
    watchdog: Option<Watchdog>,
    /// External health sources aggregated into probe responses.
    health_sources: Vec<Arc<dyn HealthSource>>,
}

impl<B> ProbeStateInner<B> {
    /// Aggregate readiness over the maintenance flag and all health sources.
    pub(crate) fn is_ready(&self) -> bool {
        // Relaxed: probes are polled independently; no cross-location ordering to protect.
        !self.in_maintenance.load(Ordering::Relaxed)
            && self.health_sources.iter().all(|src| src.is_ready())
    }

    /// Aggregate liveness over the watchdog and all health sources.
    pub(crate) fn is_alive(&self) -> bool {
        self.watchdog.as_ref().is_none_or(Watchdog::is_alive)
            && self.health_sources.iter().all(|src| src.is_alive())
    }
}

/// Readiness probe handler.
///
/// For use in k8s-like deployments.
async fn readiness_probe<B: AppBehavior>(state: State<ProbeState<B>>) -> Response {
    match state.is_ready() {
        true => state.behavior.readiness_probe().await.into_response(),
        false => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// Liveness probe handler.
///
/// For use in k8s-like deployments.
async fn liveness_probe<B: AppBehavior>(state: State<ProbeState<B>>) -> Response {
    match state.is_alive() {
        true => state.behavior.liveness_probe().await.into_response(),
        false => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// Enable maintenance mode.
async fn maintenance_on<B>(state: State<ProbeState<B>>) -> impl IntoResponse {
    if !state.in_maintenance.swap(true, Ordering::Relaxed) {
        info!("maintenance mode enabled");
    }
    StatusCode::OK
}

/// Disable maintenance mode.
async fn maintenance_off<B>(state: State<ProbeState<B>>) -> impl IntoResponse {
    if state.in_maintenance.swap(false, Ordering::Relaxed) {
        info!("maintenance mode disabled");
    }
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[derive(Debug)]
    struct FakeSource {
        ready: AtomicBool,
        alive: AtomicBool,
    }

    impl FakeSource {
        fn new(ready: bool, alive: bool) -> Arc<Self> {
            Arc::new(Self {
                ready: AtomicBool::new(ready),
                alive: AtomicBool::new(alive),
            })
        }
    }

    impl HealthSource for FakeSource {
        fn name(&self) -> &str {
            "fake"
        }
        fn is_ready(&self) -> bool {
            self.ready.load(Ordering::Relaxed)
        }
        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn readiness_aggregates_sources_and_maintenance() {
        let src = FakeSource::new(true, true);
        let state = ProbeState::new(
            StandardAppBehavior,
            false,
            None,
            vec![src.clone() as Arc<dyn HealthSource>],
        );
        assert!(state.is_ready());
        src.ready.store(false, Ordering::Relaxed);
        assert!(!state.is_ready());
        // Maintenance overrides even ready sources.
        src.ready.store(true, Ordering::Relaxed);
        let state = ProbeState::new(
            StandardAppBehavior,
            true,
            None,
            vec![src as Arc<dyn HealthSource>],
        );
        assert!(!state.is_ready());
    }

    #[test]
    fn liveness_aggregates_sources() {
        let src = FakeSource::new(true, true);
        // No watchdog: liveness depends only on sources.
        let state = ProbeState::new(
            StandardAppBehavior,
            false,
            None,
            vec![src.clone() as Arc<dyn HealthSource>],
        );
        assert!(state.is_alive());
        src.alive.store(false, Ordering::Relaxed);
        assert!(!state.is_alive());
    }

    #[test]
    fn no_sources_preserves_old_behavior() {
        let state = ProbeState::new(StandardAppBehavior, false, None, Vec::new());
        assert!(state.is_ready());
        assert!(state.is_alive());
    }
}
