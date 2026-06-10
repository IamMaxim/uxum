//! Handle object to start, stop and control the service.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum_server::{Handle as AxumHandle, service::MakeService};
use futures::{StreamExt, TryFutureExt, stream::FuturesUnordered};
use opentelemetry::{metrics::MeterProvider as _, trace::TracerProvider as _};
use opentelemetry_sdk::{
    metrics::SdkMeterProvider,
    trace::{SdkTracerProvider, Tracer},
};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, debug_span, error, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_record_hierarchical::HierarchicalRecord;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    builder::server::{ServerBuilder, ServerKind},
    config::AppConfig,
    crypto::ensure_default_crypto_provider,
    errors::IoError,
    lifecycle::{LifecycleContext, LifecycleParticipant},
    metrics::{MetricsState, gather_runtime_metrics},
    notify::ServiceNotifier,
    signal::{SignalError, SignalStream},
};

/// Error type returned by uxum handle.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HandleError {
    /// Error while setting up logging.
    #[error(transparent)]
    Logging(#[from] crate::logging::LoggingError),
    /// Error while setting up trace collection and propagation.
    #[error(transparent)]
    Tracing(#[from] crate::tracing::TracingError),
    /// Error while setting up metrics collection and propagation.
    #[error(transparent)]
    Metrics(#[from] crate::metrics::MetricsError),
    /// Error while building HTTP server.
    #[error(transparent)]
    ServerBuilder(#[from] crate::builder::server::ServerBuilderError),
    /// Error running HTTP server.
    #[error("HTTP server error: {0}")]
    Server(IoError),
    /// Error initializing crypto provider.
    #[error("Error initializing crypto provider")]
    InitTls,
    /// Error running HTTPS server.
    #[error("HTTPS server error: {0}")]
    TlsServer(IoError),
    /// Error running SPIFFE HTTPS server.
    #[cfg(feature = "spiffe")]
    #[error("SPIFFE HTTPS server error: {0}")]
    SpiffeServer(IoError),
    /// Server task error.
    #[error("Server task error: {0}")]
    ServerTask(#[from] tokio::task::JoinError),
    /// No server is currently running.
    #[error("No server is currently running")]
    NotRunning,
    /// Signal handler error.
    #[error(transparent)]
    SignalHandler(#[from] SignalError),
    /// Custom error from application initialization.
    #[error("Custom error: {0}")]
    Custom(Box<dyn std::error::Error + Send + Sync>),
    /// Error from a lifecycle participant.
    #[error(transparent)]
    Lifecycle(#[from] crate::lifecycle::LifecycleError),
}

impl HandleError {
    /// Wrap custom application initialization error.
    #[must_use]
    pub fn custom<T>(err: T) -> Self
    where
        T: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Custom(err.into())
    }
}

/// Shutdown stage relative to the HTTP server drain.
#[derive(Clone, Copy, Debug)]
enum ShutdownStage {
    /// Before the server stops accepting / drains in-flight requests.
    PreDrain,
    /// After the server has fully drained.
    PostDrain,
}

/// Handle for starting and controlling the server.
///
/// Unwritten logs will be flushed when dropping this object. This might help even in case of a
/// panic.
#[allow(dead_code)]
#[non_exhaustive]
pub struct Handle {
    /// Cancellation token for auxillary tasks.
    token: CancellationToken,
    /// Token used to request orchestrated graceful shutdown.
    shutdown_trigger: CancellationToken,
    /// Registered lifecycle participants.
    participants: Vec<Arc<dyn LifecycleParticipant>>,
    /// Application name, passed to lifecycle participants.
    app_name: Option<String>,
    /// Application version, passed to lifecycle participants.
    app_version: Option<String>,
    /// Guards for [`tracing_appender::non_blocking::NonBlocking`].
    buf_guards: Vec<WorkerGuard>,
    /// Tracing pipeline.
    tracer: Option<Tracer>,
    /// Tracing provider.
    tracer_provider: Option<SdkTracerProvider>,
    /// Metrics provider.
    metrics_provider: Option<SdkMeterProvider>,
    /// Internal [`axum_server`] control handle.
    handle: AxumHandle<SocketAddr>,
    /// Service supervisor notification.
    notify: ServiceNotifier,
    /// Service supervisor notification task.
    service_watchdog: Option<JoinHandle<()>>,
    /// UNIX signal handler task.
    signal_handler: Option<JoinHandle<()>>,
    /// Task join handles for started server tasks.
    server_tasks: Vec<JoinHandle<Result<(), HandleError>>>,
    /// Runtime metrics recording task.
    rt_metrics_task: Option<JoinHandle<()>>,
    /// Metrics container and factory.
    metrics: Option<MetricsState>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown_trigger.cancel();
        self.token.cancel();
        if let Some(provider) = self.metrics_provider.take() {
            if let Err(err) = provider.force_flush() {
                eprintln!("Error flushing metrics: {err}");
            }
            if let Err(err) = provider.shutdown() {
                eprintln!("Error shutting down OTel metrics provider: {err}")
            }
        }
        if let Some(provider) = self.tracer_provider.take() {
            if let Err(err) = provider.force_flush() {
                eprintln!("Error flushing spans: {err}");
            }
            if let Err(err) = provider.shutdown() {
                eprintln!("Error shutting down OTel tracing provider: {err}")
            }
        }
    }
}

impl Handle {
    /// Register a lifecycle participant.
    ///
    /// Must be called before [`Self::start`] or [`Self::run`]. Participants start
    /// in registration order and shut down in reverse registration order.
    pub fn register(&mut self, participant: Arc<dyn LifecycleParticipant>) -> &mut Self {
        self.participants.push(participant);
        self
    }

    /// Token that, when cancelled, initiates orchestrated graceful shutdown.
    #[must_use]
    pub fn shutdown_trigger(&self) -> CancellationToken {
        self.shutdown_trigger.clone()
    }

    /// Create the context passed to lifecycle participants.
    fn lifecycle_context(&self) -> LifecycleContext {
        let mut ctx = LifecycleContext::new(self.token.clone(), self.shutdown_trigger.clone());
        if let Some(name) = &self.app_name {
            ctx = ctx.with_app_name(name);
        }
        if let Some(version) = &self.app_version {
            ctx = ctx.with_app_version(version);
        }
        ctx
    }

    /// Spawn a task converting shutdown signals into a shutdown request.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a signal handler fails to register.
    fn spawn_signal_handler(&self) -> Result<JoinHandle<()>, HandleError> {
        let span = debug_span!("signal_handler");
        let mut sig = SignalStream::new()?;
        let trigger = self.shutdown_trigger.clone();
        Ok(tokio::spawn(
            async move {
                loop {
                    tokio::select! {
                        () = trigger.cancelled() => break,
                        next = sig.next() => match next {
                            Ok(sig) if sig.is_shutdown() => {
                                info!("received {}, initiating graceful shutdown", sig.name());
                                trigger.cancel();
                                break;
                            }
                            Ok(sig) => {
                                debug!("don't know what to do with signal {}, ignoring", sig.name());
                            }
                            Err(err) => {
                                error!("error in signal handler: {err}");
                            }
                        }
                    }
                }
            }
            .instrument(span),
        ))
    }

    /// Run one shutdown stage over all participants, in reverse registration order.
    ///
    /// Errors are logged and do not interrupt the sequence.
    async fn run_shutdown_stage(&self, stage: ShutdownStage) {
        let ctx = self.lifecycle_context();
        for participant in self.participants.iter().rev() {
            debug!(
                participant = participant.name(),
                "shutting down ({stage:?})"
            );
            let res = match stage {
                ShutdownStage::PreDrain => participant.shutdown_pre_drain(&ctx).await,
                ShutdownStage::PostDrain => participant.shutdown_post_drain(&ctx).await,
            };
            if let Err(err) = res {
                error!(
                    participant = participant.name(),
                    "error during shutdown ({stage:?}): {err}"
                );
            }
        }
    }

    /// Best-effort unwind of partially started participants (both stages, reverse order).
    async fn unwind_participants(
        participants: &[Arc<dyn LifecycleParticipant>],
        ctx: &LifecycleContext,
    ) {
        for participant in participants.iter().rev() {
            if let Err(err) = participant.shutdown_pre_drain(ctx).await {
                error!(
                    participant = participant.name(),
                    "error during unwind: {err}"
                );
            }
        }
        for participant in participants.iter().rev() {
            if let Err(err) = participant.shutdown_post_drain(ctx).await {
                error!(
                    participant = participant.name(),
                    "error during unwind: {err}"
                );
            }
        }
    }

    /// Set up background service tasks.
    ///
    /// # Errors
    ///
    /// Returns `Err` if signal handler registration fails.
    fn prepare(&mut self) -> Result<(), HandleError> {
        if self.signal_handler.is_none() {
            let signal_handler = match self.spawn_signal_handler() {
                Ok(sh) => sh,
                Err(err) => {
                    self.notify.custom_status(err.to_string());
                    return Err(err);
                }
            };
            self.signal_handler = Some(signal_handler);
        }
        if self.service_watchdog.is_none() {
            self.service_watchdog = Some(tokio::spawn(self.notify.watchdog_task()));
        }
        Ok(())
    }

    /// Start axum server tasks.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a server fails to bind or start.
    async fn start_servers<A>(
        &mut self,
        servers: Vec<ServerBuilder>,
        app: A,
    ) -> Result<(), HandleError>
    where
        A: MakeService<SocketAddr, http::Request<hyper::body::Incoming>>
            + tower::Service<SocketAddr>
            + Clone
            + Send
            + 'static,
        A::Response: tower::Service<http::Request<hyper::body::Incoming>>,
        A::MakeFuture: Send,
    {
        for server in servers {
            self.start_server(server, app.clone()).await?;
        }
        Ok(())
    }

    /// Start single axum server task.
    async fn start_server<A>(&mut self, server: ServerBuilder, app: A) -> Result<(), HandleError>
    where
        A: MakeService<SocketAddr, http::Request<hyper::body::Incoming>>
            + tower::Service<SocketAddr>
            + Clone
            + Send
            + 'static,
        A::Response: tower::Service<http::Request<hyper::body::Incoming>>,
        A::MakeFuture: Send,
    {
        let task = match server.kind().clone() {
            ServerKind::Plain => {
                let task = server
                    .build()
                    .await
                    .inspect_err(|err| self.notify.custom_status(err.to_string()))?
                    .handle(self.handle.clone())
                    .serve(app)
                    .map_err(|err| HandleError::Server(err.into()));
                tokio::spawn(task)
            }
            ServerKind::Tls { tls } => {
                ensure_default_crypto_provider();
                let task = server
                    .build_tls(&tls)
                    .await
                    .inspect_err(|err| self.notify.custom_status(err.to_string()))?
                    .handle(self.handle.clone())
                    .serve(app)
                    .map_err(|err| HandleError::TlsServer(err.into()));
                tokio::spawn(task)
            }
            #[cfg(feature = "spiffe")]
            ServerKind::Spiffe { spiffe } => {
                ensure_default_crypto_provider();
                let task = server
                    .build_spiffe(&spiffe, self.metrics.as_ref().map(|m| m.spiffe_metrics()))
                    .await
                    .inspect_err(|err| self.notify.custom_status(err.to_string()))?
                    .handle(self.handle.clone())
                    .serve(app)
                    .map_err(|err| HandleError::SpiffeServer(err.into()));
                tokio::spawn(task)
            }
        };
        self.server_tasks.push(task);
        Ok(())
    }

    /// Start the server in the background, running lifecycle participants around the listen point.
    ///
    /// Participants are started in registration order before the server begins listening
    /// (`start_pre_listen`), and again after it is accepting connections (`start_post_listen`).
    /// On failure, already-started participants are unwound via both shutdown stages.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// * Signal handler registration fails.
    /// * A lifecycle participant fails to start.
    /// * Server tasks fail to initialize.
    pub async fn start<A>(&mut self, servers: Vec<ServerBuilder>, app: A) -> Result<(), HandleError>
    where
        A: MakeService<SocketAddr, http::Request<hyper::body::Incoming>>
            + tower::Service<SocketAddr>
            + Clone
            + Send
            + 'static,
        A::Response: tower::Service<http::Request<hyper::body::Incoming>>,
        A::MakeFuture: Send,
    {
        self.prepare()?;
        let ctx = self.lifecycle_context();
        let mut started = 0_usize;
        for participant in &self.participants {
            debug!(participant = participant.name(), "starting (pre-listen)");
            if let Err(err) = participant.start_pre_listen(&ctx).await {
                error!(participant = participant.name(), "failed to start: {err}");
                Self::unwind_participants(&self.participants[..started], &ctx).await;
                return Err(err.into());
            }
            started += 1;
        }
        if let Err(err) = self.start_servers(servers, app).await {
            Self::unwind_participants(&self.participants[..started], &ctx).await;
            return Err(err);
        }
        for participant in &self.participants {
            debug!(participant = participant.name(), "starting (post-listen)");
            if let Err(err) = participant.start_post_listen(&ctx).await {
                error!(participant = participant.name(), "failed to start: {err}");
                self.abort();
                Self::unwind_participants(&self.participants, &ctx).await;
                return Err(err.into());
            }
        }
        self.notify.on_ready();
        Ok(())
    }

    /// Immediately shutdown the server.
    ///
    /// Calling this after the server tasks have already been consumed (e.g. after [`Self::wait`] returned) is a no-op that returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if one of server tasks finished with an error.
    pub async fn shutdown(&mut self) -> Result<(), HandleError> {
        self.shutdown_trigger.cancel();
        self.notify.on_shutdown();
        self.run_shutdown_stage(ShutdownStage::PreDrain).await;
        self.handle.shutdown();
        let mut result: Result<(), HandleError> = Ok(());
        let server_tasks = std::mem::take(&mut self.server_tasks);
        for res in futures::future::join_all(server_tasks).await {
            let task_result = res.map_err(HandleError::from).and_then(|inner| inner);
            if result.is_ok() {
                result = task_result;
            }
        }
        self.run_shutdown_stage(ShutdownStage::PostDrain).await;
        result
    }

    /// Gracefully shutdown the server, waiting for in-progress requests to finish.
    ///
    /// Triggers orchestrated shutdown: pre-drain lifecycle hooks run, then the HTTP
    /// server drains, then post-drain lifecycle hooks run.
    ///
    /// # Errors
    ///
    /// Returns `Err` if one of server tasks finished with an error.
    pub async fn graceful_shutdown(
        &mut self,
        graceful: Option<Duration>,
    ) -> Result<(), HandleError> {
        self.shutdown_trigger.cancel();
        self.wait(graceful).await
    }

    /// Immediately abort execution of the server.
    ///
    /// Unlike [`Self::graceful_shutdown`] and [`Self::wait`], this does **not**
    /// run lifecycle participant shutdown stages. Use it only when orderly
    /// cleanup is impossible or undesirable.
    pub fn abort(&mut self) {
        self.notify.on_shutdown();
        let server_tasks = std::mem::take(&mut self.server_tasks);
        for task in server_tasks {
            task.abort();
        }
    }

    /// Start the server and block execution until one of the server tasks exits or shutdown is
    /// requested. Runs all lifecycle shutdown stages around the HTTP server drain.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// * Signal handler registration fails.
    /// * A lifecycle participant fails to start.
    /// * One of server tasks finished with an error.
    pub async fn run<A>(
        &mut self,
        servers: Vec<ServerBuilder>,
        app: A,
        graceful: Option<Duration>,
    ) -> Result<(), HandleError>
    where
        A: MakeService<SocketAddr, http::Request<hyper::body::Incoming>>
            + tower::Service<SocketAddr>
            + Clone
            + Send
            + 'static,
        A::Response: tower::Service<http::Request<hyper::body::Incoming>>,
        A::MakeFuture: Send,
    {
        self.start(servers, app).await?;
        self.wait(graceful).await
    }

    /// Block execution until shutdown is requested or a server task exits, then run the
    /// orchestrated shutdown sequence (pre-drain hooks → HTTP drain → post-drain hooks).
    ///
    /// # Errors
    ///
    /// Returns `Err` if one of server tasks finished with an error.
    pub async fn wait(&mut self, graceful: Option<Duration>) -> Result<(), HandleError> {
        if self.server_tasks.is_empty() {
            return Err(HandleError::NotRunning);
        }
        let server_tasks = std::mem::take(&mut self.server_tasks);
        let mut tasks: FuturesUnordered<_> = server_tasks.into_iter().collect();
        let mut result: Result<(), HandleError> = Ok(());
        tokio::select! {
            () = self.shutdown_trigger.cancelled() => {}
            res = tasks.next() => {
                // A server task exited on its own; record its result and shut
                // everything else down.
                if let Some(res) = res {
                    result = res.map_err(HandleError::from).and_then(|inner| inner);
                }
                self.shutdown_trigger.cancel();
            }
        }
        self.notify.on_shutdown();
        self.run_shutdown_stage(ShutdownStage::PreDrain).await;
        self.handle.graceful_shutdown(graceful);
        while let Some(res) = tasks.next().await {
            let task_result = res.map_err(HandleError::from).and_then(|inner| inner);
            if result.is_ok() {
                result = task_result;
            }
        }
        self.run_shutdown_stage(ShutdownStage::PostDrain).await;
        result
    }

    /// Send custom status update notification to process supervisor.
    ///
    /// This call will just print the status message to log if uxum was compiled without `systemd`
    /// feature flag, or if supervisor wasn't detected at runtime.
    pub fn custom_status(&self, status: impl AsRef<str>) {
        self.notify.custom_status(status);
    }
}

impl AppConfig {
    /// Create application control handle and initialize logging and tracing subsystems.
    ///
    /// Returns a guard that shouldn't be dropped as long as there is a need for these subsystems.
    ///
    /// You can start, stop, control and monitor application with this handle.
    ///
    /// Note that this call configures and finalizes logging, tracing and metrics subsystems
    /// so if you want to make changes to those programmatically - you should do it before creating
    /// the [`Handle`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if any part of initializing of tracing or logging subsystems ends with and
    /// error.
    pub async fn handle(&mut self) -> Result<Handle, HandleError> {
        let token = CancellationToken::new();
        let (registry, buf_guards) = self.logging.make_registry()?;
        let otel_res = self.otel_resource();
        let (tracer, tracer_provider) = if let Some(tcfg) = self.tracing.as_mut() {
            let tracer_provider = tcfg.build_provider(otel_res.clone()).await?;
            let tracer = tracer_provider.tracer("uxum");
            let layer = tcfg.build_layer(&tracer);
            registry
                .with(layer)
                .with(HierarchicalRecord::default())
                .init();
            opentelemetry::global::set_text_map_propagator(
                opentelemetry_sdk::propagation::TraceContextPropagator::default(),
            );
            (Some(tracer), Some(tracer_provider))
        } else {
            registry.init();
            (None, None)
        };
        let (metrics, metrics_provider, rt_metrics_task) = if let Some(mcfg) = self.metrics.as_ref()
        {
            let (metrics_provider, prom_exporter) = mcfg.build_provider(otel_res).await?;
            let meter = metrics_provider.meter("uxum");
            let metrics_state = mcfg.build_state(&meter, prom_exporter);
            let rt_task = tokio::spawn(gather_runtime_metrics(
                metrics_state.clone(),
                mcfg.runtime_metrics_interval,
                token.clone(),
            ));
            self.metrics_state = Some(metrics_state.clone());
            opentelemetry::global::set_meter_provider(metrics_provider.clone());
            (Some(metrics_state), Some(metrics_provider), Some(rt_task))
        } else {
            (None, None, None)
        };
        let handle = AxumHandle::new();
        let notify = ServiceNotifier::new();
        Ok(Handle {
            token,
            shutdown_trigger: CancellationToken::new(),
            participants: Vec::new(),
            app_name: self.app_name.clone(),
            app_version: self.app_version.clone(),
            buf_guards,
            tracer,
            tracer_provider,
            metrics_provider,
            handle,
            notify,
            service_watchdog: None,
            signal_handler: None,
            server_tasks: Vec::with_capacity(1),
            rt_metrics_task,
            metrics,
        })
    }
}
