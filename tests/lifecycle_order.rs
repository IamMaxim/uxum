//! End-to-end test of lifecycle participant orchestration.
//!
//! NOTE: keep exactly ONE test in this file. `AppConfig::handle()` installs a
//! process-global tracing subscriber, which can only happen once per process.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use uxum::{
    AppBuilder, AppConfig, LifecycleContext, LifecycleError, LifecycleParticipant, ServerBuilder,
};

#[derive(Debug)]
struct Recorder {
    name: &'static str,
    log: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    fn record(&self, event: &str) {
        self.log
            .lock()
            .unwrap()
            .push(format!("{}:{event}", self.name));
    }
}

#[async_trait]
impl LifecycleParticipant for Recorder {
    fn name(&self) -> &str {
        self.name
    }
    async fn start_pre_listen(&self, _ctx: &LifecycleContext) -> Result<(), LifecycleError> {
        self.record("start_pre_listen");
        Ok(())
    }
    async fn start_post_listen(&self, _ctx: &LifecycleContext) -> Result<(), LifecycleError> {
        self.record("start_post_listen");
        Ok(())
    }
    async fn shutdown_pre_drain(&self, _ctx: &LifecycleContext) -> Result<(), LifecycleError> {
        self.record("shutdown_pre_drain");
        Ok(())
    }
    async fn shutdown_post_drain(&self, _ctx: &LifecycleContext) -> Result<(), LifecycleError> {
        self.record("shutdown_post_drain");
        Ok(())
    }
}

#[tokio::test]
async fn lifecycle_orchestration_order() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut app_cfg = AppConfig::default();
    let mut handle = app_cfg.handle().await.expect("handle init");
    handle.register(Arc::new(Recorder {
        name: "a",
        log: log.clone(),
    }));
    handle.register(Arc::new(Recorder {
        name: "b",
        log: log.clone(),
    }));
    let app = AppBuilder::new().build().expect("app build");
    let mut server = ServerBuilder::default();
    server.listen = "127.0.0.1:0".into();
    handle
        .start(vec![server], app.into_make_service())
        .await
        .expect("server start");
    // Not load-bearing: event ordering is deterministic; this just gives the listener a beat before we drain.
    tokio::time::sleep(Duration::from_millis(100)).await;
    handle
        .graceful_shutdown(Some(Duration::from_millis(500)))
        .await
        .expect("graceful shutdown");
    let events = log.lock().unwrap().clone();
    assert_eq!(
        events,
        vec![
            "a:start_pre_listen",
            "b:start_pre_listen",
            "a:start_post_listen",
            "b:start_post_listen",
            "b:shutdown_pre_drain",
            "a:shutdown_pre_drain",
            "b:shutdown_post_drain",
            "a:shutdown_post_drain",
        ]
    );
}
