//! PR1: a tracing-subscriber layer injected via `AppConfig::with_subscriber_layer`
//! observes events emitted after the registry is initialized.

use std::sync::{Arc, Mutex};

use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;
use uxum::AppConfig;

/// Records the target of each event it sees.
#[derive(Clone, Default)]
struct ProbeLayer {
    events: Arc<Mutex<Vec<String>>>,
}

impl<S> Layer<S> for ProbeLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        self.events
            .lock()
            .unwrap()
            .push(event.metadata().target().to_string());
    }
}

#[tokio::test]
async fn injected_layer_observes_events() {
    let probe = ProbeLayer::default();
    let seen = probe.events.clone();

    let mut app = AppConfig::default();
    app.with_subscriber_layer(probe);
    // handle() builds and `.init()`s the registry, installing the probe layer.
    let _handle = app.handle().await.expect("handle");

    tracing::info!(target: "pr1_probe", "hello");
    assert!(
        seen.lock().unwrap().iter().any(|t| t == "pr1_probe"),
        "probe layer did not observe the event; saw: {:?}",
        seen.lock().unwrap()
    );
}
