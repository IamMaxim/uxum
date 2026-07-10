//! A layer injected via `AppBuilder::with_global_layer` runs inside the
//! `CURRENT_REQUEST_ID` task-local scope (i.e. after RecordRequestIdLayer).

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use tower::{Layer, Service, ServiceExt};
use uxum::CURRENT_REQUEST_ID;
use uxum::{AppBuilder, AppConfig};

/// A tower layer whose service reads CURRENT_REQUEST_ID and records whether it
/// was in scope.
#[derive(Clone)]
struct ProbeLayer {
    saw_scope: Arc<Mutex<bool>>,
}

impl<S> Layer<S> for ProbeLayer {
    type Service = ProbeService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ProbeService {
            inner,
            saw_scope: self.saw_scope.clone(),
        }
    }
}

#[derive(Clone)]
struct ProbeService<S> {
    inner: S,
    saw_scope: Arc<Mutex<bool>>,
}

impl<S> Service<Request<Body>> for ProbeService<S>
where
    S: Service<Request<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // In scope iff the task-local is set (being set at all means
        // RecordRequestIdLayer wrapped us).
        let in_scope = CURRENT_REQUEST_ID.try_with(|_| ()).is_ok();
        *self.saw_scope.lock().unwrap() = in_scope;
        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

#[tokio::test]
async fn global_layer_runs_inside_request_id_scope() {
    let saw = Arc::new(Mutex::new(false));
    let probe = ProbeLayer {
        saw_scope: saw.clone(),
    };

    let cfg = AppConfig::default();
    let mut builder = AppBuilder::from_config(&cfg).expect("builder");
    builder.with_global_layer(move |router| router.layer(probe));
    let app = builder.build().expect("build");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let _ = resp;
    assert!(
        *saw.lock().unwrap(),
        "probe layer did not run inside CURRENT_REQUEST_ID scope"
    );
}
