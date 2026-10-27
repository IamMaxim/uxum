//! Rate limiting [`tower`] layer.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    marker::PhantomData,
    num::NonZeroU32,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use dashmap::DashMap;
use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock, QuantaClock, QuantaInstant},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
};
use pin_project::pin_project;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tower::{BoxError, Layer, Service};
use tracing::{trace_span, warn};

use crate::{
    errors,
    layers::util::{
        ExtractionError, KeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor, UserIdKeyExtractor,
    },
};

/// Error type returned by rate-limiting layer.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum RateLimitError {
    /// Extraction error.
    #[error(transparent)]
    Extraction(#[from] ExtractionError),
    /// Rate limit exceeded.
    #[error("Rate limit reached: available after {remaining_seconds} seconds")]
    LimitReached {
        /// Remaining seconds until method becomes available again.
        ///
        /// NOTE: Retry-After cannot be specified with fractional digits as per RFC 9110.
        remaining_seconds: u64,
    },
}

impl RateLimitError {
    /// HTTP status code for used for this error.
    fn http_status(&self) -> StatusCode {
        match self {
            Self::LimitReached { .. } => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response<Body> {
        let mut resp = problemdetails::new(self.http_status())
            .with_type(errors::TAG_UXUM_RATE_LIMIT)
            .with_title(self.to_string());
        if let Self::LimitReached { remaining_seconds } = self {
            resp = resp.with_value("retry_after", remaining_seconds);
        }
        resp.into_response()
    }
}

/// Configuration for rate-limiting layer.
///
/// Uses [`governor`] crate internally.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub struct HandlerRateLimitConfig {
    /// Key extractor used to find rate-limiting bucket.
    #[serde(default)]
    key: RateLimitKey,
    /// Sustained requests per second.
    rps: NonZeroU32,
    /// Maximum requests per second during burst.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    burst_rps: Option<NonZeroU32>,
    /// Duration of burst, used for bucket size calculation.
    #[serde(
        default = "HandlerRateLimitConfig::default_burst_duration",
        with = "humantime_serde"
    )]
    burst_duration: Duration,
    /// Quotas for individual keys, replacing the defaults above.
    ///
    /// Map keys are written the same way the extracted key is (for example, a user ID or an IP
    /// address). Not applicable to [`RateLimitKey::Global`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    overrides: BTreeMap<String, QuotaOverride>,
    // TODO: boolean - ignore extraction errors.
}

/// Quota replacing the default one for a single rate-limiting key.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub struct QuotaOverride {
    /// Sustained requests per second.
    rps: NonZeroU32,
    /// Maximum requests per second during burst.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    burst_rps: Option<NonZeroU32>,
    /// Duration of burst. Inherited from the enclosing limiter when not specified.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "humantime_serde"
    )]
    burst_duration: Option<Duration>,
}

impl HandlerRateLimitConfig {
    /// Default value for [`Self::burst_duration`].
    #[must_use]
    #[inline]
    fn default_burst_duration() -> Duration {
        Duration::from_secs(1)
    }

    /// Helper method to calculate governor burst size.
    pub fn burst_size(&self) -> NonZeroU32 {
        let rps = match self.burst_rps {
            Some(rps) if rps > self.rps => rps,
            _ => self.rps,
        };
        let seconds = self.burst_duration.as_secs_f64();
        NonZeroU32::new((seconds * f64::from(rps.get())).ceil() as u32).unwrap_or(self.rps)
    }

    /// Helper method for governor period calculation.
    pub fn period(&self) -> Duration {
        Duration::from_secs(1) / self.rps.get()
    }

    /// Create layer for use in [`tower`] services.
    pub fn make_layer<S, T>(&self) -> RateLimitLayer<S, T> {
        std::slice::from_ref(self).into()
    }

    /// Copy of this config with quota replaced by an override.
    fn with_override(&self, quota: &QuotaOverride) -> Self {
        Self {
            rps: quota.rps,
            burst_rps: quota.burst_rps,
            burst_duration: quota.burst_duration.unwrap_or(self.burst_duration),
            overrides: BTreeMap::new(),
            ..self.clone()
        }
    }
}

/// Deserialize either a single rate limit or a list of them.
pub(crate) fn deserialize_rate_limits<'de, D>(
    deserializer: D,
) -> Result<Vec<HandlerRateLimitConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(HandlerRateLimitConfig),
        Many(Vec<HandlerRateLimitConfig>),
    }

    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(limit) => vec![limit],
        OneOrMany::Many(limits) => limits,
    })
}

/// Method of key extraction for rate limiting.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
enum RateLimitKey {
    /// Global rate limit.
    #[default]
    Global,
    /// Per-peer-IP-address rate limit.
    PeerIp,
    /// Smart per-peer-IP-address rate limit.
    ///
    /// Same as [`RateLimitKey::PeerIp`], but accounts for addresses passed via
    /// `X-Forwarded-For` and similar headers.
    SmartIp,
    /// Per-authenticated-user-ID rate limit.
    UserId,
}

/// Rate-limiting [`tower`] layer.
pub struct RateLimitLayer<S, T> {
    /// Rate limiter configurations. A request has to pass all of them.
    configs: Vec<HandlerRateLimitConfig>,
    /// Inner service type.
    _phantom_service: PhantomData<S>,
    /// Request body type.
    _phantom_request: PhantomData<T>,
}

impl<S, T> From<&[HandlerRateLimitConfig]> for RateLimitLayer<S, T> {
    fn from(value: &[HandlerRateLimitConfig]) -> Self {
        // TODO: don't clone, but share, for runtime updates maybe?
        Self {
            configs: value.to_vec(),
            _phantom_service: PhantomData,
            _phantom_request: PhantomData,
        }
    }
}

impl<S, T> Layer<S> for RateLimitLayer<S, T>
where
    S: Service<Request<T>> + Send + 'static,
    T: Send + 'static,
{
    type Service = RateLimit<S, T>;

    fn layer(&self, service: S) -> Self::Service {
        RateLimit::new(service, &self.configs)
    }
}

/// Rate-limiting [`tower`] service.
pub struct RateLimit<S, T> {
    /// Inner service.
    inner: S,
    /// Rate limiters. A request has to pass all of them.
    limiters: Arc<[Box<dyn Limiter<T> + Send + Sync>]>,
}

impl<S, T> Clone for RateLimit<S, T>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            limiters: Arc::clone(&self.limiters),
        }
    }
}

impl<S, T> Service<Request<T>> for RateLimit<S, T>
where
    S: Service<Request<T>>,
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = RateLimitFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(res) => Poll::Ready(res.map_err(Into::into)),
        }
    }

    fn call(&mut self, req: Request<T>) -> Self::Future {
        let rate_result = {
            let _span = trace_span!("rate").entered();
            self.limiters
                .iter()
                .try_for_each(|limiter| limiter.check_limit(&req))
        };
        match rate_result {
            Ok(()) => RateLimitFuture::Positive {
                inner: self.inner.call(req),
            },
            // TODO: option to allow ignoring extraction errors.
            Err(error) => {
                if let RateLimitError::LimitReached { remaining_seconds } = &error {
                    warn!(wait = remaining_seconds, "rate limit exceeded");
                }
                RateLimitFuture::Negative { error }
            }
        }
    }
}

impl<S, T> RateLimit<S, T>
where
    S: Service<Request<T>> + Send + 'static,
    T: Send + 'static,
{
    /// Create new rate limiting service.
    #[must_use]
    pub fn new(inner: S, configs: &[HandlerRateLimitConfig]) -> Self {
        Self {
            inner,
            limiters: configs.iter().map(Self::make_limiter).collect(),
        }
    }

    /// Create a limiter matching the configured key extraction method.
    fn make_limiter(config: &HandlerRateLimitConfig) -> Box<dyn Limiter<T> + Send + Sync> {
        match config.key {
            RateLimitKey::Global => {
                if !config.overrides.is_empty() {
                    warn!("ignoring rate limit overrides for global limiter");
                }
                Box::new(GlobalLimiter::new(config))
            }
            RateLimitKey::PeerIp => Box::new(KeyedLimiter::new(PeerIpKeyExtractor, config)),
            RateLimitKey::SmartIp => Box::new(KeyedLimiter::new(SmartIpKeyExtractor, config)),
            RateLimitKey::UserId => Box::new(KeyedLimiter::new(UserIdKeyExtractor, config)),
        }
    }
}

/// Rate-limiting [`tower`] service future.
#[pin_project(project = ProjectedOutcome)]
pub enum RateLimitFuture<F> {
    /// Happy path, calling inner service.
    Positive {
        /// Inner future.
        #[pin]
        inner: F,
    },
    /// Key extraction error or rate limit exceeded.
    Negative {
        /// Cause of negative response.
        error: RateLimitError,
    },
}

impl<F, U, E> Future for RateLimitFuture<F>
where
    F: Future<Output = Result<U, E>>,
    E: Into<BoxError>,
{
    type Output = Result<U, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ProjectedOutcome::Positive { inner } => {
                let resp = ready!(inner.poll(cx).map_err(Into::into))?;
                Poll::Ready(Ok(resp))
            }
            ProjectedOutcome::Negative { error } => Poll::Ready(Err(Box::new(error.clone()))),
        }
    }
}

/// Trait for all rate limiters.
trait Limiter<T> {
    /// Check whether a request can pass through a rate-limiter.
    fn check_limit(&self, req: &Request<T>) -> Result<(), RateLimitError>;
}

/// Global rate limiter.
///
/// Does no key extraction from requests.
struct GlobalLimiter {
    /// Internal limiter state.
    limiter: RateLimiter<NotKeyed, InMemoryState, QuantaClock, NoOpMiddleware<QuantaInstant>>,
}

impl<T> Limiter<T> for GlobalLimiter {
    fn check_limit(&self, _req: &Request<T>) -> Result<(), RateLimitError> {
        self.check()
    }
}

impl GlobalLimiter {
    /// Check whether a request can pass through this limiter.
    fn check(&self) -> Result<(), RateLimitError> {
        self.limiter.check().map_err(|neg| {
            let remaining_seconds = neg.wait_time_from(DefaultClock::default().now()).as_secs();
            RateLimitError::LimitReached { remaining_seconds }
        })
    }

    /// Create new global limiter.
    #[must_use]
    fn new(config: &HandlerRateLimitConfig) -> Self {
        Self {
            limiter: RateLimiter::direct(
                Quota::with_period(config.period())
                    .unwrap()
                    .allow_burst(config.burst_size()),
            ),
        }
    }
}

/// Keyed rate limiter
///
/// Extracts key data from requests using provided [`Self::extractor`].
struct KeyedLimiter<K: KeyExtractor> {
    /// Key extractor.
    extractor: K,
    /// Internal keyed limiter states.
    limiters: RateLimiter<
        K::Key,
        DashMap<K::Key, InMemoryState>,
        QuantaClock,
        NoOpMiddleware<QuantaInstant>,
    >,
    /// Dedicated limiters for keys with an overridden quota.
    overrides: HashMap<K::Key, GlobalLimiter>,
    /// Number of checks made, used to schedule removal of stale keys.
    checks: AtomicU32,
}

/// Number of keyed checks between removals of stale keys from limiter state.
const EVICTION_INTERVAL: u32 = 4096;

impl<T, K: KeyExtractor> Limiter<T> for KeyedLimiter<K> {
    fn check_limit(&self, req: &Request<T>) -> Result<(), RateLimitError> {
        let key = self.extractor.extract(req)?;
        // Keep state from growing forever: forget keys whose quota has fully replenished.
        if self.checks.fetch_add(1, Ordering::Relaxed) % EVICTION_INTERVAL == EVICTION_INTERVAL - 1
        {
            self.limiters.retain_recent();
            self.limiters.shrink_to_fit();
        }
        if let Some(limiter) = self.overrides.get(&key) {
            return limiter.check();
        }
        self.limiters.check_key(&key).map_err(|neg| {
            let remaining_seconds = neg.wait_time_from(DefaultClock::default().now()).as_secs();
            RateLimitError::LimitReached { remaining_seconds }
        })
    }
}

impl<K: KeyExtractor> KeyedLimiter<K> {
    /// Create new keyed limiter.
    #[must_use]
    fn new(extractor: K, config: &HandlerRateLimitConfig) -> Self {
        Self {
            extractor,
            limiters: RateLimiter::keyed(
                Quota::with_period(config.period())
                    .unwrap()
                    .allow_burst(config.burst_size()),
            ),
            overrides: config
                .overrides
                .iter()
                .filter_map(|(key, quota)| match key.parse::<K::Key>() {
                    Ok(key) => Some((key, GlobalLimiter::new(&config.with_override(quota)))),
                    Err(_) => {
                        warn!(key, "ignoring rate limit override with invalid key");
                        None
                    }
                })
                .collect(),
            checks: AtomicU32::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, time::Duration};

    use futures::executor::block_on;
    use serde_json::{from_value, json};
    use tower::service_fn;

    use super::*;
    use crate::auth::UserId;

    fn limit(value: serde_json::Value) -> HandlerRateLimitConfig {
        from_value(value).unwrap()
    }

    fn request(user: &str) -> Request<()> {
        let mut req = Request::new(());
        req.extensions_mut().insert(UserId::from(user));
        req
    }

    /// Make a number of requests as `user`, returning how many were let through.
    fn allowed<S>(service: &mut S, user: &str, count: usize) -> usize
    where
        S: Service<Request<()>>,
    {
        (0..count)
            .filter(|_| block_on(service.call(request(user))).is_ok())
            .count()
    }

    fn rate_limited(
        configs: &[HandlerRateLimitConfig],
    ) -> impl Service<Request<()>, Response = Response<()>, Error = BoxError> + use<> {
        RateLimit::new(
            service_fn(|_req: Request<()>| async { Ok::<_, Infallible>(Response::new(())) }),
            configs,
        )
    }

    /// Deserialize - single limit or a list of limits.
    #[test]
    fn de_one_or_many() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(deserialize_with = "deserialize_rate_limits")]
            rate_limit: Vec<HandlerRateLimitConfig>,
        }

        let one: Wrapper = from_value(json!({"rate_limit": {"rps": 1}})).unwrap();
        let many: Wrapper =
            from_value(json!({"rate_limit": [{"rps": 1}, {"key": "user_id", "rps": 2}]})).unwrap();
        assert_eq!(one.rate_limit.len(), 1);
        assert_eq!(many.rate_limit.len(), 2);
        assert_eq!(many.rate_limit[1].key, RateLimitKey::UserId);
    }

    /// A request has to pass every configured limit.
    #[test]
    fn all_limits_must_pass() {
        let mut service = rate_limited(&[
            limit(json!({"key": "user_id", "rps": 1, "burst_duration": "2s"})),
            limit(json!({"key": "global", "rps": 1, "burst_duration": "3s"})),
        ]);
        // User limit (2) is hit first, and rejected requests don't count towards global one.
        assert_eq!(allowed(&mut service, "alice", 5), 2);
        // Global limit (3) leaves a single request for another user.
        assert_eq!(allowed(&mut service, "bob", 5), 1);
    }

    /// Overridden keys use their own quota, everyone else uses the default one.
    #[test]
    fn overrides_replace_quota() {
        let mut service = rate_limited(&[limit(json!({
            "key": "user_id",
            "rps": 1,
            "burst_duration": "2s",
            "overrides": {
                "alice": {"rps": 1, "burst_duration": "5s"},
                "carol": {"rps": 1, "burst_rps": 4}
            }
        }))]);
        assert_eq!(allowed(&mut service, "alice", 10), 5);
        assert_eq!(allowed(&mut service, "bob", 10), 2);
        // Burst duration is inherited.
        assert_eq!(allowed(&mut service, "carol", 10), 8);
    }

    /// Overrides with unparseable keys are ignored.
    #[test]
    fn invalid_override_key_ignored() {
        let mut service = rate_limited(&[limit(json!({
            "key": "peer_ip",
            "rps": 1,
            "overrides": {"not-an-ip": {"rps": 10}}
        }))]);
        let mut req = Request::new(());
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
        ));
        assert!(block_on(service.call(req)).is_ok());
    }

    /// Keys with fully replenished quota are dropped from limiter state.
    #[test]
    fn stale_keys_are_evicted() {
        let limiter = KeyedLimiter::new(
            UserIdKeyExtractor,
            &limit(json!({"key": "user_id", "rps": 1_000_000})),
        );
        for i in 0..EVICTION_INTERVAL - 1 {
            limiter.check_limit(&request(&i.to_string())).unwrap();
        }
        assert_eq!(limiter.limiters.len(), (EVICTION_INTERVAL - 1) as usize);
        std::thread::sleep(Duration::from_millis(50));
        limiter.check_limit(&request("last")).unwrap();
        assert!(limiter.limiters.len() < 2);
    }
}
