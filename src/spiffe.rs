//! SPIFFE authentication and authorization support.

use std::{
    collections::BTreeSet,
    env, fmt, io,
    net::SocketAddr,
    num::NonZeroUsize,
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use axum::{Extension, middleware::AddExtension};
use axum_server::{
    Server as AxumServer,
    accept::{Accept, DefaultAcceptor},
    tls_rustls::{RustlsAcceptor, RustlsConfig, future::RustlsAcceptorFuture},
};
use pin_project::pin_project;
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use spiffe::{
    SpiffeIdError, X509ResourceLimits, X509Source, X509SourceError, cert::error::CertificateError,
};
use spiffe_rustls::{
    Error as SpiffeRustlsError, TrustDomain, TrustDomainPolicy, authorizer, mtls_client,
    mtls_server,
};
use spiffe_rustls_tokio::PeerIdentity;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Layer;
use tracing::{Instrument, debug_span, info};
use url::Url;

use crate::{
    builder::server::{ServerBuilder, ServerBuilderError},
    layers::ext::ListenerInfo,
    metrics::SpiffeMetrics,
    tls::TlsAlpnProtocol,
};

/// SPIFFE-related error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpiffeError {
    /// Invalid SPIFFE ID.
    #[error("Invalid SPIFFE ID: {0}")]
    Id(#[from] SpiffeIdError),
    /// Error setting up SPIFFE X.509 source.
    #[error("Error setting up SPIFFE X.509 source: {0}")]
    Source(#[from] X509SourceError),
    /// Error setting up SPIFFE TLS config.
    #[error("Error setting up SPIFFE TLS config: {0}")]
    Rustls(#[from] SpiffeRustlsError),
    /// Cannot find SPIFFE workload API endpoint.
    #[error("Cannot find SPIFFE workload API endpoint: {0}")]
    NoEndpoint(String),
}

/// SPIFFE configuration.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub struct SpiffeConfig {
    /// SPIFFE local resource limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<SpiffeResourceLimits>,
    /// Custom SPIFFE workload API endpoint.
    ///
    /// Typically contains `unix://` URL to a socket.
    ///
    /// Default value is `unix:///tmp/spire-agent/public/api.sock`.
    ///
    /// Explicitly specify no value to force use of `SPIFFE_ENDPOINT_SOCKET`
    /// environment variable.
    #[serde(
        default = "SpiffeConfig::default_workload_api",
        skip_serializing_if = "Option::is_none"
    )]
    pub workload_api: Option<Url>,
    /// Optional timeout for initial sync of SPIFFE state and retrieval of
    /// bundle sets.
    ///
    /// Unbounded by default.
    #[serde(default, with = "humantime_serde")]
    pub initial_sync_timeout: Option<Duration>,
    /// Wait time to finish background tasks for source.
    ///
    /// Default is 30 seconds.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "humantime_serde"
    )]
    pub shutdown_timeout: Option<Duration>,
    /// Reconnect interval settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect: Option<SpiffeReconnectBackoff>,
    /// SPIFFE authorizer settings.
    #[serde(default)]
    pub authorize: SpiffeAuthorize,
    /// SPIFFE trust domain policy.
    #[serde(default)]
    pub trust_domain_policy: SpiffeTrustDomainPolicy,
    /// TLS handshake timeout.
    ///
    /// Default is 10 seconds.
    #[serde(
        default = "SpiffeConfig::default_handshake_timeout",
        with = "humantime_serde"
    )]
    pub handshake_timeout: Duration,
    /// Protocols to consider for negotiation using TLS ALPN.
    #[serde(default = "SpiffeConfig::default_alpn_protocols")]
    pub alpn_protocols: Vec<TlsAlpnProtocol>,
}

impl Default for SpiffeConfig {
    fn default() -> Self {
        Self {
            limits: None,
            workload_api: Self::default_workload_api(),
            initial_sync_timeout: None,
            shutdown_timeout: None,
            reconnect: None,
            authorize: SpiffeAuthorize::default(),
            trust_domain_policy: SpiffeTrustDomainPolicy::default(),
            handshake_timeout: Self::default_handshake_timeout(),
            alpn_protocols: Self::default_alpn_protocols(),
        }
    }
}

impl SpiffeConfig {
    /// Default value for [`Self::handshake_timeout`].
    #[must_use]
    #[inline]
    fn default_handshake_timeout() -> Duration {
        Duration::from_secs(10)
    }

    /// Default value for [`Self::workload_api`].
    #[must_use]
    #[inline]
    fn default_workload_api() -> Option<Url> {
        // SAFETY: static value always parses successfully.
        Some(Url::parse("unix:///tmp/spire-agent/public/api.sock").unwrap())
    }

    /// Default value for [`Self::alpn_protocols`].
    #[must_use]
    #[inline]
    fn default_alpn_protocols() -> Vec<TlsAlpnProtocol> {
        vec![TlsAlpnProtocol::Http2, TlsAlpnProtocol::Http11]
    }

    /// Generate SPIFFE X.509 source object from configuration.
    ///
    /// # Errors
    ///
    /// Returns `Err` if provided SPIFFE configuration is invalid.
    pub async fn build_source(
        &self,
        metrics: Option<SpiffeMetrics>,
    ) -> Result<X509Source, SpiffeError> {
        // TODO: use unified X.509 source for all servers and clients.
        let mut builder = X509Source::builder();
        if let Some(ref limits) = self.limits {
            builder = builder.resource_limits(limits.clone().into());
        }
        if let Some(ref endpoint) = self.workload_api {
            builder = builder.endpoint(endpoint);
        } else if let Err(err) = env::var("SPIFFE_ENDPOINT_SOCKET") {
            return Err(SpiffeError::NoEndpoint(err.to_string()));
        }
        if let Some(timeout) = self.initial_sync_timeout {
            builder = builder.initial_sync_timeout(timeout);
        }
        if let Some(timeout) = self.shutdown_timeout {
            builder = builder.shutdown_timeout(Some(timeout));
        }
        if let Some(SpiffeReconnectBackoff {
            min_backoff,
            max_backoff,
        }) = self.reconnect
        {
            builder = builder.reconnect_backoff(min_backoff, max_backoff);
        }
        if let Some(metrics) = metrics {
            builder = builder.metrics(metrics.into_arc_inner());
        }
        builder.build().await.map_err(Into::into)
    }

    /// Generate configuration object for server-side RusTLS.
    ///
    /// # Errors
    ///
    /// Returns `Err` if provided SPIFFE configuration is invalid.
    pub async fn rustls_server_config(
        &self,
        metrics: Option<SpiffeMetrics>,
    ) -> Result<RustlsConfig, SpiffeError> {
        let source = self.build_source(metrics).await?;
        let mut builder = mtls_server(source);
        builder = match &self.authorize {
            SpiffeAuthorize::Any => builder.authorize(authorizer::any()),
            SpiffeAuthorize::Exact { spiffe_ids } => {
                builder.authorize(authorizer::exact(spiffe_ids.iter().map(|s| s.as_str()))?)
            }
            SpiffeAuthorize::TrustDomains { trust_domains } => builder.authorize(
                authorizer::trust_domains(trust_domains.iter().map(|s| s.as_str()))?,
            ),
        };
        // TODO: add customizer function support.
        let config = builder
            .trust_domain_policy(self.trust_domain_policy.clone().try_into()?)
            .with_alpn_protocols(&self.alpn_protocols)
            .build()?;
        Ok(RustlsConfig::from_config(Arc::new(config)))
    }

    /// Generate configuration object for client-side RusTLS.
    ///
    /// # Errors
    ///
    /// Returns `Err` if provided SPIFFE configuration is invalid.
    pub async fn rustls_client_config(
        &self,
        metrics: Option<SpiffeMetrics>,
    ) -> Result<ClientConfig, SpiffeError> {
        let source = self.build_source(metrics).await?;
        let mut builder = mtls_client(source);
        builder = match &self.authorize {
            SpiffeAuthorize::Any => builder.authorize(authorizer::any()),
            SpiffeAuthorize::Exact { spiffe_ids } => {
                builder.authorize(authorizer::exact(spiffe_ids.iter().map(|s| s.as_str()))?)
            }
            SpiffeAuthorize::TrustDomains { trust_domains } => builder.authorize(
                authorizer::trust_domains(trust_domains.iter().map(|s| s.as_str()))?,
            ),
        };
        builder = builder.trust_domain_policy(self.trust_domain_policy.clone().try_into()?);
        // TODO: add customizer function support.
        let config = builder.with_alpn_protocols(&self.alpn_protocols).build()?;
        Ok(config)
    }
}

/// SPIFFE resource limits for SVID and bundle storage to prevent resource exhaustion.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub struct SpiffeResourceLimits {
    /// Maximum number of SVIDs allowed in a context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_svids: Option<NonZeroUsize>,
    /// Maximum number of bundles allowed in a bundle set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bundles: Option<NonZeroUsize>,
    /// Maximum bundle DER size in bytes (per bundle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bundle_der_bytes: Option<NonZeroUsize>,
}

impl From<SpiffeResourceLimits> for X509ResourceLimits {
    fn from(value: SpiffeResourceLimits) -> Self {
        Self::new(
            value.max_svids.map(NonZeroUsize::get),
            value.max_bundles.map(NonZeroUsize::get),
            value.max_bundle_der_bytes.map(NonZeroUsize::get),
        )
    }
}

/// Backoff interval configuration between subsequent workload API connection attempts.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub struct SpiffeReconnectBackoff {
    /// Minimum interval between reconnect attempts.
    #[serde(with = "humantime_serde")]
    pub min_backoff: Duration,
    /// Maximum interval between reconnect attempts.
    #[serde(with = "humantime_serde")]
    pub max_backoff: Duration,
}

/// SPIFFE authorizer configuration.
///
/// Limits Spiffe IDs that can connect to server.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SpiffeAuthorize {
    /// Allow any SPIFFE ID.
    #[default]
    Any,
    /// Allow only exact SPIFFE IDs listed.
    Exact {
        /// Allowed SPIFFE IDs.
        spiffe_ids: Vec<String>,
    },
    /// Allow SPIFFE IDs from listed trust domains.
    TrustDomains {
        /// Allowed trust domains.
        trust_domains: Vec<String>,
    },
}

/// Policy for selecting which trust domains to trust during certificate verification.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SpiffeTrustDomainPolicy {
    /// Default: use all trust domain bundles provided by the Workload API.
    #[default]
    #[serde(alias = "any")]
    AnyInBundleSet,
    /// Only trust the specified trust domain.
    #[serde(alias = "single", alias = "local")]
    LocalOnly {
        /// Allowed trust domain.
        domain: String,
    },
    /// Restrict to these trust domains only.
    #[serde(alias = "list")]
    AllowList {
        /// Allowed trust domains.
        domains: Vec<String>,
    },
}

impl TryFrom<SpiffeTrustDomainPolicy> for TrustDomainPolicy {
    type Error = SpiffeIdError;

    fn try_from(value: SpiffeTrustDomainPolicy) -> Result<Self, Self::Error> {
        match value {
            SpiffeTrustDomainPolicy::AnyInBundleSet => Ok(Self::AnyInBundleSet),
            SpiffeTrustDomainPolicy::LocalOnly { domain } => {
                Ok(Self::LocalOnly(domain.try_into()?))
            }
            SpiffeTrustDomainPolicy::AllowList { domains } => {
                let domains: Result<BTreeSet<TrustDomain>, Self::Error> =
                    domains.into_iter().map(TryFrom::try_from).collect();
                Ok(Self::AllowList(domains?))
            }
        }
    }
}

/// Wrapper over [`axum_server::tls_rustls::RustlsAcceptor`].
///
/// Provides extensions to identify connecting SPIFFE workload, in addition to [`ListenerInfo`].
#[derive(Clone, Debug)]
pub struct SpiffeAcceptor<A = DefaultAcceptor> {
    /// Wrapped inner TLS acceptor.
    inner: RustlsAcceptor<A>,
    /// Listener information.
    listener_info: ListenerInfo,
}

impl<A> SpiffeAcceptor<A> {
    /// Create new acceptor by wrapping existing TLS acceptor.
    pub fn new(inner: RustlsAcceptor<A>, listener_info: ListenerInfo) -> Self {
        Self {
            inner,
            listener_info,
        }
    }
}

impl<A> Deref for SpiffeAcceptor<A> {
    type Target = RustlsAcceptor<A>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<A, I, S> Accept<I, S> for SpiffeAcceptor<A>
where
    A: Accept<I, S>,
    A::Stream: AsyncRead + AsyncWrite + Unpin,
{
    type Stream = TlsStream<A::Stream>;
    type Service = AddExtension<AddExtension<A::Service, ListenerInfo>, PeerIdentity>;
    type Future = SpiffeAcceptorFuture<RustlsAcceptorFuture<A::Future, A::Stream, A::Service>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.accept(stream, service);
        let listener_info = self.listener_info.clone();

        SpiffeAcceptorFuture::new(inner, listener_info)
    }
}

/// Acceptor future for [`SpiffeAcceptor`].
#[pin_project]
pub struct SpiffeAcceptorFuture<F> {
    #[pin]
    inner: F,
    listener_info: Option<ListenerInfo>,
}

impl<F> SpiffeAcceptorFuture<F> {
    /// Construct new future.
    pub fn new(inner: F, listener_info: ListenerInfo) -> Self {
        Self {
            inner,
            listener_info: Some(listener_info),
        }
    }
}

impl<F> fmt::Debug for SpiffeAcceptorFuture<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpiffeAcceptorFuture").finish()
    }
}

impl<F, I, S> Future for SpiffeAcceptorFuture<F>
where
    F: Future<Output = io::Result<(TlsStream<I>, S)>>,
    I: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<(
        TlsStream<I>,
        AddExtension<AddExtension<S, ListenerInfo>, PeerIdentity>,
    )>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let inner_res = ready!(this.inner.poll(cx));
        Poll::Ready(inner_res.and_then(|(stream, service)| {
            let (_io, conn) = stream.get_ref();
            let peer_identity = if let Some([leaf, ..]) = conn.peer_certificates() {
                match spiffe::cert::spiffe_id_from_der(leaf.as_ref()) {
                    Ok(spiffe_id) => PeerIdentity::new(Some(spiffe_id)),
                    Err(err) => match err {
                        CertificateError::MissingSpiffeId | CertificateError::MultipleSpiffeIds => {
                            PeerIdentity::new(None)
                        }
                        _ => return Err(io::Error::other(err.to_string())),
                    },
                }
            } else {
                PeerIdentity::new(None)
            };
            let listener_info = this
                .listener_info
                .take()
                .ok_or_else(|| io::Error::other("no listener info"))?;
            let service = Extension(peer_identity).layer(Extension(listener_info).layer(service));
            Ok((stream, service))
        }))
    }
}

impl ServerBuilder {
    /// Build SPIFFE network server.
    ///
    /// # Errors
    ///
    /// Returns `Err` if builder encounters an error while setting up a listening socket
    /// or configuring TLS or SPIFFE parameters.
    #[cfg(feature = "spiffe")]
    pub async fn build_spiffe(
        self,
        spiffe_config: &SpiffeConfig,
        metrics: Option<SpiffeMetrics>,
    ) -> Result<AxumServer<SocketAddr, SpiffeAcceptor>, ServerBuilderError> {
        let span = debug_span!("build_spiffe_server");
        async move {
            let listener = self.create_listener(&self.listen).await?;
            let local_addr = listener
                .local_addr()
                .map_err(|err| ServerBuilderError::ListenerLocalAddr(err.into()))?;
            let listener_info = ListenerInfo::new_spiffe(local_addr);
            let rustls_config = spiffe_config.rustls_server_config(metrics).await?;
            let acceptor = RustlsAcceptor::new(rustls_config)
                .handshake_timeout(spiffe_config.handshake_timeout);
            let acceptor = SpiffeAcceptor::new(acceptor, listener_info);
            let mut server = axum_server::from_tcp(listener)
                .map_err(|err| ServerBuilderError::BuildServer(err.into()))?
                .acceptor(acceptor);

            let builder = server.http_builder();
            self.configure_http1(builder);
            self.configure_http2(builder);

            info!("finished building SPIFFE TLS server");
            Ok(server)
        }
        .instrument(span)
        .await
    }
}
