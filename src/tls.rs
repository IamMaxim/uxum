//! TLS support types and utilities.

use std::{io, net::SocketAddr, ops::Deref, path::Path, sync::Arc, time::Duration};

use axum::middleware::AddExtension;
use axum_server::{
    Server as AxumServer,
    accept::{Accept, DefaultAcceptor},
    tls_rustls::{RustlsAcceptor, RustlsConfig, future::RustlsAcceptorFuture},
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tracing::{Instrument, debug_span, info};

use crate::{
    builder::server::{ListenerInfoAcceptorFuture, ServerBuilder, ServerBuilderError},
    layers::ext::ListenerInfo,
    util::fs::read_file,
};

/// TLS configuration.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub struct TlsConfig {
    /// Path to certificate or certificate chain in PEM format.
    #[serde(alias = "cert", alias = "chain")]
    pub certificate: Box<Path>,
    /// Path to private key file in PEM format.
    #[serde(alias = "key")]
    pub private_key: Box<Path>,
    /// TLS handshake timeout.
    ///
    /// Default is 10 seconds.
    #[serde(
        default = "TlsConfig::default_handshake_timeout",
        with = "humantime_serde"
    )]
    pub handshake_timeout: Duration,
    /// Protocols to consider for negotiation using TLS ALPN.
    #[serde(default = "TlsConfig::default_alpn_protocols")]
    pub alpn_protocols: Vec<TlsAlpnProtocol>,
}

impl TlsConfig {
    /// Default value for [`Self::handshake_timeout`].
    #[must_use]
    #[inline]
    fn default_handshake_timeout() -> Duration {
        Duration::from_secs(10)
    }

    /// Default value for [`Self::alpn_protocols`].
    #[must_use]
    #[inline]
    fn default_alpn_protocols() -> Vec<TlsAlpnProtocol> {
        vec![TlsAlpnProtocol::Http2, TlsAlpnProtocol::Http11]
    }

    /// Generate configuration object for RusTLS.
    ///
    /// # Errors
    ///
    /// Returns `Err` if provided TLS configuration is invalid.
    pub async fn rustls_config(&self) -> Result<RustlsConfig, ServerBuilderError> {
        fn err_into(err: io::Error) -> ServerBuilderError {
            ServerBuilderError::TlsConfig(err.into())
        }
        let cert = read_file(&self.certificate).await.map_err(err_into)?;
        let cert = CertificateDer::pem_slice_iter(&cert).collect::<Result<Vec<_>, _>>()?;
        let key = read_file(&self.private_key).await.map_err(err_into)?;
        let key = PrivateKeyDer::from_pem_slice(&key)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth() // TODO: optional client auth?
            .with_single_cert(cert, key)?;
        config.alpn_protocols = self
            .alpn_protocols
            .iter()
            .map(|p| p.as_ref().to_vec())
            .collect();
        Ok(RustlsConfig::from_config(Arc::new(config)))
    }
}

/// Protocol to consider for negotiation using TLS ALPN.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum TlsAlpnProtocol {
    /// HTTP/1.1.
    #[default]
    #[serde(
        alias = "http",
        alias = "http1",
        alias = "http/1",
        alias = "http/1.1",
        alias = "h1"
    )]
    Http11,
    /// HTTP/2. Required for gRPC.
    #[serde(alias = "http/2", alias = "h2")]
    Http2,
}

impl AsRef<[u8]> for TlsAlpnProtocol {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Http11 => b"http/1.1",
            Self::Http2 => b"h2",
        }
    }
}

/// Wrapper over [`axum_server::tls_rustls::RustlsAcceptor`].
///
/// Adds [`ListenerInfo`]
#[derive(Clone, Debug)]
pub struct TlsAcceptor<A = DefaultAcceptor> {
    /// Wrapped inner TLS acceptor.
    inner: RustlsAcceptor<A>,
    /// Listener information.
    listener_info: ListenerInfo,
}

impl<A> TlsAcceptor<A> {
    /// Create new acceptor by wrapping existing TLS acceptor.
    pub fn new(inner: RustlsAcceptor<A>, listener_info: ListenerInfo) -> Self {
        Self {
            inner,
            listener_info,
        }
    }
}

impl<A> Deref for TlsAcceptor<A> {
    type Target = RustlsAcceptor<A>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<A, I, S> Accept<I, S> for TlsAcceptor<A>
where
    A: Accept<I, S>,
    A::Stream: AsyncRead + AsyncWrite + Unpin,
{
    type Stream = TlsStream<A::Stream>;
    type Service = AddExtension<A::Service, ListenerInfo>;
    type Future =
        ListenerInfoAcceptorFuture<RustlsAcceptorFuture<A::Future, A::Stream, A::Service>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.accept(stream, service);
        let listener_info = self.listener_info.clone();

        ListenerInfoAcceptorFuture::new(inner, listener_info)
    }
}

impl ServerBuilder {
    /// Build TLS network server.
    ///
    /// # Errors
    ///
    /// Returns `Err` if builder encounters an error while setting up a listening socket
    /// or configuring TLS parameters.
    pub async fn build_tls(
        self,
        tls_config: &TlsConfig,
    ) -> Result<AxumServer<SocketAddr, TlsAcceptor>, ServerBuilderError> {
        let span = debug_span!("build_tls_server");
        async move {
            let listener = self.create_listener(&self.listen).await?;
            let local_addr = listener
                .local_addr()
                .map_err(|err| ServerBuilderError::ListenerLocalAddr(err.into()))?;
            let listener_info = ListenerInfo::new_tls(local_addr);
            let rustls_config = tls_config.rustls_config().await?;
            let acceptor =
                RustlsAcceptor::new(rustls_config).handshake_timeout(tls_config.handshake_timeout);
            let acceptor = TlsAcceptor::new(acceptor, listener_info);
            let mut server = axum_server::from_tcp(listener)
                .map_err(|err| ServerBuilderError::BuildServer(err.into()))?
                .acceptor(acceptor);

            let builder = server.http_builder();
            self.configure_http1(builder);
            self.configure_http2(builder);

            info!("finished building TLS server");
            Ok(server)
        }
        .instrument(span)
        .await
    }
}
