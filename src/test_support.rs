//! In-process TLS/HTTP fixture server, used only by integration tests
//! (enabled by the `test-server` cargo feature).
//!
//! Serves a single self-signed certificate over TCP+TLS for HTTP/1.1 and
//! HTTP/2 (hyper), and over UDP+QUIC for HTTP/3 (quinn + h3). The generated
//! certificate is added to a [`rustls::RootCertStore`] that callers pass to
//! the `*_with_roots` probe variants so everything runs locally and
//! deterministically with no external network. The servers run as tasks on
//! the caller's Tokio runtime (call [`FixtureServer::start`] inside an async
//! context).
#![cfg(feature = "test-server")]
#![allow(clippy::module_name_repetitions)]

use rustls::RootCertStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

/// A running local TLS/QUIC test server and the trust store for its
/// certificate.
pub struct FixtureServer {
    tcp_addr: SocketAddr,
    udp_addr: SocketAddr,
    /// Root store containing the server's self-signed certificate.
    pub roots: RootCertStore,
    /// Held so the server tasks stay alive for the lifetime of the fixture;
    /// dropped (detaching) on teardown.
    #[allow(dead_code)]
    handles: Vec<JoinHandle<()>>,
}

impl FixtureServer {
    /// Generate a self-signed certificate and start the TCP (HTTP/1.1 + h2)
    /// and UDP (HTTP/3) servers on ephemeral loopback ports, as tasks on the
    /// current Tokio runtime.
    ///
    /// # Panics
    ///
    /// Panics if the self-signed certificate cannot be generated or the
    /// loopback sockets cannot be bound (e.g. in a sandbox without network).
    pub async fn start() -> Self {
        // rustls needs a default crypto provider; ring is the only selected
        // provider, so install it explicitly (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("generate self-signed cert");

        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).expect("add self-signed cert to roots");

        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            key_pair.serialize_der(),
        ));

        // TCP/TLS server cert (ALPN h2 + http/1.1).
        let mut tls_server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der.clone_key())
            .expect("build TLS server config");
        tls_server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        // QUIC server cert (ALPN h3).
        let mut quic_rustls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .expect("build QUIC server config");
        quic_rustls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_cfg =
            quinn::crypto::rustls::QuicServerConfig::try_from(quic_rustls).expect("build QUIC crypto config");
        let quic_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let tcp_addr = tcp_listener.local_addr().expect("tcp local addr");

        let quic_endpoint = quinn::Endpoint::server(quic_cfg, "127.0.0.1:0".parse().expect("udp bind addr"))
            .expect("bind quic endpoint");
        let udp_addr = quic_endpoint.local_addr().expect("udp local addr");

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server));

        let handles = vec![
            tokio::spawn(run_tcp_server(tcp_listener, tls_acceptor)),
            tokio::spawn(run_quic_server(quic_endpoint)),
        ];

        Self {
            tcp_addr,
            udp_addr,
            roots,
            handles,
        }
    }

    /// TCP (HTTP/1.1 + HTTP/2) listen address.
    #[must_use]
    pub const fn tcp_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    /// UDP (HTTP/3) listen address.
    #[must_use]
    pub const fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }
}

use rcgen::CertifiedKey;

/// Accept TLS connections and serve HTTP/1.1 or HTTP/2 chosen by negotiated
/// ALPN.
async fn run_tcp_server(listener: tokio::net::TcpListener, acceptor: tokio_rustls::TlsAcceptor) {
    loop {
        let Ok((tcp, _peer)) = listener.accept().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let negotiated_h2 = tls.get_ref().1.alpn_protocol().is_some_and(|a| a == b"h2");
            let io = hyper_util::rt::TokioIo::new(tls);
            let service = hyper::service::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(
                    bytes::Bytes::from_static(b"ok"),
                )))
            });
            let result = if negotiated_h2 {
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
            } else {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
            };
            let _ = result;
        });
    }
}

/// Accept QUIC connections and serve HTTP/3 (`200 ok` per request).
async fn run_quic_server(endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(serve_quic_connection(incoming));
    }
}

async fn serve_quic_connection(incoming: quinn::Incoming) {
    let Ok(conn) = incoming.await else {
        return;
    };
    let Ok(mut h3_conn) = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await else {
        return;
    };
    loop {
        let Ok(Some(resolver)) = h3_conn.accept().await else {
            return;
        };
        let Ok((_request, mut stream)) = resolver.resolve_request().await else {
            return;
        };
        let response = hyper::Response::builder().status(200).body(()).expect("status 200");
        if stream.send_response(response).await.is_err() {
            return;
        }
        if stream.send_data(bytes::Bytes::from_static(b"ok")).await.is_err() {
            return;
        }
        let _ = stream.finish().await;
    }
}
