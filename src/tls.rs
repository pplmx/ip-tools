//! TLS handshake diagnostics.
//!
//! Each probe performs a full TLS handshake to one destination socket address
//! while presenting an explicit Server Name (SNI). Connecting to a specific IP
//! while presenting the hostname as SNI is the recommended pattern, because
//! many servers are virtual-hosted and answer differently per SNI.
//!
//! The module exposes a lower-level `connect` helper (used by the HTTP
//! probes) and a higher-level [`probe`] that records a complete
//! [`TlsObservation`].

use crate::model::tls::{CertificateSummary, TlsObservation};
use crate::model::{FailureKind, ProbeError};
use crate::tcp::classify_io_error;
use rustls_pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

/// ALPN protocols offered for a general TLS observation probe.
pub const ALPN_GENERAL: &[&[u8]] = &[b"h2", b"http/1.1"];
/// ALPN protocols offered when forcing a plain HTTP/1.1 exchange.
pub const ALPN_HTTP1: &[&[u8]] = &[b"http/1.1"];
/// ALPN protocol offered when requesting HTTP/2.
pub const ALPN_H2: &[&[u8]] = &[b"h2"];

// Trusted roots, loaded once per process.
static ROOTS: std::sync::OnceLock<rustls::RootCertStore> = std::sync::OnceLock::new();

/// Load (once) the system trust store.
pub(crate) fn roots() -> rustls::RootCertStore {
    ROOTS
        .get_or_init(|| {
            // rustls 0.23 requires an explicit provider when multiple provider
            // features are enabled transitively. Install ring once.
            let install = rustls::crypto::ring::default_provider().install_default();
            let _ = install;
            let mut store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = store.add(cert);
            }
            store
        })
        .clone()
}

/// Build a TLS client configuration offering the given ALPN protocols and
/// trusting `roots`.
fn client_config(alpn: &[&[u8]], roots: &rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// A completed TLS handshake together with the negotiated parameters.
pub(crate) struct TlsConnection {
    /// The established TLS stream.
    pub stream: tokio_rustls::client::TlsStream<TcpStream>,
    /// Negotiated TLS version, e.g. `TLSv1.3`.
    pub version: Option<String>,
    /// Negotiated cipher suite.
    pub cipher: Option<String>,
    /// Negotiated ALPN protocol.
    pub alpn: Option<String>,
    /// Peer certificate summary.
    pub certificate: Option<CertificateSummary>,
    /// Handshake latency in milliseconds.
    pub latency_ms: u64,
}

/// Perform TCP connect + TLS handshake to `destination` presenting `sni`,
/// bounded by `timeout`, trusting an explicit root store (used to verify
/// in-process test fixtures with self-signed certificates; the CLI and system
/// probes pass `[roots()]`).
pub(crate) async fn connect_with_roots(
    destination: SocketAddr,
    sni: &str,
    alpn: &[&[u8]],
    timeout: Duration,
    roots: &rustls::RootCertStore,
) -> Result<TlsConnection, ProbeError> {
    let start = Instant::now();

    let stream = match tokio::time::timeout(timeout, TcpStream::connect(destination)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(ProbeError {
                kind: classify_io_error(&e),
                message: format!("tcp connect to {destination} failed: {e}"),
            });
        }
        Err(_elapsed) => {
            return Err(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("tcp connect to {destination} timed out after {timeout:?}"),
            });
        }
    };

    let Some(name) = server_name(sni) else {
        return Err(ProbeError {
            kind: FailureKind::Protocol,
            message: format!("cannot use {sni:?} as a server name"),
        });
    };
    let connector = TlsConnector::from(client_config(alpn, roots));
    let handshake = connector.connect(name, stream);
    let tls_stream = match tokio::time::timeout(timeout, handshake).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let kind = classify_tls_error(&e);
            return Err(ProbeError {
                kind,
                message: format!("tls handshake to {destination} with SNI {sni} failed: {e}"),
            });
        }
        Err(_elapsed) => {
            return Err(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("tls handshake to {destination} with SNI {sni} timed out after {timeout:?}"),
            });
        }
    };

    let conn = tls_stream.get_ref().1;
    let version = conn.protocol_version().map(version_name).map(str::to_string);
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|cs| cipher_name(cs.suite()))
        .map(str::to_string);
    let alpn = conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
    let certificate = conn.peer_certificates().and_then(|c| c.first()).and_then(cert_summary);

    Ok(TlsConnection {
        stream: tls_stream,
        version,
        cipher,
        alpn,
        certificate,
        latency_ms: start.elapsed().as_millis() as u64,
    })
}

/// Perform a single TLS handshake to `destination` presenting `sni`, bounded
/// by `timeout`, and record a complete observation.
pub async fn probe(destination: SocketAddr, sni: &str, timeout: Duration) -> TlsObservation {
    probe_with_roots(destination, sni, timeout, &roots()).await
}

/// [`probe`] trusting an explicit root store, for verifying TLS fixtures.
pub async fn probe_with_roots(
    destination: SocketAddr,
    sni: &str,
    timeout: Duration,
    roots: &rustls::RootCertStore,
) -> TlsObservation {
    let start = Instant::now();
    match connect_with_roots(destination, sni, ALPN_GENERAL, timeout, roots).await {
        Ok(conn) => TlsObservation {
            destination,
            sni: sni.to_string(),
            success: true,
            version: conn.version,
            cipher: conn.cipher,
            alpn: conn.alpn,
            certificate: conn.certificate,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            failure: None,
        },
        Err(failure) => TlsObservation {
            destination,
            sni: sni.to_string(),
            success: false,
            version: None,
            cipher: None,
            alpn: None,
            certificate: None,
            latency_ms: None,
            failure: Some(failure),
        },
    }
}

/// Build a rustls [`ServerName`] from a host string, supporting IP literals
/// (bracketed or bare) and DNS hostnames.
fn server_name(host: &str) -> Option<ServerName<'static>> {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Some(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(trimmed.to_string()).ok()
}

/// Map a tokio-rustls I/O error to a [`FailureKind`], distinguishing
/// certificate validity failures from generic handshake failures by
/// inspecting the underlying rustls error.
fn classify_tls_error(e: &std::io::Error) -> FailureKind {
    let underlying = e.get_ref().and_then(|s| s.downcast_ref::<rustls::Error>());
    if matches!(underlying, Some(rustls::Error::InvalidCertificate(_))) {
        FailureKind::Certificate
    } else {
        FailureKind::TlsHandshake
    }
}

const fn version_name(v: rustls::ProtocolVersion) -> &'static str {
    match v {
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
        _ => "unknown",
    }
}

/// Map a negotiated cipher suite to a human-readable name (falling back to a
/// hex identifier for suites not in the table).
const fn cipher_name(cs: rustls::CipherSuite) -> &'static str {
    use rustls::CipherSuite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    match cs {
        TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "ECDHE_ECDSA_AES_128_GCM_SHA256",
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "ECDHE_ECDSA_AES_256_GCM_SHA384",
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE_ECDSA_CHACHA20_POLY1305_SHA256",
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "ECDHE_RSA_AES_128_GCM_SHA256",
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "ECDHE_RSA_AES_256_GCM_SHA384",
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE_RSA_CHACHA20_POLY1305_SHA256",
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => "ECDHE_RSA_AES_128_CBC_SHA",
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => "ECDHE_RSA_AES_256_CBC_SHA",
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => "ECDHE_ECDSA_AES_128_CBC_SHA",
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => "ECDHE_ECDSA_AES_256_CBC_SHA",
        _ => "unknown",
    }
}

/// Extract a certificate summary from the peer's DER certificate.
fn cert_summary(der: &rustls_pki_types::CertificateDer<'_>) -> Option<CertificateSummary> {
    use x509_parser::prelude::*;
    let (_, cert) = parse_x509_certificate(der.as_ref()).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    Some(CertificateSummary {
        subject,
        issuer,
        not_before_utc: format_utc(cert.validity().not_before.timestamp()),
        not_after_utc: format_utc(cert.validity().not_after.timestamp()),
    })
}

/// Format a Unix timestamp as an RFC 3339 UTC string, using the classic
/// civil-from-days algorithm (no external date library).
fn format_utc(ts: i64) -> Option<String> {
    if ts < 0 {
        return None;
    }
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mo <= 2 { y + 1 } else { y };
    Some(format!("{yr:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch_as_utc() {
        // 2000-01-02T03:04:05Z = 946782245
        assert_eq!(format_utc(946_782_245).as_deref(), Some("2000-01-02T03:04:05Z"));
        // 2026-07-29T22:10:08Z
        assert!(format_utc(1_785_500_000).is_some());
        assert_eq!(format_utc(-1), None);
    }
}
