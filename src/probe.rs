//! Repeated probing and statistics.
//!
//! A single attempt is insufficient to diagnose intermittent connectivity.
//! This module repeats a probe against one destination and aggregates
//! success/failure rates, latency percentiles and the failure distribution.
//! Latencies are measured with monotonic clocks.

use crate::model::probe::{FailureCount, ProbeResult};
use crate::model::{FailureKind, HttpObservation, LatencyStats};
use crate::tcp;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// Repeatedly probe a TLS handshake to `destination`, aggregating
/// handshake-latency statistics like [`tcp_repeat`] (with `--insecure`
/// support).
///
/// # Examples
///
/// ```no_run
/// use ip_tools::probe;
/// use std::net::SocketAddr;
/// use std::time::Duration;
///
/// # tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
/// let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
/// let r = probe::tls_repeat(addr, "1.1.1.1", 5, Duration::from_secs(3), false).await;
/// println!("tls success rate: {:.0}%", r.success_rate * 100.0);
/// # });
/// ```
pub async fn tls_repeat(
    destination: SocketAddr,
    sni: &str,
    attempts: usize,
    timeout: Duration,
    insecure: bool,
) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = if insecure {
            crate::tls::probe_insecure(destination, sni, timeout).await
        } else {
            crate::tls::probe(destination, sni, timeout).await
        };
        if obs.success {
            (true, obs.latency_ms, None)
        } else {
            (false, None, obs.failure.map(|f| f.kind))
        }
    })
    .await
}

/// Repeatedly probe TCP connectivity to `destination` `attempts` times.
///
/// Attempts are run sequentially per address so that the latency distribution
/// (including jitter) reflects genuine per-attempt timing rather than
/// concurrent-request skew. Returns an aggregated [`ProbeResult`].
///
/// # Examples
///
/// ```no_run
/// use ip_tools::probe;
/// use std::net::SocketAddr;
/// use std::time::Duration;
///
/// # tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
/// let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
/// let r = probe::tcp_repeat(addr, 10, Duration::from_secs(2)).await;
/// println!(
///     "{}% reachable, p50={:?} ms, failures={}",
///     r.success_rate * 100.0,
///     r.latency.p50,
///     r.failures,
/// );
/// # });
/// ```
pub async fn tcp_repeat(destination: SocketAddr, attempts: usize, timeout: Duration) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = tcp::probe(destination, timeout).await;
        if obs.success {
            (true, obs.latency_ms, None)
        } else {
            (false, None, obs.failure.map(|f| f.kind))
        }
    })
    .await
}

/// Repeatedly probe HTTPS/HTTP1.1 to `destination` presenting `host`/`method`
/// (and the request `path` and any extra `headers`) `attempts` times,
/// aggregating latency statistics like [`tcp_repeat`].
// The request shape (host/method/path/headers) mirrors the underlying probe
// so the repeat variants stay a thin aggregation wrapper; the arity is a
// deliberate, readable signature rather than a hidden options struct.
#[allow(clippy::too_many_arguments)]
pub async fn http_repeat(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    attempts: usize,
    timeout: Duration,
    insecure: bool,
) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = if insecure {
            crate::http::probe_insecure(destination, host, method, path, headers, body, timeout).await
        } else {
            crate::http::probe(destination, host, method, path, headers, body, timeout).await
        };
        http_outcome(obs)
    })
    .await
}

/// Repeatedly probe HTTPS/HTTP2 to `destination` presenting `host`/`method`
/// `attempts` times, aggregating latency statistics like [`tcp_repeat`].
///
/// # Examples
///
/// ```no_run
/// use ip_tools::probe;
/// use std::net::SocketAddr;
/// use std::time::Duration;
///
/// # tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
/// let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
/// let r = probe::http2_repeat(addr, "1.1.1.1", "HEAD", "/", &[], None, 5, Duration::from_secs(3), false).await;
/// println!("http2 success rate: {:.0}%", r.success_rate * 100.0);
/// # });
/// ```
#[allow(clippy::too_many_arguments)] // see `http_repeat`
pub async fn http2_repeat(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    attempts: usize,
    timeout: Duration,
    insecure: bool,
) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = if insecure {
            crate::http2::probe_insecure(destination, host, method, path, headers, body, timeout).await
        } else {
            crate::http2::probe(destination, host, method, path, headers, body, timeout).await
        };
        http_outcome(obs)
    })
    .await
}

/// Repeatedly probe HTTPS/HTTP3 (QUIC) to `destination` presenting
/// `host`/`method` `attempts` times, aggregating latency statistics like
/// [`tcp_repeat`].
#[allow(clippy::too_many_arguments)] // see `http_repeat`
pub async fn http3_repeat(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    attempts: usize,
    timeout: Duration,
    insecure: bool,
) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = if insecure {
            crate::http3::probe_insecure(destination, host, method, path, headers, body, timeout).await
        } else {
            crate::http3::probe(destination, host, method, path, headers, body, timeout).await
        };
        http_outcome(obs)
    })
    .await
}

/// Map a single HTTP probe observation onto the shared (success, latency,
/// failure-kind) aggregation tuple: an error status (e.g. 5xx) is still a
/// completed probe, so only a transport/protocol failure counts as failed.
fn http_outcome(obs: HttpObservation) -> (bool, Option<u64>, Option<FailureKind>) {
    if obs.failure.is_none() {
        (true, obs.latency_ms, None)
    } else {
        let kind = obs.failure.map(|f| f.kind);
        (false, None, kind)
    }
}

/// Shared aggregation over repeated per-attempt outcomes: success flag,
/// latency millis (on success), and the classified failure kind (on failure).
///
/// Attempts are run sequentially per address so that the latency distribution
/// (including jitter) reflects genuine per-attempt timing rather than
/// concurrent-request skew.
async fn repeat_impl<F, Fut>(destination: SocketAddr, attempts: usize, mut attempt: F) -> ProbeResult
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = (bool, Option<u64>, Option<FailureKind>)>,
{
    let mut latency = LatencyStats::default();
    let mut failures: HashMap<FailureKind, usize> = HashMap::new();
    let mut successes = 0usize;

    for _ in 0..attempts {
        let (ok, latency_ms, kind) = attempt().await;
        if ok {
            successes += 1;
            latency.push(latency_ms.unwrap_or(0));
        } else if let Some(kind) = kind {
            *failures.entry(kind).or_default() += 1;
        }
    }

    let failures_total: usize = failures.values().sum();
    let mut failure_counts: Vec<FailureCount> = failures
        .into_iter()
        .map(|(kind, count)| FailureCount { kind, count })
        .collect();
    failure_counts.sort_by_key(|f| std::cmp::Reverse(f.count));

    ProbeResult {
        destination,
        attempts,
        successes,
        failures: failures_total,
        success_rate: if attempts == 0 {
            0.0
        } else {
            successes as f64 / attempts as f64
        },
        latency: latency.summarize(),
        failure_counts,
    }
}
