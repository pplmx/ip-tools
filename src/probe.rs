//! Repeated probing and statistics.
//!
//! A single attempt is insufficient to diagnose intermittent connectivity.
//! This module repeats a probe against one destination and aggregates
//! success/failure rates, latency percentiles and the failure distribution.
//! Latencies are measured with monotonic clocks.

use crate::model::probe::{FailureCount, ProbeResult, StatusCount};
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
    tls_repeat_with_version(
        destination,
        sni,
        attempts,
        timeout,
        insecure,
        crate::tls::TlsProtocol::Auto,
    )
    .await
}

/// [`tls_repeat`] offering only the given TLS protocol version during the
/// handshake (the `--tls-version` slice of the repeat probes).
pub async fn tls_repeat_with_version(
    destination: SocketAddr,
    sni: &str,
    attempts: usize,
    timeout: Duration,
    insecure: bool,
    protocol: crate::tls::TlsProtocol,
) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = if insecure {
            crate::tls::probe_insecure_with_version(destination, sni, timeout, protocol).await
        } else {
            crate::tls::probe_with_version(destination, sni, timeout, protocol).await
        };
        if obs.success {
            (true, obs.latency_ms, None, None, None)
        } else {
            (false, None, obs.failure.map(|f| f.kind), None, None)
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
            (true, obs.latency_ms, None, None, None)
        } else {
            (false, None, obs.failure.map(|f| f.kind), None, None)
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
    http_repeat_with_version(
        destination,
        host,
        method,
        path,
        headers,
        body,
        attempts,
        timeout,
        insecure,
        crate::tls::TlsProtocol::Auto,
    )
    .await
}

/// [`http_repeat`] offering only the given TLS protocol version (the
/// `--tls-version` slice of the repeat probes).
#[allow(clippy::too_many_arguments)]
pub async fn http_repeat_with_version(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    attempts: usize,
    timeout: Duration,
    insecure: bool,
    protocol: crate::tls::TlsProtocol,
) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = if insecure {
            crate::http::probe_insecure_with_version(destination, host, method, path, headers, body, timeout, protocol)
                .await
        } else {
            crate::http::probe_with_version(destination, host, method, path, headers, body, timeout, protocol).await
        };
        http_outcome(obs)
    })
    .await
}

/// Repeatedly probe cleartext HTTP/1.1 (`--plain`) to `destination` presenting
/// `host` as the `Host` header `attempts` times.
///
/// Aggregates latency statistics like [`http_repeat_with_version`] but without
/// any TLS handshake — for internal services, captive portals and HTTP-only
/// health checks that a TLS repeat would fail to observe.
#[allow(clippy::too_many_arguments)] // see `http_repeat`
pub async fn http_repeat_plain(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    attempts: usize,
    timeout: Duration,
) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = crate::http::probe_plain(destination, host, method, path, headers, body, timeout).await;
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
    http2_repeat_with_version(
        destination,
        host,
        method,
        path,
        headers,
        body,
        attempts,
        timeout,
        insecure,
        crate::tls::TlsProtocol::Auto,
    )
    .await
}

/// [`http2_repeat`] offering only the given TLS protocol version (the
/// `--tls-version` slice of the repeat probes).
#[allow(clippy::too_many_arguments)]
pub async fn http2_repeat_with_version(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    attempts: usize,
    timeout: Duration,
    insecure: bool,
    protocol: crate::tls::TlsProtocol,
) -> ProbeResult {
    repeat_impl(destination, attempts, || async {
        let obs = if insecure {
            crate::http2::probe_insecure_with_version(destination, host, method, path, headers, body, timeout, protocol)
                .await
        } else {
            crate::http2::probe_with_version(destination, host, method, path, headers, body, timeout, protocol).await
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
/// failure-kind, status, TTFB) aggregation tuple: an error status (e.g. 5xx)
/// is still a completed probe, so only a transport/protocol failure counts as
/// failed. The fourth tuple element is the observed HTTP status (for
/// surfacing the status distribution in the report), present on every
/// completed response; the fifth is the time-to-first-byte (server-response
/// latency), `None` when no headers arrived.
///
/// A response whose body never completes (headers + status arrived, then the
/// stream stalled past `--timeout` — `body_bytes: None`) is *not* a clean
/// success: the single-shot probe surfaces it as `body: incomplete (timed
/// out)`, so the repeat aggregate must not fold it into `successes` with the
/// latency pushed at the full wall-clock `--timeout` (which would report a
/// server that answered in 0 ms as `latency p95 ≈ timeout` and let a
/// body-stalling endpoint satisfy `--expect-rate 1 --expect-status 2xx`). It
/// is bucketed as a `Timeout` failure while its status and TTFB are still
/// recorded — the server did answer, it just never delivered the body.
fn http_outcome(obs: HttpObservation) -> (bool, Option<u64>, Option<FailureKind>, Option<u16>, Option<u64>) {
    if obs.failure.is_none() {
        if obs.body_bytes.is_none() {
            return (false, None, Some(FailureKind::Timeout), obs.status, obs.ttfb_ms);
        }
        (true, obs.latency_ms, None, obs.status, obs.ttfb_ms)
    } else {
        let kind = obs.failure.map(|f| f.kind);
        (false, None, kind, None, None)
    }
}

/// Shared aggregation over repeated per-attempt outcomes: success flag,
/// latency millis (on success), the classified failure kind (on failure),
/// the observed HTTP status, and the time-to-first-byte (for HTTP repeats).
///
/// Attempts are run sequentially per address so that the latency distribution
/// (including jitter) reflects genuine per-attempt timing rather than
/// concurrent-request skew.
async fn repeat_impl<F, Fut>(destination: SocketAddr, attempts: usize, mut attempt: F) -> ProbeResult
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = (bool, Option<u64>, Option<FailureKind>, Option<u16>, Option<u64>)>,
{
    let mut latency = LatencyStats::default();
    let mut ttfb = LatencyStats::default();
    let mut failures: HashMap<FailureKind, usize> = HashMap::new();
    let mut statuses: HashMap<u16, usize> = HashMap::new();
    let mut successes = 0usize;

    for _ in 0..attempts {
        let (ok, latency_ms, kind, status, ttfb_ms) = attempt().await;
        if let Some(status) = status {
            *statuses.entry(status).or_default() += 1;
        }
        // TTFB is the time until response headers arrive, so it is a valid
        // sample for every attempt that reached headers — including one whose
        // body later stalled (the single-shot probe reports its ttfb too).
        // Transport failures carry `None` and are unaffected.
        if let Some(ttfb_ms) = ttfb_ms {
            ttfb.push(ttfb_ms);
        }
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
    // Sort most-frequent-first; a tie (equal counts, e.g. a 200x3 / 503x3
    // flapper) must fall back to a stable kind key — the HashMap iteration
    // order is randomized per process, so a count-only sort made the JSON/CSV
    // byte-for-byte different between runs on exactly the flapping scenario
    // this report exists to expose. `failure.kind as u8` is the declaration
    // order of the fieldless enum: a deterministic secondary key.
    failure_counts.sort_by_key(|failure| (std::cmp::Reverse(failure.count), failure.kind as u8));
    let mut status_counts: Vec<StatusCount> = statuses
        .into_iter()
        .map(|(status, count)| StatusCount { status, count })
        .collect();
    status_counts.sort_by_key(|s| (std::cmp::Reverse(s.count), s.status));

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
        ttfb: ttfb.summarize(),
        failure_counts,
        status_counts,
    }
}

#[cfg(test)]
mod tests {
    use super::{http_outcome, repeat_impl};
    use crate::model::FailureKind;

    /// A transport-success HTTP observation whose body never completed.
    fn stalled_obs(latency_ms: u64) -> crate::model::HttpObservation {
        crate::model::HttpObservation {
            destination: "192.0.2.1:443".parse().unwrap(),
            host: "stall.invalid".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: None,
            headers: Vec::new(),
            body_bytes: None, // headers arrived, then the stream stalled
            body_capped: false,
            body_snippet: None,
            latency_ms: Some(latency_ms), // the full wall-clock wait
            ttfb_ms: Some(0),             // headers answered immediately
            failure: None,
        }
    }

    #[test]
    fn http_outcome_treats_a_stalled_body_as_a_failure() {
        // Headers + status arrived, but the body never completed: the attempt
        // must not aggregate as a clean success with the latency pushed at the
        // full `--timeout` wall-clock. Status and TTFB stay recorded (the
        // server did answer), but the attempt counts as a Timeout failure.
        let (ok, latency, kind, status, ttfb) = http_outcome(stalled_obs(801));
        assert!(!ok, "a body-stalled exchange is not a completed probe");
        assert_eq!(latency, None, "no polluting timeout-scaled latency sample");
        assert_eq!(kind, Some(FailureKind::Timeout));
        assert_eq!(status, Some(200), "the status is still surfaced");
        assert_eq!(ttfb, Some(0), "the server-response latency is still sampled");
    }

    #[test]
    fn http_outcome_keeps_a_completed_body_a_success() {
        let mut obs = stalled_obs(9);
        obs.body_bytes = Some(12); // body completed
        let (ok, latency, kind, _, ttfb) = http_outcome(obs);
        assert!(ok);
        assert_eq!(latency, Some(9));
        assert_eq!(kind, None);
        assert_eq!(ttfb, Some(0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn repeat_impl_aggregates_http_status_counts() {
        // A repeat HTTP probe must surface the status distribution while
        // preserving the transport-success semantics: a completed response
        // with any status (even 503) counts as a successful exchange.
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempt = std::sync::Arc::new(AtomicU32::new(0));
        let r = repeat_impl("1.1.1.1:443".parse().unwrap(), 4, move || {
            let attempt = std::sync::Arc::clone(&attempt);
            async move {
                match attempt.fetch_add(1, Ordering::SeqCst) + 1 {
                    1..=3 => (true, Some(5), None, Some(200), Some(2)),
                    4 => (true, Some(9), None, Some(503), Some(8)),
                    _ => (false, None, None, None, None),
                }
            }
        })
        .await;
        assert_eq!(r.successes, 4, "transport-success semantics preserved");
        assert_eq!(r.failures, 0);
        assert_eq!(r.status_counts.len(), 2, "200 and 503 both recorded");
        let pairs: Vec<(u16, usize)> = r.status_counts.iter().map(|s| (s.status, s.count)).collect();
        assert!(pairs.contains(&(200, 3)), "200x3: {pairs:?}");
        assert!(pairs.contains(&(503, 1)), "503x1: {pairs:?}");
        // TTFB aggregates across the successful attempts: samples [2,2,2,8].
        assert_eq!(r.ttfb.count, 4, "ttfb should cover every completed response");
        assert_eq!(r.ttfb.min, Some(2));
        assert_eq!(r.ttfb.max, Some(8));
        assert_eq!(r.ttfb.p50, Some(2));
    }
}
