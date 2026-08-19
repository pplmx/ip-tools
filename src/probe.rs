//! Repeated probing and statistics.
//!
//! A single attempt is insufficient to diagnose intermittent connectivity.
//! This module repeats a probe against one destination and aggregates
//! success/failure rates, latency percentiles and the failure distribution.
//! Latencies are measured with monotonic clocks.

use crate::model::probe::{FailureCount, ProbeResult};
use crate::model::{FailureKind, LatencyStats};
use crate::tcp;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// Repeatedly probe TCP connectivity to `destination` `attempts` times.
///
/// Attempts are run sequentially per address so that the latency distribution
/// (including jitter) reflects genuine per-attempt timing rather than
/// concurrent-request skew. Returns an aggregated [`ProbeResult`].
pub async fn tcp_repeat(destination: SocketAddr, attempts: usize, timeout: Duration) -> ProbeResult {
    let mut latency = LatencyStats::default();
    let mut failures: HashMap<FailureKind, usize> = HashMap::new();
    let mut successes = 0usize;

    for _ in 0..attempts {
        let obs = tcp::probe(destination, timeout).await;
        if obs.success {
            successes += 1;
            latency.push(obs.latency_ms.unwrap_or(0));
        } else if let Some(err) = obs.failure {
            *failures.entry(err.kind).or_default() += 1;
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
