//! Latency statistics over repeated measurements.
//!
//! Latencies are stored as whole milliseconds (`u64`). Statistics only
//! account for successful attempts; failures are reported separately by the
//! caller.

use serde::Serialize;

/// Running latency distribution over successful samples.
#[derive(Debug, Clone, Default)]
pub struct LatencyStats {
    samples: Vec<u64>,
}

impl LatencyStats {
    /// Record one successful sample in milliseconds.
    pub fn push(&mut self, ms: u64) {
        self.samples.push(ms);
    }

    /// Number of successful samples recorded.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.samples.len()
    }

    /// Snapshot a serializable summary plus the raw samples.
    #[must_use]
    pub fn summarize(&self) -> LatencySummary {
        self.into()
    }
}

/// A serializable snapshot of a [`LatencyStats`] distribution.
///
/// Includes the raw per-attempt samples so that JSON output contains complete
/// raw observation data, not just aggregates.
#[derive(Debug, Clone, Serialize)]
pub struct LatencySummary {
    /// Number of successful samples.
    pub count: usize,
    /// Minimum latency (ms).
    pub min: Option<u64>,
    /// 50th percentile (ms).
    pub p50: Option<u64>,
    /// 90th percentile (ms).
    pub p90: Option<u64>,
    /// 95th percentile (ms).
    pub p95: Option<u64>,
    /// 99th percentile (ms).
    pub p99: Option<u64>,
    /// Maximum latency (ms).
    pub max: Option<u64>,
    /// Arithmetic mean (ms).
    pub mean: Option<u64>,
    /// Population standard deviation, used as a jitter estimate (ms).
    pub jitter: Option<u64>,
    /// Raw per-attempt latencies (only successful attempts).
    pub samples: Vec<u64>,
}

impl LatencySummary {
    /// Compute the `p`-th percentile (0..100) of the samples.
    fn percentile(sorted: &[u64], p: f64) -> Option<u64> {
        let n = sorted.len();
        if n == 0 || !(0.0..=100.0).contains(&p) {
            return None;
        }
        let idx = ((p / 100.0) * n as f64).ceil() as usize;
        let idx = idx.saturating_sub(1).min(n.saturating_sub(1));
        sorted.get(idx).copied()
    }
}

impl From<&LatencyStats> for LatencySummary {
    fn from(stats: &LatencyStats) -> Self {
        let mut sorted = stats.samples.clone();
        sorted.sort_unstable();
        let n = stats.samples.len();
        let min = sorted.first().copied();
        let max = sorted.last().copied();

        let mean = if n == 0 {
            None
        } else {
            let sum: u128 = stats.samples.iter().map(|&s| u128::from(s)).sum();
            Some((sum / n as u128) as u64)
        };

        let jitter = if n == 0 {
            None
        } else {
            let mean_f = mean.unwrap_or(0) as f64;
            let variance = stats
                .samples
                .iter()
                .map(|&s| {
                    let d = s as f64 - mean_f;
                    d * d
                })
                .sum::<f64>()
                / n as f64;
            Some(variance.sqrt() as u64)
        };

        Self {
            count: n,
            min,
            p50: Self::percentile(&sorted, 50.0),
            p90: Self::percentile(&sorted, 90.0),
            p95: Self::percentile(&sorted, 95.0),
            p99: Self::percentile(&sorted, 99.0),
            max,
            mean,
            jitter,
            samples: stats.samples.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_stats_produce_none_aggregates() {
        let s = LatencyStats::default();
        let sum = s.summarize();
        assert_eq!(sum.count, 0);
        assert!(sum.min.is_none() && sum.p50.is_none() && sum.jitter.is_none());
        assert!(sum.samples.is_empty());
    }

    #[test]
    fn percentiles_are_computed() {
        let mut s = LatencyStats::default();
        for v in [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000] {
            s.push(v);
        }
        let sum = s.summarize();
        assert_eq!(sum.min, Some(100));
        assert_eq!(sum.max, Some(1000));
        assert_eq!(sum.p50, Some(500));
        assert_eq!(sum.p90, Some(900));
        // Nearest-rank: rank = ceil(p/100 * n); for n=10 p95 and p99 map to
        // the largest sample.
        assert_eq!(sum.p95, Some(1000));
        assert_eq!(sum.p99, Some(1000));
    }

    #[test]
    fn mean_and_jitter_are_stable() {
        let mut s = LatencyStats::default();
        s.push(100);
        s.push(100);
        s.push(100);
        let sum = s.summarize();
        assert_eq!(sum.mean, Some(100));
        assert_eq!(sum.jitter, Some(0));
    }
}
