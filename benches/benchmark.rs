use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ip_tools::{get_local_ip, list_net_ifs, LatencyStats};

fn bench_get_local_ip(c: &mut Criterion) {
    c.bench_function("get_local_ip", |b| {
        b.iter(get_local_ip);
    });
}

fn bench_list_net_ifs(c: &mut Criterion) {
    c.bench_function("list_net_ifs", |b| {
        b.iter(list_net_ifs);
    });
}

/// Benchmark the probe engine's latency aggregation (percentiles, mean,
/// jitter) for typical `probe --count N` sizes, plus one large run.
fn bench_latency_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency_stats");
    for n in [10usize, 100, 10_000] {
        let mut stats = LatencyStats::default();
        for v in 0..n {
            stats.push(v.try_into().expect("usize fits u64"));
        }
        group.bench_with_input(BenchmarkId::new("summarize", n), &stats, |b, stats| {
            b.iter(|| stats.summarize());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_get_local_ip, bench_list_net_ifs, bench_latency_stats);
criterion_main!(benches);
