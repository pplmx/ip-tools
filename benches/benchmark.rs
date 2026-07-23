use criterion::{criterion_group, criterion_main, Criterion};
use ip_tools::{get_local_ip, list_net_ifs};

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

criterion_group!(benches, bench_get_local_ip, bench_list_net_ifs);
criterion_main!(benches);
