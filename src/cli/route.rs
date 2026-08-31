//! `route` subcommand handler.

use super::{resolve_for_tcp_servers, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::report::{render_route, render_route_repeat, to_json};
use ip_tools::route as ip_route;
use ip_tools::style::Style;
use ip_tools::target::Target;
use ip_tools::RouteHop;
use ip_tools::RouteRepeat;
use ip_tools::TracerouteConfig;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

/// Trace the network path to a host (Linux, needs root). Runs the blocking
/// traceroute off the async runtime, then reverse-resolves router names.
/// With `--count N` (>1) the trace is repeated and the per-hop observations
/// are aggregated across runs (see [`run_route_repeat`]).
#[allow(clippy::too_many_lines)] // orchestration: parse, guard zero/oversize, trace, render
pub(super) async fn run_route(sub_m: &ArgMatches, style: Style) -> ExitCode {
    let json = sub_m.get_flag("json");
    let csv = sub_m.get_flag("csv");
    let count = *sub_m.get_one::<usize>("count").expect("count has default");
    let target_str = sub_m.get_one::<String>("target").expect("required target");
    let max_hops = *sub_m.get_one::<u8>("max-hops").expect("max-hops has default");
    let probes_per_hop = *sub_m
        .get_one::<u8>("probes-per-hop")
        .expect("probes-per-hop has default");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");

    if let Err(e) = super::ensure_single_output_format(sub_m) {
        eprintln!("Error: {e}");
        return ExitCode::FAILURE;
    }

    // A 0-repeat request is a caller mistake, and silently running a single
    // trace would hide it. `--count 0`, `--max-hops 0` and `--probes-per-hop 0`
    // are all rejected at argument parse by the shared nonzero parsers (exit 2,
    // like `--timeout`/`--concurrency`) — no in-handler zero guard survives.
    // `--count` is additionally capped at `u16::MAX` because the per-hop
    // `answered` aggregate is a `u16` — a larger count would silently wrap a
    // busy hop to "0 runs answered" (false 100% loss); that is a range bound,
    // not a zero-input slip, so it stays an in-handler exit-1 error.
    if count > u16::MAX as usize {
        eprintln!("Error: --count is at most 65535 for route (the per-hop aggregate is 16-bit)");
        return ExitCode::FAILURE;
    }

    let target = match Target::parse(target_str, DEFAULT_PORT) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Resolution is bounded by the user's `--timeout`, not the blanket
    // default: every other probe command threads its `--timeout` into DNS so
    // a slow resolver cannot hold a `route --timeout 200` trace for ~10 s
    // (the default is 5 s per lookup, A + AAAA).
    let addresses =
        match resolve_for_tcp_servers(&target.host, &[], &[], &[], false, Duration::from_millis(timeout_ms)).await {
            Ok(addrs) => addrs,
            Err(err) => {
                eprintln!("Error: {err}");
                return ExitCode::FAILURE;
            }
        };
    let Some(&dest_ip) = addresses.iter().find(|a| a.is_ipv4()) else {
        eprintln!("Error: route diagnostics need an IPv4 address for {}", target.host);
        return ExitCode::FAILURE;
    };

    let cfg = TracerouteConfig {
        // `--max-hops 0` / `--probes-per-hop 0` were rejected up front, so no
        // clamp is needed here (a `.max(1)` would be unreachable dead code).
        max_hops,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_hop,
    };

    if count > 1 {
        return run_route_repeat(sub_m, dest_ip, cfg, count, json, csv, style).await;
    }

    let hops = match tokio::task::spawn_blocking(move || ip_route::traceroute(dest_ip, &cfg)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("Error: traceroute task failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Reverse-resolve router addresses (best effort).
    let mut hops = hops;
    if let Ok(builder) = hickory_resolver::TokioResolver::builder_tokio() {
        if let Ok(resolver) = builder.build() {
            for hop in &mut hops {
                if let Some(addr) = hop.addr {
                    if let Ok(lookup) = resolver.reverse_lookup(addr).await {
                        if let Some(rec) = lookup.answers().first() {
                            if let hickory_resolver::proto::rr::RData::PTR(name) = &rec.data {
                                hop.hostname = Some(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // `--strict`: a lost hop is an observation (routers routinely filter
    // TTL-expired replies), but scripting/CI often wants a non-zero exit when
    // any hop was lost. Output above is still rendered in full either way.
    let lost = if sub_m.get_flag("strict") {
        hops.iter().filter(|h| h.lost).count()
    } else {
        0
    };

    if csv {
        print!("{}", render_route_csv(&hops));
    } else if json {
        println!("{}", to_json(&hops));
    } else {
        print!("{}", render_route(&style, &hops));
    }
    if lost > 0 {
        eprintln!("Error: {lost} route hop(s) lost (--strict)");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `route --count N` (N > 1): repeat the traceroute and aggregate per-hop
/// latency and router addresses across runs, so a path change (flapping
/// next-hop, load-balanced router, BGP/MPLS churn) that a single trace cannot
/// show becomes visible.
async fn run_route_repeat(
    sub_m: &ArgMatches,
    dest_ip: IpAddr,
    cfg: TracerouteConfig,
    count: usize,
    json: bool,
    csv: bool,
    style: Style,
) -> ExitCode {
    let mut repeat = match tokio::task::spawn_blocking(move || ip_route::traceroute_repeat(dest_ip, cfg, count)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("Error: traceroute task failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Best-effort reverse hostname for hops answered by one stable router. A
    // hop whose router changed between runs is the divergence itself — naming
    // one of the addresses would be misleading — so those stay unlabelled.
    resolve_repeat_hostnames(&mut repeat).await;

    // `--strict`: a hop that never answered across any run is a fully-lost
    // hop (the repeat analogue of a lost single-trace hop).
    let lost = if sub_m.get_flag("strict") {
        repeat.hops.iter().filter(|h| h.answered == 0).count()
    } else {
        0
    };

    if csv {
        print!("{}", render_route_repeat_csv(&repeat));
    } else if json {
        println!("{}", to_json(&repeat));
    } else {
        print!("{}", render_route_repeat(&style, &repeat));
    }
    if lost > 0 {
        eprintln!("Error: {lost} route hop(s) entirely lost across {count} runs (--strict)");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Reverse-resolve each repeat hop's single router address (best effort).
async fn resolve_repeat_hostnames(repeat: &mut RouteRepeat) {
    if let Ok(builder) = hickory_resolver::TokioResolver::builder_tokio() {
        if let Ok(resolver) = builder.build() {
            for hop in &mut repeat.hops {
                if hop.addrs.len() != 1 {
                    continue;
                }
                let addr = hop.addrs[0];
                if let Ok(lookup) = resolver.reverse_lookup(addr).await {
                    if let Some(rec) = lookup.answers().first() {
                        if let hickory_resolver::proto::rr::RData::PTR(name) = &rec.data {
                            hop.hostname = Some(name.to_string());
                        }
                    }
                }
            }
        }
    }
}

/// Render a repeated-traceroute aggregation as CSV: a header then one row per
/// hop, with the aggregated router address(es), min/p50/max latency, answer
/// rate and path-change verdict (RFC 4180 quoting).
fn render_route_repeat_csv(repeat: &RouteRepeat) -> String {
    let mut out = String::from("ttl,hostname,addr,rtt_min_ms,rtt_med_ms,rtt_max_ms,answered,runs,path_changed\n");
    for h in &repeat.hops {
        out.push_str(&h.ttl.to_string());
        out.push(',');
        out.push_str(&csv_field(h.hostname.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(&hop_addrs(h)));
        out.push(',');
        for rtt in [h.rtt.min, h.rtt.p50, h.rtt.max] {
            out.push_str(&csv_field(&rtt.map_or_else(String::new, |ms| ms.to_string())));
            out.push(',');
        }
        out.push_str(&h.answered.to_string());
        out.push(',');
        out.push_str(&repeat.runs.to_string());
        out.push(',');
        out.push_str(if h.path_changed { "1" } else { "0" });
        out.push('\n');
    }
    out
}

/// The distinct router addresses of a repeat hop, `;`-joined.
fn hop_addrs(h: &ip_tools::RouteHopStats) -> String {
    h.addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(";")
}

/// Render a traceroute path as CSV: a header then one row per hop, with
/// empty fields for lost hops or missing hostnames (RFC 4180 quoting).
fn render_route_csv(hops: &[RouteHop]) -> String {
    let mut out = String::from("ttl,hostname,addr,rtt_ms,lost\n");
    for h in hops {
        out.push_str(&h.ttl.to_string());
        out.push(',');
        out.push_str(&csv_field(h.hostname.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(h.addr.map_or_else(String::new, |a| a.to_string()).as_str()));
        out.push(',');
        out.push_str(&csv_field(
            h.rtt_ms.map_or_else(String::new, |ms| ms.to_string()).as_str(),
        ));
        out.push(',');
        out.push_str(if h.lost { "1" } else { "0" });
        out.push('\n');
    }
    out
}

use super::csv_field;

#[cfg(test)]
mod tests {
    use super::csv_field;
    use super::*;
    use ip_tools::LatencyStats;

    #[test]
    fn render_route_repeat_csv_aggregates_answered_and_path_change() {
        let mut stable = LatencyStats::default();
        stable.push(2);
        stable.push(4);
        let repeat = RouteRepeat {
            runs: 2,
            hops: vec![
                ip_tools::RouteHopStats {
                    ttl: 1,
                    answered: 2,
                    addrs: vec!["192.0.2.1".parse().unwrap()],
                    hostname: Some("r1.example.com".into()),
                    rtt: stable.summarize(),
                    path_changed: false,
                },
                ip_tools::RouteHopStats {
                    ttl: 2,
                    answered: 2,
                    // No latency samples: a divergent hop with unknown RTT must
                    // still render its `;`-joined addrs + path_changed verdict.
                    addrs: vec!["192.0.2.2".parse().unwrap(), "192.0.2.9".parse().unwrap()],
                    hostname: None,
                    rtt: LatencyStats::default().summarize(),
                    path_changed: true,
                },
                ip_tools::RouteHopStats {
                    ttl: 3,
                    answered: 0,
                    addrs: Vec::new(),
                    hostname: None,
                    rtt: ip_tools::LatencyStats::default().summarize(),
                    path_changed: false,
                },
            ],
        };
        let out = render_route_repeat_csv(&repeat);
        let mut lines = out.lines();
        assert_eq!(
            lines.next(),
            Some("ttl,hostname,addr,rtt_min_ms,rtt_med_ms,rtt_max_ms,answered,runs,path_changed")
        );
        // Stable hop: sole addr, min/med/max latency, 2/2 answered.
        assert_eq!(lines.next(), Some("1,r1.example.com,192.0.2.1,2,2,4,2,2,0"));
        // Divergent hop: `;`-joined addrs and path_changed=1 (empty latency).
        assert_eq!(lines.next(), Some("2,,192.0.2.2;192.0.2.9,,,,2,2,1"));
        // Fully-lost hop: everything empty, answered=0.
        assert_eq!(lines.next(), Some("3,,,,,,0,2,0"));
        assert!(lines.next().is_none());
    }

    #[test]
    fn render_route_csv_emits_one_row_per_hop() {
        let hops = [
            RouteHop {
                ttl: 1,
                addr: Some("192.0.2.1".parse().unwrap()),
                hostname: Some("r1.example.com".into()),
                rtt_ms: Some(3),
                lost: false,
            },
            RouteHop {
                ttl: 2,
                addr: None,
                hostname: None,
                rtt_ms: None,
                lost: true,
            },
            RouteHop {
                ttl: 3,
                addr: Some("192.0.2.3".parse().unwrap()),
                hostname: None,
                rtt_ms: Some(12),
                lost: false,
            },
        ];
        let out = render_route_csv(&hops);
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some("ttl,hostname,addr,rtt_ms,lost"));
        // Reachable hop: full row, not lost.
        assert_eq!(lines.next(), Some("1,r1.example.com,192.0.2.1,3,0"));
        // Lost hop: empty hostname/addr/rtt, lost=1.
        assert_eq!(lines.next(), Some("2,,,,1"));
        assert_eq!(lines.next(), Some("3,,192.0.2.3,12,0"));
        assert!(lines.next().is_none());
    }

    #[test]
    fn csv_field_quotes_and_doubles_embedded_quotes() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("plain"), "plain");
    }
}
