//! `route` subcommand handler.

use super::{resolve_for_tcp, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::report::{render_route, to_json};
use ip_tools::route as ip_route;
use ip_tools::target::Target;
use ip_tools::RouteHop;
use ip_tools::TracerouteConfig;
use std::process::ExitCode;
use std::time::Duration;

/// Trace the network path to a host (Linux, needs root). Runs the blocking
/// traceroute off the async runtime, then reverse-resolves router names.
pub(super) async fn run_route(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let csv = sub_m.get_flag("csv");
    let target_str = sub_m.get_one::<String>("target").expect("required target");
    let max_hops = *sub_m.get_one::<u8>("max-hops").expect("max-hops has default");
    let probes_per_hop = *sub_m
        .get_one::<u8>("probes-per-hop")
        .expect("probes-per-hop has default");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");

    let target = match Target::parse(target_str, DEFAULT_PORT) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let addresses = match resolve_for_tcp(&target.host).await {
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
        max_hops: max_hops.max(1),
        timeout: Duration::from_millis(timeout_ms),
        probes_per_hop: probes_per_hop.max(1),
    };

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
        print!("{}", render_route(&hops));
    }
    if lost > 0 {
        eprintln!("Error: {lost} route hop(s) lost (--strict)");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
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

/// Quote a CSV field when it contains a comma, quote, or newline (RFC 4180).
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
