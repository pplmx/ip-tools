//! `dns` subcommand handler.

use super::{parse_custom_servers, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::dns::DnsClient;
use ip_tools::model::{DnsObservation, DnsRecordType, ResolverKind};
use ip_tools::report::{render_dns, to_json};
use ip_tools::target::Target;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

/// Resolve a hostname and report the DNS observations for each record type.
pub(super) async fn run_dns(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let target_str = sub_m.get_one::<String>("target").expect("required target");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
    let timeout = Duration::from_millis(timeout_ms);

    let target = match Target::parse(target_str, DEFAULT_PORT) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let custom: Vec<SocketAddr> = match parse_custom_servers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let only_v6 = sub_m.get_flag("ipv6");
    let insecure = sub_m.get_flag("insecure");
    let doh_endpoints: Vec<String> = sub_m
        .get_many::<String>("doh")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();

    let record_types = if only_v6 {
        vec![DnsRecordType::Aaaa]
    } else {
        vec![DnsRecordType::A, DnsRecordType::Aaaa]
    };

    // An IP-literal target is already an address: there is nothing to resolve,
    // and treating it as a name would report a confusing "no records found"
    // error from the resolvers (and a spurious `--strict` failure). Every other
    // subcommand already short-circuits literals; `dns` reports the literal as
    // its own record for the matching family and an empty (no-records,
    // no-error) answer for the other — like a NODATA reply.
    let literal = target
        .host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok();
    let observations = if let Some(literal) = literal {
        literal_observations(&target.host, literal, &record_types)
    } else {
        let client = DnsClient::new(&custom, timeout, 1);
        let mut obs = Vec::new();
        for rt in record_types {
            obs.extend(client.resolve(&target.host, rt).await);
            for endpoint in &doh_endpoints {
                obs.push(ip_tools::dns::doh_query(endpoint, &target.host, rt, timeout, insecure).await);
            }
        }
        obs
    };

    // `--strict`: a failed lookup is an observation, but scripting/CI often
    // wants a non-zero exit when any resolver could not answer. Output above
    // is still rendered in full either way.
    let failed = if sub_m.get_flag("strict") {
        observations.iter().filter(|o| o.error.is_some()).count()
    } else {
        0
    };

    if json {
        println!("{}", to_json(&observations));
    } else {
        print!("{}", render_dns(&target.host, &observations));
    }
    if failed > 0 {
        eprintln!("Error: {failed}/{} DNS lookups failed (--strict)", observations.len());
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Observations for an IP-literal target: the literal is its own record for
/// the matching address family and an empty (no-records) observation for the
/// other family. No resolver is consulted, so the answer is deterministic and
/// never a lookup error. Reported under [`ResolverKind::System`] purely as the
/// "no resolver involved" label; the observation itself carries no ambiguity.
fn literal_observations(host: &str, literal: IpAddr, record_types: &[DnsRecordType]) -> Vec<DnsObservation> {
    record_types
        .iter()
        .map(|&rt| DnsObservation {
            hostname: host.to_string(),
            resolver: ResolverKind::System,
            record_type: rt,
            records: match (rt, literal) {
                (DnsRecordType::A, IpAddr::V4(v4)) => vec![IpAddr::V4(v4)],
                (DnsRecordType::Aaaa, IpAddr::V6(v6)) => vec![IpAddr::V6(v6)],
                _ => Vec::new(),
            },
            latency_ms: Some(0),
            error: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_observations_report_the_address_for_its_records() {
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let obs = literal_observations("1.1.1.1", v4, &[DnsRecordType::A, DnsRecordType::Aaaa]);
        assert_eq!(obs.len(), 2);
        let a = obs
            .iter()
            .find(|o| o.record_type == DnsRecordType::A)
            .expect("A observation");
        assert_eq!(a.records, vec![v4]);
        assert_eq!(a.latency_ms, Some(0));
        assert!(a.error.is_none(), "a literal is never a lookup failure");
        let aaaa = obs
            .iter()
            .find(|o| o.record_type == DnsRecordType::Aaaa)
            .expect("AAAA observation");
        assert!(aaaa.records.is_empty(), "other family is NODATA: {aaaa:?}");
        assert!(aaaa.error.is_none(), "other family is NODATA, not an error");

        // An IPv6 literal reports AAAA; its (absent) A row is empty NODATA.
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let obs6 = literal_observations("[2001:db8::1]", v6, &[DnsRecordType::A, DnsRecordType::Aaaa]);
        let aaaa6 = obs6
            .iter()
            .find(|o| o.record_type == DnsRecordType::Aaaa)
            .expect("AAAA observation");
        assert_eq!(aaaa6.records, vec![v6]);
        let a6 = obs6
            .iter()
            .find(|o| o.record_type == DnsRecordType::A)
            .expect("A observation");
        assert!(a6.records.is_empty());
        assert!(obs6.iter().all(|o| o.error.is_none()));

        // `--ipv6` (AAAA-only) still yields a per-record-type observation.
        let obs_v6_only = literal_observations("1.1.1.1", v4, &[DnsRecordType::Aaaa]);
        assert_eq!(obs_v6_only.len(), 1);
        assert!(obs_v6_only[0].records.is_empty());
    }
}
