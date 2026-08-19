//! `dns` subcommand handler.

use super::{parse_custom_servers, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::dns::DnsClient;
use ip_tools::model::DnsRecordType;
use ip_tools::report::{render_dns, to_json};
use ip_tools::target::Target;
use std::net::SocketAddr;
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

    let client = DnsClient::new(&custom, timeout, 1);
    let only_v6 = sub_m.get_flag("ipv6");

    let mut observations = Vec::new();
    let record_types = if only_v6 {
        vec![DnsRecordType::Aaaa]
    } else {
        vec![DnsRecordType::A, DnsRecordType::Aaaa]
    };
    for rt in record_types {
        observations.extend(client.resolve(&target.host, rt).await);
    }

    if json {
        println!("{}", to_json(&observations));
    } else {
        print!("{}", render_dns(&target.host, &observations));
    }
    ExitCode::SUCCESS
}
