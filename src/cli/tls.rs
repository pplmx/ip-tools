//! `tls` subcommand handler.

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::model::TlsObservation;
use ip_tools::report::render_tls;
use ip_tools::tls as ip_tls;
use std::process::ExitCode;

/// Resolve a target's addresses and perform a TLS handshake (with the target
/// hostname as SNI) to each in parallel.
pub(super) async fn run_tls(sub_m: &ArgMatches) -> ExitCode {
    let insecure = sub_m.get_flag("insecure");
    run_probe_flow(
        sub_m,
        render_tls,
        |obs: &TlsObservation| obs.destination,
        move |host, dest, timeout| async move {
            if insecure {
                ip_tls::probe_insecure(dest, &host, timeout).await
            } else {
                ip_tls::probe(dest, &host, timeout).await
            }
        },
    )
    .await
}
