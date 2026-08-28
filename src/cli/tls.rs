//! `tls` subcommand handler.

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::model::TlsObservation;
use ip_tools::report::{cert_covers_hostname, render_tls};
use ip_tools::style::Style;
use ip_tools::tls as ip_tls;
use std::process::ExitCode;

/// Resolve a target's addresses and perform a TLS handshake (with the target
/// hostname as SNI) to each in parallel.
pub(super) async fn run_tls(sub_m: &ArgMatches, style: Style) -> ExitCode {
    let insecure = sub_m.get_flag("insecure");
    let protocol = super::parse_tls_protocol(sub_m);
    run_probe_flow(
        sub_m,
        style,
        render_tls,
        |obs: &TlsObservation| obs.destination,
        |obs: &TlsObservation| !obs.success,
        Some(render_tls_csv),
        None, /* `--expect-*` is an HTTP response-shape assertion (`tls` has no status/body) */
        move |host, dest, timeout| async move {
            if insecure {
                ip_tls::probe_insecure_with_version(dest, &host, timeout, protocol).await
            } else {
                ip_tls::probe_with_version(dest, &host, timeout, protocol).await
            }
        },
    )
    .await
}

/// Render a TLS call sweep as CSV: a header then one row per destination,
/// with handshake details (version/cipher/ALPN/certificate) when present.
fn render_tls_csv(per_target: &[(String, Vec<TlsObservation>)]) -> String {
    let mut out = String::from(
        "host,destination,sni,success,version,cipher,alpn,subject,issuer,not_after_utc,sans,covers,latency_ms,failure\n",
    );
    for (host, results) in per_target {
        for o in results {
            out.push_str(&csv_field(host));
            out.push(',');
            out.push_str(&csv_field(&o.destination.to_string()));
            out.push(',');
            out.push_str(&csv_field(&o.sni));
            out.push(',');
            out.push(if o.success { '1' } else { '0' });
            out.push(',');
            out.push_str(&csv_field(o.version.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(o.cipher.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(o.alpn.as_deref().unwrap_or("")));
            out.push(',');
            let cert = o.certificate.as_ref();
            out.push_str(&csv_field(cert.map_or("", |c| c.subject.as_str())));
            out.push(',');
            out.push_str(&csv_field(cert.map_or("", |c| c.issuer.as_str())));
            out.push(',');
            out.push_str(&csv_field(cert.and_then(|c| c.not_after_utc.as_deref()).unwrap_or("")));
            out.push(',');
            // The certificate's Subject Alternative Names (which hostnames/IPs
            // it is valid for) and the derived `covers <sni>` verdict — the
            // wrong-host / wildcard-mismatch signal the human report and JSON
            // show but the CSV export dropped.
            out.push_str(&csv_field(&cert.map(|c| c.sans.join(";")).unwrap_or_default()));
            out.push(',');
            // The `covers <sni>` verdict: "yes" when the SANs cover the SNI,
            // "no" when a certificate was presented but does not cover it
            // (wrong-host / wildcard mismatch), empty when no certificate was
            // observed at all — so a spreadsheet can tell the mismatch from a
            // failed handshake, as the human `covers ...: no` row does.
            out.push_str(match cert {
                Some(c) if cert_covers_hostname(&o.sni, &c.sans) => "yes",
                Some(_) => "no",
                None => "",
            });
            out.push(',');
            out.push_str(&csv_field(&opt(o.latency_ms)));
            out.push(',');
            out.push_str(&csv_field(
                &o.failure.as_ref().map_or_else(String::new, |e| e.kind.to_string()),
            ));
            out.push('\n');
        }
    }
    out
}

fn opt(v: Option<u64>) -> String {
    v.map_or_else(String::new, |x| x.to_string())
}

/// Quote a CSV field when it contains a comma, quote, or newline (RFC 4180).
use super::csv_field;

#[cfg(test)]
mod tests {
    use super::*;
    use ip_tools::model::{CertificateSummary, FailureKind, ProbeError, TlsObservation};

    fn obs(destination: &str, success: bool, version: Option<&str>) -> TlsObservation {
        TlsObservation {
            destination: destination.parse().unwrap(),
            sni: "example.com".into(),
            success,
            version: version.map(str::to_string),
            cipher: Some("AES_256_GCM".into()),
            alpn: Some("h2".into()),
            certificate: success.then(|| CertificateSummary {
                subject: "CN=example.com".into(),
                issuer: "CN=CA".into(),
                not_before_utc: None,
                not_after_utc: Some("2027-01-01T00:00:00Z".into()),
                sans: vec!["example.com".into()],
            }),
            latency_ms: success.then_some(7),
            failure: (!success).then(|| ProbeError {
                kind: FailureKind::Timeout,
                message: "timed out".into(),
            }),
        }
    }

    #[test]
    fn render_tls_csv_emits_handshake_details() {
        let per_target = vec![(
            "example.com".to_string(),
            vec![
                obs("192.0.2.1:443", true, Some("TLSv1.3")),
                obs("192.0.2.2:443", false, None),
            ],
        )];
        let out = render_tls_csv(&per_target);
        let mut lines = out.lines();
        assert_eq!(
            lines.next(),
            Some("host,destination,sni,success,version,cipher,alpn,subject,issuer,not_after_utc,sans,covers,latency_ms,failure")
        );
        assert_eq!(
            lines.next(),
            Some("example.com,192.0.2.1:443,example.com,1,TLSv1.3,AES_256_GCM,h2,CN=example.com,CN=CA,2027-01-01T00:00:00Z,example.com,yes,7,")
        );
        // Failed hop: success=0, empty cert fields, failure kind in last column.
        assert_eq!(
            lines.next(),
            Some("example.com,192.0.2.2:443,example.com,0,,AES_256_GCM,h2,,,,,,,timeout")
        );
        assert!(lines.next().is_none());
    }
}
