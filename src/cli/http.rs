//! `http` subcommand handler (HTTP/1.1).

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::http as ip_http;
use ip_tools::model::HttpObservation;
use ip_tools::report::{cert_covers_hostname, render_http};
use ip_tools::style::Style;
use std::process::ExitCode;

/// Resolve a target's addresses and perform an HTTPS/HTTP1.1 request to each
/// in parallel (bounded by `--concurrency`).
pub(super) async fn run_http(sub_m: &ArgMatches, style: Style) -> ExitCode {
    let method = sub_m.get_one::<String>("method").expect("method has default").clone();
    let path = sub_m.get_one::<String>("path").expect("path has default").clone();
    let plain = sub_m.get_flag("plain");
    let insecure = sub_m.get_flag("insecure");
    let protocol = super::parse_tls_protocol(sub_m);
    let headers = match super::parse_custom_headers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let body = match super::parse_body(sub_m) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let output_body = sub_m.try_get_one::<String>("output-body").ok().flatten().cloned();
    let max_body_bytes = *sub_m
        .get_one::<u64>("max-body-bytes")
        .expect("max-body-bytes has default");
    run_probe_flow(
        sub_m,
        style,
        render_http,
        |obs: &HttpObservation| obs.destination,
        |obs: &HttpObservation| obs.failure.is_some(),
        Some(render_http_csv),
        move |host, dest, timeout| {
            let method = method.clone();
            let path = path.clone();
            let headers = headers.clone();
            let body = body.clone();
            let output_body = output_body.clone();
            async move {
                let header_refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                let output = output_body.as_deref().map(std::path::Path::new);
                if plain {
                    ip_http::probe_plain_output(
                        dest,
                        &host,
                        &method,
                        &path,
                        &header_refs,
                        body.as_deref(),
                        timeout,
                        max_body_bytes,
                        output,
                    )
                    .await
                } else if insecure {
                    ip_http::probe_insecure_with_version_output(
                        dest,
                        &host,
                        &method,
                        &path,
                        &header_refs,
                        body.as_deref(),
                        timeout,
                        protocol,
                        max_body_bytes,
                        output,
                    )
                    .await
                } else {
                    ip_http::probe_with_version_output(
                        dest,
                        &host,
                        &method,
                        &path,
                        &header_refs,
                        body.as_deref(),
                        timeout,
                        protocol,
                        max_body_bytes,
                        output,
                    )
                    .await
                }
            }
        },
    )
    .await
}

/// Render an HTTP family fleet sweep as CSV: a header then one row per
/// destination, with the response status/protocol/TTFB when present. Shared
/// by `http`, `http2` and `http3`.
pub(super) fn render_http_csv(per_target: &[(String, Vec<HttpObservation>)]) -> String {
    let mut out =
        String::from("host,destination,protocol,status,location,body_bytes,ttfb_ms,latency_ms,sni,version,cipher,alpn,subject,issuer,not_after_utc,sans,covers,headers,body_snippet,failure\n");
    for (host, results) in per_target {
        for o in results {
            // The HTTPS probes embed the negotiated TLS handshake in each
            // observation, so expose it in CSV (mirroring `tls --csv`) — a
            // fleet sweep otherwise loses the cert/protocol-version evidence.
            let tls = o.tls.as_ref();
            out.push_str(&csv_field(host));
            out.push(',');
            out.push_str(&csv_field(&o.destination.to_string()));
            out.push(',');
            out.push_str(&csv_field(o.protocol.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(&opt(o.status.map(u64::from))));
            out.push(',');
            out.push_str(&csv_field(o.location.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(&opt(o.body_bytes)));
            out.push(',');
            out.push_str(&csv_field(&opt(o.ttfb_ms)));
            out.push(',');
            out.push_str(&csv_field(&opt(o.latency_ms)));
            out.push(',');
            out.push_str(&csv_field(tls.map_or("", |t| t.sni.as_str())));
            out.push(',');
            out.push_str(&csv_field(tls.and_then(|t| t.version.as_deref()).unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(tls.and_then(|t| t.cipher.as_deref()).unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(tls.and_then(|t| t.alpn.as_deref()).unwrap_or("")));
            let cert = tls.and_then(|t| t.certificate.as_ref());
            out.push(',');
            out.push_str(&csv_field(cert.map_or("", |c| c.subject.as_str())));
            out.push(',');
            out.push_str(&csv_field(cert.map_or("", |c| c.issuer.as_str())));
            out.push(',');
            out.push_str(&csv_field(cert.and_then(|c| c.not_after_utc.as_deref()).unwrap_or("")));
            out.push(',');
            // The served certificate's SANs and the `covers <sni>` verdict,
            // mirroring `tls --csv` and the human `covers <sni>: yes/no` row —
            // a wrong-host/wildcard mismatch must survive a spreadsheet sweep.
            out.push_str(&csv_field(&cert.map(|c| c.sans.join(";")).unwrap_or_default()));
            out.push(',');
            out.push_str(
                if cert.is_some_and(|c| cert_covers_hostname(tls.map_or("", |t| t.sni.as_str()), &c.sans)) {
                    "yes"
                } else {
                    ""
                },
            );
            out.push(',');
            // The observed response headers (the diagnostic-relevant set the
            // human report curates: server identity, CDN/proxy hops, caching,
            // security markers) as `Name: value` pairs joined by "; ", so a
            // fleet sweep in a spreadsheet retains the server/edge evidence
            // instead of dropping it (parity with the TTL/status columns).
            out.push_str(&csv_field(&curated_headers_csv(&o.headers)));
            out.push(',');
            // The bounded body snippet (WAF block page / JS challenge / auth or
            // API error / captive-portal prompt) — the content that makes a
            // bare status meaningful, which the human report and JSON carry.
            // Quoted via the shared csv_field helper (may span commas/quotes).
            out.push_str(&csv_field(o.body_snippet.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(
                &o.failure.as_ref().map_or_else(String::new, |e| e.kind.to_string()),
            ));
            out.push('\n');
        }
    }
    out
}

/// Join the diagnostic-relevant response headers as `Name: value` pairs
/// separated by "; " for the CSV `headers` column (empty when there are none
/// or the probe failed before headers). Matches the curated set the human
/// report renders and the `Name: value` formatting it uses.
fn curated_headers_csv(headers: &[(String, String)]) -> String {
    let mut parts = Vec::new();
    for (name, value) in headers {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "server"
                | "via"
                | "x-powered-by"
                | "x-served-by"
                | "x-cache"
                | "x-cache-hits"
                | "cf-ray"
                | "cf-cache-status"
                | "age"
                | "cache-control"
                | "expires"
                | "etag"
                | "last-modified"
                | "content-type"
                | "alt-svc"
                | "set-cookie"
        ) {
            parts.push(format!("{name}: {value}"));
        }
    }
    parts.join("; ")
}

fn opt(v: Option<u64>) -> String {
    v.map_or_else(String::new, |x| x.to_string())
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
    use ip_tools::model::{CertificateSummary, TlsObservation};

    fn obs(destination: &str, cert: Option<CertificateSummary>) -> HttpObservation {
        HttpObservation {
            destination: destination.parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: Some(TlsObservation {
                destination: destination.parse().unwrap(),
                sni: "example.com".into(),
                success: true,
                version: Some("TLSv1.3".into()),
                cipher: Some("AES_256_GCM".into()),
                alpn: Some("h2".into()),
                certificate: cert,
                latency_ms: Some(7),
                failure: None,
            }),
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: Some("/moved".into()),
            headers: vec![("server".into(), "fixture".into())],
            body_bytes: Some(2),
            body_snippet: Some("ok".into()),
            latency_ms: Some(7),
            ttfb_ms: Some(3),
            failure: None,
        }
    }

    fn cert(sans: &[&str]) -> CertificateSummary {
        CertificateSummary {
            subject: "CN=example.com".into(),
            issuer: "CN=CA".into(),
            not_before_utc: None,
            not_after_utc: Some("2027-01-01T00:00:00Z".into()),
            sans: sans.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn head(destination: &str) -> String {
        // The repeated leading columns (host..not_after), after which the
        // per-row assertions anchor the sans+covers pair.
        format!("example.com,{destination},HTTP/1.1,200,/moved,2,3,7,example.com,TLSv1.3,AES_256_GCM,h2,CN=example.com,CN=CA,2027-01-01T00:00:00Z,")
    }

    #[test]
    fn render_http_csv_emits_cert_sans_and_covers() {
        let per_target = vec![(
            "example.com".to_string(),
            vec![
                // A cert whose SANs cover the presented SNI → covers=yes.
                obs("192.0.2.1:443", Some(cert(&["example.com"]))),
                // SANs only cover a different name → covers left blank, the
                // wrong-host/wildcard-mismatch signal a spreadsheet sweep needs.
                obs("192.0.2.2:443", Some(cert(&["other.example"]))),
                // No cert (failed/TLS-less row) → blank sans and covers.
                obs("192.0.2.3:443", None),
            ],
        )];
        let out = render_http_csv(&per_target);
        let mut lines = out.lines();
        assert_eq!(
            lines.next(),
            Some("host,destination,protocol,status,location,body_bytes,ttfb_ms,latency_ms,sni,version,cipher,alpn,subject,issuer,not_after_utc,sans,covers,headers,body_snippet,failure")
        );
        assert!(
            lines
                .next()
                .is_some_and(|l| l.starts_with(&format!("{}example.com,yes,", head("192.0.2.1:443")))),
            "covering SANs must render covers=yes: {out}"
        );
        assert!(
            lines
                .next()
                .is_some_and(|l| l.starts_with(&format!("{}other.example,", head("192.0.2.2:443")))),
            "non-covering SANs render the SANs and a blank covers: {out}"
        );
        // Cert-less row: no subject/issuer/not_after either, then blank sans
        // and covers before the shared trailing columns.
        assert_eq!(
            lines.next(),
            Some(
                "example.com,192.0.2.3:443,HTTP/1.1,200,/moved,2,3,7,example.com,TLSv1.3,AES_256_GCM,h2,,,,,,server: fixture,ok,"
            ),
            "cert-less row renders blank sans and covers: {out}"
        );
        assert!(lines.next().is_none());
    }
}
