//! Target parsing: split CLI inputs like `github.com`, `github.com:443`,
//! `1.2.3.4:443` or `[2001:db8::1]:443` into a hostname and a port.

use crate::error::{DiagError, Result};

/// A resolved target: a hostname (or literal IP) plus a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Hostname, or an IP literal in textual form (bracketed for IPv6).
    pub host: String,
    /// Port to probe.
    pub port: u16,
}

impl Target {
    /// Parse `input` into a host + port, using `default_port` when no explicit
    /// port is present.
    ///
    /// # Errors
    ///
    /// Returns [`DiagError::InvalidTarget`] when the port is non-numeric or
    /// the input is malformed.
    pub fn parse(input: &str, default_port: u16) -> Result<Self> {
        // A pasted URL (`https://example.com`) is the most common caller
        // mistake: it has exactly one colon, so the generic branch would
        // reject it with "expected '<host>:<port>'" and leave the operator
        // wondering why. Name the scheme directly instead.
        for scheme in ["http://", "https://"] {
            if let Some(rest) = input.strip_prefix(scheme) {
                let reason =
                    format!("looks like a URL (did you mean '{rest}'? this tool takes 'host[:port]', not a scheme)");
                return Err(invalid(input, &reason));
            }
        }
        // Bracket form: "[addr]:port" or "[addr]"
        if let Some(rest) = input.strip_prefix('[') {
            return match rest.split_once(']') {
                Some(("", "")) => Err(invalid(input, "empty address in brackets")),
                Some((addr, "")) => Ok(Self {
                    host: format!("[{addr}]"),
                    port: default_port,
                }),
                Some((addr, port_part)) => {
                    let port = parse_port(port_part.strip_prefix(':').unwrap_or(""), input)?;
                    Ok(Self {
                        host: format!("[{addr}]"),
                        port,
                    })
                }
                None => Err(invalid(input, "unterminated '[' ")),
            };
        }

        // A `user@` prefix is the other common paste (from an scp/curl-style
        // URL). It would otherwise be accepted as part of the hostname and
        // fail later with a baffling "hostname user@example.com did not
        // resolve". Point at the '@' up front instead.
        if let Some((userinfo, _)) = input.rsplit_once('@') {
            if !userinfo.is_empty() {
                let reason = format!(
                    "looks like a user@host string (this tool takes 'host[:port]', drop the '{userinfo}@' prefix)"
                );
                return Err(invalid(input, &reason));
            }
        }

        // Exactly one colon => host:port, unless it looks like a bare IPv6
        // literal (which has multiple colons).
        if input.matches(':').count() == 1 {
            if let Some((host, port)) = input.rsplit_once(':') {
                if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                    let port = port.parse::<u16>().map_err(|_| invalid(input, "port out of range"))?;
                    return Ok(Self {
                        host: host.to_string(),
                        port,
                    });
                }
            }
            return Err(invalid(input, "expected '<host>:<port>'"));
        }

        // Hostname or bare IP literal (no port).
        if input.trim().is_empty() {
            return Err(invalid(input, "empty target"));
        }
        Ok(Self {
            host: input.to_string(),
            port: default_port,
        })
    }
}

fn parse_port(s: &str, input: &str) -> Result<u16> {
    s.parse::<u16>().map_err(|_| invalid(input, "port out of range"))
}

fn invalid(input: &str, reason: &str) -> DiagError {
    DiagError::InvalidTarget {
        input: input.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_hostname() {
        assert_eq!(
            Target::parse("github.com", 443).unwrap(),
            Target {
                host: "github.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn host_with_port() {
        assert_eq!(
            Target::parse("example.com:8080", 443).unwrap(),
            Target {
                host: "example.com".into(),
                port: 8080
            }
        );
    }

    #[test]
    fn ipv4_with_port() {
        assert_eq!(
            Target::parse("1.2.3.4:443", 443).unwrap(),
            Target {
                host: "1.2.3.4".into(),
                port: 443
            }
        );
    }

    #[test]
    fn bare_ipv6_literal() {
        assert_eq!(
            Target::parse("2001:db8::1", 443).unwrap(),
            Target {
                host: "2001:db8::1".into(),
                port: 443
            }
        );
    }

    #[test]
    fn bracketed_ipv6_with_port() {
        assert_eq!(
            Target::parse("[2001:db8::1]:8443", 443).unwrap(),
            Target {
                host: "[2001:db8::1]".into(),
                port: 8443
            }
        );
    }

    #[test]
    fn rejects_bad_port() {
        assert!(Target::parse("example.com:notaport", 443).is_err());
        assert!(Target::parse("example.com:99999", 443).is_err());
        assert!(Target::parse("", 443).is_err());
    }

    #[test]
    fn rejects_unterminated_or_empty_brackets() {
        // A stray '[' with no closing bracket is malformed.
        assert!(Target::parse("[", 443).is_err());
        assert!(Target::parse("[::1", 443).is_err());
        // "[]" claims to be a literal but names no address: accept it and the
        // failure would surface later as a confusing "did not resolve" for an
        // empty hostname, so reject it up front.
        let err = Target::parse("[]", 443).unwrap_err().to_string();
        assert!(err.contains("[]"), "empty-bracket error should name the input: {err}");
    }

    #[test]
    fn pasted_url_gets_a_scheme_hint() {
        // A pasted `https://example.com` is the classic caller mistake: name
        // the scheme and suggest the bare host instead of a generic
        // "expected '<host>:<port>'".
        for input in ["https://example.com", "http://example.com:8080", "https://[::1]:443"] {
            let err = Target::parse(input, 443).unwrap_err().to_string();
            assert!(
                err.contains("looks like a URL"),
                "scheme hint missing for {input}: {err}"
            );
        }
    }

    #[test]
    fn userinfo_prefix_gets_an_at_hint() {
        // `user@example.com:443` would otherwise resolve as a hostname
        // containing '@' and fail later with a baffling DNS error; point at
        // the '@' up front.
        let err = Target::parse("user@example.com:443", 443).unwrap_err().to_string();
        assert!(
            err.contains("user@host") && err.contains("user@"),
            "userinfo hint missing: {err}"
        );
    }
}
