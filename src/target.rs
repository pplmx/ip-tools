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
        // Bracket form: "[addr]:port" or "[addr]"
        if let Some(rest) = input.strip_prefix('[') {
            return match rest.split_once(']') {
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
}
