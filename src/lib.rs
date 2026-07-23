//! A small library for retrieving the local IP address and listing network
//! interfaces together with their IP addresses.
//!
//! The same functionality is also exposed through the `ip-tools` command-line
//! tool. Both IPv4 and IPv6 addresses are reported where available.
//!
//! # Examples
//!
//! Print the local IP address and every network interface:
//!
//! ```
//! use ip_tools::{get_local_ip, list_net_ifs};
//!
//! if let Ok(ip) = get_local_ip() {
//!     println!("local IP: {ip}");
//! }
//!
//! if let Ok(interfaces) = list_net_ifs() {
//!     for (name, ip) in &interfaces {
//!         println!("{name}: {ip}");
//!     }
//! }
//! ```
//!
//! See [`get_local_ip`] and [`list_net_ifs`] for details, and [`IpToolsError`]
//! for the error type returned on failure.
#![warn(clippy::pedantic, clippy::nursery)]

use local_ip_address::{list_afinet_netifas, local_ip};
use std::net::IpAddr;

/// Error type for IP tools operations.
///
/// # Examples
///
/// `IpToolsError` implements [`std::error::Error`], so the underlying cause is
/// available via `Error::source`:
///
/// ```
/// use ip_tools::get_local_ip;
/// use std::error::Error;
///
/// if let Err(err) = get_local_ip() {
///     println!("failed: {err}");
///     if let Some(source) = err.source() {
///         println!("caused by: {source}");
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum IpToolsError {
    /// Failed to determine the local IP address.
    #[error("failed to get local IP address: {0}")]
    LocalIp(#[from] local_ip_address::Error),
    /// Failed to list network interfaces.
    #[error("failed to list network interfaces: {0}")]
    ListInterfaces(#[source] local_ip_address::Error),
}

/// Retrieves the local IP address.
///
/// # Errors
///
/// Returns [`Err`] containing an [`IpToolsError`] if the local IP cannot
/// be determined, e.g. when no network interface is configured.
///
/// # Examples
///
/// ```
/// use ip_tools::get_local_ip;
///
/// match get_local_ip() {
///     Ok(ip) => println!("local IP: {ip}"),
///     Err(e) => eprintln!("error: {e}"),
/// }
/// ```
pub fn get_local_ip() -> Result<IpAddr, IpToolsError> {
    Ok(local_ip()?)
}

/// Lists all network interfaces and their IP addresses.
///
/// # Errors
///
/// Returns [`Err`] containing an [`IpToolsError`] if the interface list
/// cannot be retrieved.
///
/// # Examples
///
/// ```
/// use ip_tools::list_net_ifs;
///
/// match list_net_ifs() {
///     Ok(interfaces) => {
///         for (name, ip) in &interfaces {
///             println!("{name}: {ip}");
///         }
///     }
///     Err(e) => eprintln!("error: {e}"),
/// }
/// ```
pub fn list_net_ifs() -> Result<Vec<(String, IpAddr)>, IpToolsError> {
    list_afinet_netifas().map_err(IpToolsError::ListInterfaces)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a `local_ip_address::Error::StrategyError` for testing.
    fn strategy_error(msg: &str) -> local_ip_address::Error {
        local_ip_address::Error::StrategyError(msg.into())
    }

    #[test]
    fn error_display_local_ip() {
        let err = IpToolsError::LocalIp(strategy_error("gateway unreachable"));
        assert_eq!(
            err.to_string(),
            "failed to get local IP address: \
             An error occurred executing the underlying strategy error.\ngateway unreachable"
        );
    }

    #[test]
    fn error_display_list_interfaces() {
        let err = IpToolsError::ListInterfaces(local_ip_address::Error::PlatformNotSupported("wasm32".into()));
        assert_eq!(
            err.to_string(),
            "failed to list network interfaces: \
             The current platform: `wasm32`, is not supported"
        );
    }

    #[test]
    fn error_source_returns_inner_for_local_ip() {
        let err = IpToolsError::LocalIp(strategy_error("boom"));
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "source() should return the inner error");
        assert!(source.unwrap().is::<local_ip_address::Error>());
    }

    #[test]
    fn error_source_returns_inner_for_list_interfaces() {
        let err = IpToolsError::ListInterfaces(local_ip_address::Error::LocalIpAddressNotFound);
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "source() should return the inner error");
        assert!(source.unwrap().is::<local_ip_address::Error>());
    }

    #[test]
    fn error_from_converts_to_local_ip_variant() {
        // The From<local_ip_address::Error> impl always produces LocalIp so that
        // the `?` operator works on get_local_ip. list_net_ifs avoids this footgun
        // by using map_err(IpToolsError::ListInterfaces) directly.
        let err: IpToolsError = strategy_error("via from").into();
        match err {
            IpToolsError::LocalIp(e) => assert!(e.to_string().contains("via from")),
            IpToolsError::ListInterfaces(_) => {
                panic!("From should produce the LocalIp variant, not ListInterfaces")
            }
        }
    }

    #[test]
    fn error_is_send_and_sync() {
        // Compile-time guarantee: IpToolsError must be Send + Sync so it can
        // be used in async contexts and shared across threads.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IpToolsError>();
    }
}
