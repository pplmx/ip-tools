use local_ip_address::{list_afinet_netifas, local_ip};
use std::net::IpAddr;

/// Error type for IP tools operations.
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
pub fn get_local_ip() -> Result<IpAddr, IpToolsError> {
    Ok(local_ip()?)
}

/// Lists all network interfaces and their IP addresses.
///
/// # Errors
///
/// Returns [`Err`] containing an [`IpToolsError`] if the interface list
/// cannot be retrieved.
pub fn list_net_ifs() -> Result<Vec<(String, IpAddr)>, IpToolsError> {
    let net_ifs = list_afinet_netifas().map_err(IpToolsError::ListInterfaces)?;
    Ok(net_ifs)
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
