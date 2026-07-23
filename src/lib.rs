use local_ip_address::{list_afinet_netifas, local_ip};
use std::net::IpAddr;

/// Error type for IP tools operations.
#[derive(Debug)]
pub enum IpToolsError {
    /// Failed to determine the local IP address.
    LocalIp(local_ip_address::Error),
    /// Failed to list network interfaces.
    ListInterfaces(local_ip_address::Error),
}

impl std::fmt::Display for IpToolsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpToolsError::LocalIp(e) => write!(f, "failed to get local IP address: {e}"),
            IpToolsError::ListInterfaces(e) => {
                write!(f, "failed to list network interfaces: {e}")
            }
        }
    }
}

impl std::error::Error for IpToolsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IpToolsError::LocalIp(e) | IpToolsError::ListInterfaces(e) => Some(e),
        }
    }
}

impl From<local_ip_address::Error> for IpToolsError {
    fn from(e: local_ip_address::Error) -> Self {
        IpToolsError::LocalIp(e)
    }
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
