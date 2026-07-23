use ip_tools::{get_local_ip, list_net_ifs};

#[test]
fn test_get_local_ip() {
    let result = get_local_ip();
    assert!(
        result.is_ok(),
        "get_local_ip() should succeed when a network interface is available"
    );
    let ip = result.unwrap();
    // A valid local IP should not be an unspecified or loopback address
    // (loopback is possible on some systems, so we only check unspecified).
    assert!(!ip.is_unspecified(), "local IP should not be unspecified (0.0.0.0)");
}

#[test]
fn test_list_net_ifs() {
    let result = list_net_ifs();
    assert!(
        result.is_ok(),
        "list_net_ifs() should succeed when network interfaces are available"
    );
    let interfaces = result.unwrap();
    assert!(
        !interfaces.is_empty(),
        "at least one network interface should be listed"
    );
    // Each entry should have a non-empty name and a valid IP address.
    for (name, ip) in &interfaces {
        assert!(!name.is_empty(), "interface name should not be empty");
        assert!(
            !ip.is_unspecified(),
            "interface {:?} IP should not be unspecified",
            name
        );
    }
}

#[test]
fn test_get_local_ip_returns_ipaddr() {
    // Ensure the returned type is a valid IpAddr (not unspecified).
    if let Ok(ip) = get_local_ip() {
        // is_unspecified covers both IPv4 0.0.0.0 and IPv6 ::
        assert!(!ip.is_unspecified());
    }
}
