//! Example: print the local IP address and all network interfaces.
//!
//! Run with:
//!
//! ```shell
//! cargo run --example ip_info
//! ```

use ip_tools::{get_local_ip, list_net_ifs};

fn main() {
    match get_local_ip() {
        Ok(ip) => println!("local IP: {ip}"),
        Err(e) => eprintln!("error: {e}"),
    }

    match list_net_ifs() {
        Ok(interfaces) => {
            println!("network interfaces:");
            for (name, ip) in &interfaces {
                println!("  {name}: {ip}");
            }
        }
        Err(e) => eprintln!("error: {e}"),
    }
}
