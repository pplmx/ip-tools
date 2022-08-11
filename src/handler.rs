use get_if_addrs::get_if_addrs;
use local_ip_address::{list_afinet_netifas, local_ip};

pub fn get_local_ip() {
    println!("{:?}", local_ip().unwrap());
}

// list all network interfaces
pub fn list_net_ifs() {
    let net_ifs = list_afinet_netifas().unwrap();
    for (name, ip) in net_ifs {
        println!("{}:\t{:?}", name, ip);
    }
}

pub fn list_ifs() {
    // List all of the machine's network interfaces
    for ifs in get_if_addrs().unwrap() {
        println!("{:#?}", ifs);
    }
}
