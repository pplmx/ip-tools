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
