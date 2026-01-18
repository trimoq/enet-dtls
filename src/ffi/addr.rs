use enet_sys::*;
use std::net::{IpAddr, SocketAddr};

// pub(crate) fn to_enet_addr(saddr: &SocketAddr) -> ENetAddress {
//     ENetAddress {
//         host: match saddr.ip() {
//             IpAddr::V4(ipv4_addr) => ipv4_addr.to_bits().to_be(),
//             IpAddr::V6(_ipv6_addr) => todo!(),
//         },
//         port: saddr.port(),
//     }
// }
pub(crate) fn to_enet_addr_inplace(saddr: &SocketAddr, addr: &mut ENetAddress) {
    addr.host = match saddr.ip() {
        IpAddr::V4(ipv4_addr) => ipv4_addr.to_bits().to_be(),
        IpAddr::V6(_ipv6_addr) => todo!(),
    };
    addr.port = saddr.port()
}
pub(crate) fn from_enet_addr(addr: &_ENetAddress) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(addr.host.to_ne_bytes().into()), addr.port)
}
