use crate::socket::EnetPacketSocket as EnetPacketSocketWrapper;

pub mod addr;
pub mod enet;
pub mod local;

pub type EnetPacketSocket = EnetPacketSocketWrapper;

pub fn force_link_symbols() {}

#[allow(dead_code)]
#[derive(Debug)]
enum ENetSocketOptionRs {
    EnetSockoptNonblock = 1,
    EnetSockoptBroadcast = 2,
    EnetSockoptRcvbuf = 3,
    EnetSockoptSndbuf = 4,
    EnetSockoptReuseaddr = 5,
    EnetSockoptRcvtimeo = 6,
    EnetSockoptSndtimeo = 7,
    EnetSockoptError = 8,
    EnetSockoptNodelay = 9,
}
