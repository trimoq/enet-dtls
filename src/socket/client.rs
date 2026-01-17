use std::{io, net::SocketAddr};

use crate::{PacketSocket, ReceiveResult};

pub struct ClientDtlsSocket {}
impl ClientDtlsSocket {
    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        todo!()
    }
}
impl PacketSocket for ClientDtlsSocket {
    fn get_addr(&self) -> io::Result<SocketAddr> {
        todo!()
    }

    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        todo!()
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        todo!()
    }

    fn poll(&mut self) -> io::Result<()> {
        todo!()
    }
}
