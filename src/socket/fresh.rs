use std::{io, net::SocketAddr};

use crate::{PacketSocket, ReceiveResult};

pub(crate) struct FreshSocket {}

impl PacketSocket for FreshSocket {
    fn is_fresh(&self) -> bool {
        true
    }

    fn get_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Socket not connected",
        ))
    }

    fn send(&mut self, _: SocketAddr, _: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Socket not connected",
        ))
    }

    fn receive(&mut self, _: &mut [u8]) -> io::Result<ReceiveResult> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Socket not connected",
        ))
    }

    fn poll(&mut self) -> io::Result<()> {
        unimplemented!("Can't poll on a fresh socket")
    }
}
