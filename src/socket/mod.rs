use std::io::{self};
use std::net::SocketAddr;
use thiserror::Error;

use crate::socket::client::ClientDtlsSocket;
use crate::socket::fresh::FreshSocket;
use crate::socket::server::ServerDtlsSocket;

mod client;
mod connections;
mod fresh;
mod server;

pub trait PacketSocket {
    fn get_addr(&self) -> io::Result<SocketAddr>;
    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()>;
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult>;
    //todo add timeout
    fn poll(&mut self) -> io::Result<()>;
    fn is_fresh(&self) -> bool {
        false
    }
}
#[derive(Error, Debug)]
pub enum PacketSocketError {
    #[error("Socket not bound")]
    SocketNotBound,

    #[error("Socket not fresh")]
    SocketNotFresh,

    #[error("Connect token is missing")]
    MissingConnectToken,

    #[error("Cant connect with server socket")]
    ConnectOnServerSock,

    #[error("TODO")]
    TODO,
}

pub struct ReceiveResult {
    pub len: u32,
    pub saddr: SocketAddr,
}

pub struct PacketSocketWrapper {
    inner: Box<dyn PacketSocket>,
}

impl PacketSocket for PacketSocketWrapper {
    fn get_addr(&self) -> io::Result<SocketAddr> {
        self.inner.get_addr()
    }

    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        self.inner.send(addr, bytes)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        self.inner.receive(buffer)
    }

    fn poll(&mut self) -> io::Result<()> {
        self.inner.poll()
    }
}

impl PacketSocketWrapper {
    pub fn new() -> Self {
        PacketSocketWrapper {
            inner: Box::new(FreshSocket {}),
        }
    }

    pub fn bind(&mut self, addr: SocketAddr) -> Result<(), PacketSocketError> {
        if self.inner.is_fresh() {
            self.inner = self.do_bind(addr)?;
            Ok(())
        } else {
            Err(PacketSocketError::SocketNotFresh)
        }
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<(), PacketSocketError> {
        if self.inner.is_fresh() {
            self.inner = self.do_connect(addr)?;
            Ok(())
        } else {
            Err(PacketSocketError::SocketNotFresh)
        }
    }

    fn do_bind(&self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
        let sock = ServerDtlsSocket::bind(addr).map_err(|_e| PacketSocketError::TODO)?;
        Ok(Box::new(sock))
    }
    fn do_connect(&self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
        let sock = ClientDtlsSocket::connect(addr).map_err(|_e| PacketSocketError::TODO)?;
        Ok(Box::new(sock))
    }
}
