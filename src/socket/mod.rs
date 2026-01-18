use arc_swap::ArcSwap;
use bytes::Bytes;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

use crate::ffi;
use crate::socket::client::ClientDtlsSocket;
use crate::socket::fresh::FreshSocket;
use crate::socket::server::ServerDtlsSocket;

mod client;
mod connections;
mod fresh;
mod server;

#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub enabled: bool,
    pub secret: [u64; 2],
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            secret: [0x4141414141414141, 0x4141414141414141],
        }
    }
}

pub struct CookieConfigHandle {
    config: Arc<ArcSwap<CookieConfig>>,
    generation: Arc<AtomicU64>,
}

impl CookieConfigHandle {
    pub fn new(config: CookieConfig) -> Self {
        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn update(&self, config: CookieConfig) {
        self.config.store(Arc::new(config));
        self.generation.fetch_add(1, Ordering::Release);
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<CookieConfig>> {
        self.config.load()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl Clone for CookieConfigHandle {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            generation: Arc::clone(&self.generation),
        }
    }
}

pub struct ServerTlsOptions {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub cookie: CookieConfigHandle,
}
impl Default for ServerTlsOptions {
    fn default() -> Self {
        Self {
            cert_path: Default::default(),
            key_path: Default::default(),
            cookie: CookieConfigHandle::new(CookieConfig::default()),
        }
    }
}

pub struct ClientTlsOptions {
    pub ca_cert_path: PathBuf,
    pub domain: String,
    pub verify: bool
}
impl Default for ClientTlsOptions{
    fn default() -> Self {
        Self { 
            ca_cert_path: Default::default(),
            domain: Default::default(), 
            verify: Default::default() 
        }
    }
}

pub struct ServerSocketOptions {
    pub addr: SocketAddr,
    pub tls: ServerTlsOptions,
}

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
pub struct Packet {
    pub buf: Bytes,
    pub addr: SocketAddr,
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

pub struct EnetPacketSocket {
    wrapper: PacketSocketWrapper,
}
impl PacketSocket for EnetPacketSocket {
    fn get_addr(&self) -> io::Result<SocketAddr> {
        self.wrapper.get_addr()
    }

    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        // special handling for connect, as enet does not bother to conenct before send
        if self.wrapper.is_fresh() {
            let tls = ffi::take_client_tls_options();
            self.connect(addr, tls).unwrap();
        }
        let res = self.wrapper.send(addr, bytes);
        let _ = self.wrapper.poll();
        res
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        let _ = self.wrapper.poll();
        self.wrapper.receive(buffer)
    }

    fn poll(&mut self) -> io::Result<()> {
        // unimplemented!("Enet polls on send and receive respectively")
        self.wrapper.poll()
    }
}
impl EnetPacketSocket {
    pub fn new() -> Self {
        // println!("{}",to_enet_addr(&("127.0.0.1:9001".parse().unwrap())).port);
        EnetPacketSocket {
            wrapper: PacketSocketWrapper::new(),
        }
    }

    pub fn bind(&mut self, opts: ServerSocketOptions) -> Result<(), PacketSocketError> {
        let res = self.wrapper.bind(opts);
        let _ = self.wrapper.poll();
        res
    }

    pub fn connect(
        &mut self,
        addr: SocketAddr,
        tls: ClientTlsOptions,
    ) -> Result<(), PacketSocketError> {
        let res = self.wrapper.connect(addr, tls);
        let _ = self.wrapper.poll();
        res
    }
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
    fn is_fresh(&self) -> bool {
        self.inner.is_fresh()
    }
}

impl PacketSocketWrapper {
    pub fn new() -> Self {
        // println!("{}",to_enet_addr(&("127.0.0.1:9001".parse().unwrap())).port);
        PacketSocketWrapper {
            inner: Box::new(FreshSocket {}),
        }
    }

    pub fn bind(&mut self, opts: ServerSocketOptions) -> Result<(), PacketSocketError> {
        if self.inner.is_fresh() {
            self.inner = self.do_bind(opts)?;
            Ok(())
        } else {
            Err(PacketSocketError::SocketNotFresh)
        }
    }

    pub fn connect(
        &mut self,
        addr: SocketAddr,
        tls: ClientTlsOptions,
    ) -> Result<(), PacketSocketError> {
        if self.inner.is_fresh() {
            self.inner = self.do_connect(addr, tls)?;
            Ok(())
        } else {
            Err(PacketSocketError::SocketNotFresh)
        }
    }

    fn do_bind(
        &self,
        opts: ServerSocketOptions,
    ) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
        let sock = ServerDtlsSocket::bind(opts).map_err(|_e| PacketSocketError::TODO)?;
        Ok(Box::new(sock))
    }
    fn do_connect(
        &self,
        addr: SocketAddr,
        tls: ClientTlsOptions,
    ) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
        let sock = ClientDtlsSocket::connect(addr, tls).map_err(|_e| PacketSocketError::TODO)?;
        Ok(Box::new(sock))
    }
}
