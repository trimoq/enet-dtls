use bytes::{BufMut, BytesMut};
use log::trace;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use openssl::ssl::{ErrorCode, SslConnector, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::X509;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::slice::from_raw_parts_mut;
use std::time::Duration;

use crate::socket::ClientTlsOptions;
use crate::socket::server::MioUdpWrapper;
use crate::{Packet, PacketSocket, ReceiveResult};

const SOCKET: Token = Token(0);

pub struct ClientDtlsSocket {
    poll: Poll,
    events: Events,
    ssl_stream: SslStream<MioUdpWrapper>,
    server_addr: SocketAddr,
    local_addr: SocketAddr,
    buffer: BytesMut,
    receive_queue: VecDeque<Packet>,
}

impl ClientDtlsSocket {
    pub fn connect(addr: SocketAddr, tls: ClientTlsOptions) -> io::Result<Self> {
        let mut poll = Poll::new()?;
        let events = Events::with_capacity(128);

        let cert_pem = std::fs::read(&tls.ca_cert_path)?;
        let cert = X509::from_pem(&cert_pem)?;

        let mut connector = SslConnector::builder(SslMethod::dtls_client())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector.cert_store_mut().add_cert(cert)?;
        let connector = connector.build();

        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_nonblocking(true)?;
        sock.connect(&addr.into())?;

        let local_addr = sock
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to get local address"))?;

        let mut mio_udp = UdpSocket::from_std(sock.into());

        // Register with both READABLE and WRITABLE for handshake
        poll.registry().register(
            &mut mio_udp,
            SOCKET,
            Interest::READABLE.add(Interest::WRITABLE),
        )?;

        let wrapper = MioUdpWrapper(mio_udp);
        let ssl = connector.configure()?.into_ssl(&tls.domain)?;
        let mut ssl_stream = SslStream::new(ssl, wrapper)?;

        let mut handshake_events = Events::with_capacity(8);
        loop {
            match ssl_stream.connect() {
                Ok(_) => {
                    trace!("DTLS handshake complete");
                    break;
                }
                Err(e) => match e.code() {
                    ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                        trace!("Handshake in progress: {:?}", e.code());
                        // Wait for socket readiness using mio poll instead of sleeping
                        poll.poll(&mut handshake_events, Some(Duration::from_millis(100)))?;
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("DTLS handshake failed: {e}"),
                        ));
                    }
                },
            }
        }

        poll.registry()
            .reregister(ssl_stream.get_mut().inner_mut(), SOCKET, Interest::READABLE)?;

        Ok(ClientDtlsSocket {
            poll,
            events,
            ssl_stream,
            server_addr: addr,
            local_addr,
            buffer: BytesMut::with_capacity(64 * 1024),
            receive_queue: VecDeque::new(),
        })
    }

    fn do_receive(&mut self) {
        // Read until WouldBlock to drain the socket
        loop {
            if self.buffer.remaining_mut() < 1024 {
                self.buffer.reserve(4096);
            }

            let slice = self.buffer.chunk_mut();
            let outcome = unsafe {
                let buffer = from_raw_parts_mut(slice.as_mut_ptr(), slice.len());
                match self.ssl_stream.read(buffer) {
                    Ok(len) => {
                        self.buffer.advance_mut(len);
                        Ok(len)
                    }
                    e => e,
                }
            };

            match outcome {
                Ok(len) => {
                    let buf = self.buffer.split_to(len).freeze();
                    trace!("Client received {} bytes", len);
                    self.receive_queue.push_back(Packet {
                        buf,
                        addr: self.server_addr,
                    });
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => {
                    trace!("Receive error: {e}");
                    break;
                }
            }
        }
    }
}

impl PacketSocket for ClientDtlsSocket {
    fn get_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn send(&mut self, _addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        // client only talks to one server, ignore addr
        self.ssl_stream.write_all(bytes)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        match self.receive_queue.pop_front() {
            Some(pkt) => {
                let len = pkt.buf.len();
                buffer[..len].copy_from_slice(&pkt.buf);
                Ok(ReceiveResult {
                    len: len as u32,
                    saddr: pkt.addr,
                })
            }
            None => Err(io::Error::new(ErrorKind::WouldBlock, "would block")),
        }
    }

    fn poll(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.poll.poll(&mut self.events, timeout)?;

        let should_receive = self
            .events
            .iter()
            .any(|e| e.token() == SOCKET && e.is_readable());

        if should_receive {
            self.do_receive();
        }

        Ok(())
    }
}
