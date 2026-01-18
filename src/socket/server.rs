use bytes::{BufMut, BytesMut};
use log::{debug, trace, warn};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Registry, Token};
use openssl::ssl::{ErrorCode, Ssl, SslAcceptor, SslMethod, SslStream};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::slice::from_raw_parts_mut;
use std::time::Duration;

use crate::protocol::EnetDissector;
use crate::socket::connections::Connections;
use crate::tls::{CookieConfig, TlsConfig, TlsConfigHandle};
use crate::{Packet, PacketSocket, ReceiveResult, ServerSocketOptions};

const LISTENER: Token = Token(0);

pub struct ServerDtlsSocket {
    mio_stuff: MioStuff,
    tls_stuff: TlsStuff,
    state: State,
}
struct MioStuff {
    poll: Poll,
    events: Events,
}
struct TlsStuff {
    tls_enabled: bool,
    cookies_enabled: bool,

    acc: SslAcceptor,

    config_handle: TlsConfigHandle,
    config_generation: u64,
}

fn secret_to_bytes(secret: u64) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&secret.to_le_bytes());
    bytes
}

impl TlsStuff {
    fn new(acc: SslAcceptor, config_handle: TlsConfigHandle) -> Self {
        let config_generation = config_handle.generation();
        let config = config_handle.load();
        TlsStuff {
            tls_enabled: config.is_tls_enabled(),
            cookies_enabled: config.are_cookies_enabled(),
            acc,
            config_handle,
            config_generation,
        }
    }

    fn build_acceptor(tls_config: &TlsConfig) -> io::Result<SslAcceptor> {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::dtls_server())?;

        if let Some(cert_config) = &tls_config.cert {
            builder.set_private_key_file(
                cert_config.key_path.clone(),
                openssl::ssl::SslFiletype::PEM,
            )?;
            builder.set_certificate_chain_file(cert_config.cert_path.clone())?;
        }

        if let Some(cookie_config) = &tls_config.cookies {
            trace!("Configuring with cookies enabled");
            builder.set_options(openssl::ssl::SslOptions::COOKIE_EXCHANGE);

            let secret = secret_to_bytes(cookie_config.secret);
            builder.set_cookie_generate_cb(move |_ssl, cookie| {
                trace!("Cookie generated");
                cookie[..secret.len()].copy_from_slice(&secret);
                Ok(secret.len())
            });

            let secret = secret_to_bytes(cookie_config.secret);
            builder.set_cookie_verify_cb(move |_ssl, cookie| {
                let res = cookie == secret;
                trace!("Cookie verified: {res}");
                res
            });
        }

        Ok(builder.build())
    }

    fn check_and_rebuild(&mut self) -> io::Result<()> {
        let new_gen = self.config_handle.generation();
        if new_gen != self.config_generation {
            let config = self.config_handle.load();
            self.tls_enabled = config.is_tls_enabled();
            self.cookies_enabled = config.are_cookies_enabled();
            self.acc = Self::build_acceptor(&config)?;
            self.config_generation = new_gen;
            debug!("Rebuilt TLS acceptor with new config");
        }
        Ok(())
    }
}

struct State {
    addr: SocketAddr,
    connections: Connections,
    listener: UdpSocket,
    buffer: BytesMut,
    receive_queue: VecDeque<Packet>,
}

impl State {
    fn handle_packet_on_new_connection(
        &mut self,
        tls: &TlsStuff,
        registry: &Registry,
    ) -> io::Result<()> {
        let mut recv_buf = [0u8; 1500];
        let (len, src) = match self.listener.peek_from(&mut recv_buf) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        trace!("New accept: {:?}", &recv_buf[..len]);

        if tls.tls_enabled {
            trace!("TLS is enabled");
            let (ssl, is_verified) = self.fun_name(tls);
            if !is_verified {
                trace!("Unverified packet, dropping");
                return Ok(());
            }

            trace!("Verified packet, begin client setup");

            let (entry, con_id, wrapper) = self.hannes(registry, src)?;
            let mut ssl_stream = SslStream::new(ssl, wrapper).map_err(|_e| {
                warn!("SSL stream crreation failed");
                io::Error::new(io::ErrorKind::NotConnected, "Socket not connected")
            })?;
            match ssl_stream.accept() {
                Ok(_) => {
                    trace!("Handshake accept ok")
                }
                Err(e) => {
                    trace!("Hanshake accept err: {e}");
                    match e.code() {
                        ErrorCode::WANT_READ => trace!("Read would have blocked"),
                        ErrorCode::WANT_WRITE => trace!("Write would have blocked"),
                        _ => {
                            warn!("Other error occured");
                            return Ok(());
                        }
                    }
                }
            }
            entry.insert(Client {
                // ssl_stream,
                stream: Box::new(ssl_stream),
                addr: src,
                con_id,
            });
        } else {
            trace!("TLS is DISABLED");
            trace!("Verified client, begin client setup");
            let (entry, con_id, wrapper) = self.hannes(registry, src)?;
            entry.insert(Client {
                // ssl_stream,
                stream: Box::new(wrapper),
                addr: src,
                con_id,
            });
        }

        Ok(())
    }

    fn hannes(
        &mut self,
        registry: &Registry,
        src: SocketAddr,
    ) -> Result<(slab::VacantEntry<'_, Client>, usize, MioUdpWrapper), io::Error> {
        let c_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        c_sock.set_reuse_address(true)?;
        c_sock.set_nonblocking(true)?;
        c_sock.bind(&(self.addr.into()))?;
        c_sock.connect(&src.into())?;

        let mut mio_udp = UdpSocket::from_std(c_sock.into());
        let entry = self.connections.vacant_entry(src);
        let token = Token(entry.key() + 1);
        let con_id = entry.key();
        registry.register(
            &mut mio_udp,
            token,
            Interest::READABLE.add(Interest::WRITABLE),
        )?;
        let wrapper = MioUdpWrapper(mio_udp);
        Ok((entry, con_id, wrapper))
    }

    fn fun_name(&mut self, tls: &TlsStuff) -> (Ssl, bool) {
        let mut ssl = Ssl::new(&tls.acc.context()).unwrap();
        let ssl_ref = &mut ssl;
        if !tls.cookies_enabled {
            trace!("Cookies disabled, won't verify first packet");
            return (ssl, true);
        }

        trace!("Verifying first packet");
        let is_verified = unsafe {
            let bio: *mut openssl_sys::bio_st =
                openssl_sys::BIO_new_dgram(self.listener.as_raw_fd(), 0);
            openssl_sys::SSL_set_bio(ssl_ref.as_ptr(), bio, bio);
            let bio_addr = openssl_sys::BIO_ADDR_new();
            use foreign_types_shared::ForeignTypeRef;
            let res = openssl_sys::DTLSv1_listen(ssl_ref.as_ptr(), bio_addr);
            trace!("Verify result: {res}");
            res > 0
        };
        (ssl, is_verified)
    }

    fn handle_packet_on_existing_connection(&mut self, token: Token) {
        trace!("Token matching");

        if self.buffer.remaining_mut() < 1024 {
            self.buffer.reserve(4096);
        }

        let client_idx = token.0 - 1;
        let mut should_remove = false;

        if let Some(client) = self.connections.get_mut(client_idx) {
            trace!("Handling client [{}]", client.con_id);
            let slice = self.buffer.chunk_mut();

            // safety: the uninitalized memory is passed to openssl and we must only read from it
            let outcome = unsafe {
                let buffer = from_raw_parts_mut(slice.as_mut_ptr(), slice.len());
                match client.stream.read(buffer) {
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
                    trace!("RECEIVED {:?}", &buf[..]);
                    self.receive_queue.push_back(Packet {
                        buf,
                        addr: client.addr,
                    });
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    trace!("Would block");
                }
                Err(e) => {
                    trace!("Removing [{}]: {e}", client.addr);
                    should_remove = true
                }
            }
        }

        if should_remove {
            self.connections.remove(client_idx);
        }
    }
}

impl PacketSocket for ServerDtlsSocket {
    fn get_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.state.addr)
    }

    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        // fuck it, we ball: if the socket can't send, drop it
        match self.state.connections.get_by_ip_mut(addr) {
            Some(s) => s.stream.write(bytes).map(|_| ()),
            None => {
                println!("Client gone");
                Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "client vanished",
                ))
            }
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        // trace!("receive");
        match self.state.receive_queue.pop_front() {
            Some(pkt) => {
                // trace!(
                //     "received pkt: {}: {}",
                //     pkt.buf.len(),
                //     EnetDissector::parse(&pkt.buf).unwrap()
                // );
                let len = pkt.buf.len();
                buffer[..len].clone_from_slice(&pkt.buf);
                Ok(ReceiveResult {
                    len: len as u32,
                    saddr: pkt.addr,
                })
            }
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "would block")),
        }
    }

    fn poll(&mut self) -> io::Result<()> {
        let ServerDtlsSocket {
            mio_stuff,
            tls_stuff,
            state,
        } = self;

        tls_stuff.check_and_rebuild()?;

        mio_stuff
            .poll
            .poll(&mut mio_stuff.events, Some(Duration::from_micros(1)))?;

        for event in mio_stuff.events.iter() {
            match event.token() {
                LISTENER => {
                    let _ =
                        state.handle_packet_on_new_connection(tls_stuff, mio_stuff.poll.registry());
                }
                token => {
                    state.handle_packet_on_existing_connection(token);
                }
            }
        }

        Ok(())
    }
}

impl ServerDtlsSocket {
    pub fn bind(opts: ServerSocketOptions) -> io::Result<Self> {
        let poll = Poll::new()?;
        let events = Events::with_capacity(128);

        let tls_config = opts.tls.handle.load();
        let acc = TlsStuff::build_acceptor(&tls_config)?;

        let l_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        l_sock.set_reuse_address(true)?;
        l_sock.set_nonblocking(true)?;
        l_sock.bind(&opts.addr.into())?;
        let mut listener = UdpSocket::from_std(l_sock.into());

        poll.registry()
            .register(&mut listener, LISTENER, Interest::READABLE)?;

        let connections = Connections::new();

        let res = ServerDtlsSocket {
            mio_stuff: MioStuff { poll, events },
            tls_stuff: TlsStuff::new(acc, opts.tls.handle),
            state: State {
                connections,
                listener,
                addr: opts.addr,
                buffer: BytesMut::with_capacity(1024 * 1024),
                receive_queue: VecDeque::new(),
            },
        };
        Ok(res)
    }
}

pub struct Client {
    pub(crate) addr: SocketAddr,
    // ssl_stream: SslStream<MioUdpWrapper>,
    stream: Box<dyn ReadWrite>,
    con_id: usize,
}

trait ReadWrite: Read + Write {}
impl<S: Read + Write> ReadWrite for S {}

#[derive(Debug)]
pub struct MioUdpWrapper(pub UdpSocket);

impl Read for MioUdpWrapper {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.0.recv(buf)
    }
}

impl Write for MioUdpWrapper {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.0.send(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}
