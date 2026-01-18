use bytes::{BufMut, BytesMut};
use log::{trace, warn};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Registry, Token};
use openssl::ssl::{ErrorCode, Ssl, SslAcceptor, SslMethod, SslRef, SslStream};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::slice::from_raw_parts_mut;
use std::time::Duration;

use crate::protocol::EnetDissector;
use crate::socket::connections::Connections;
use crate::socket::ServerSocketOptions;
use crate::{Packet, PacketSocket, ReceiveResult};

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
    acc: SslAcceptor,
}
struct State {
    addr: SocketAddr,
    connections: Connections,
    listener: UdpSocket,
    buffer: BytesMut,
    receive_queue: VecDeque<Packet>,
    send_queue: VecDeque<Packet>,
}

impl State {
    fn handle_packet_on_new_connection(
        &mut self,
        tls: &TlsStuff,
        registry: &Registry,
    ) -> io::Result<()> {
        let mut recv_buf = [0u8; 1500];
        let ctx = tls.acc.context();

        let (len, src) = match self.listener.peek_from(&mut recv_buf) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        trace!("New accept: {:?}", &recv_buf[..len]);

        let mut ssl = Ssl::new(&ctx).unwrap();
        let ssl_ref: &mut SslRef = &mut ssl;

        let is_verified = unsafe {
            let bio = openssl_sys::BIO_new_dgram(self.listener.as_raw_fd(), 0);
            openssl_sys::SSL_set_bio(ssl_ref.as_ptr(), bio, bio);
            let bio_addr = openssl_sys::BIO_ADDR_new();
            use foreign_types_shared::ForeignTypeRef;
            let res = openssl_sys::DTLSv1_listen(ssl_ref.as_ptr(), bio_addr);
            trace!("Verify result: {res}");
            res > 0
        };

        if !is_verified {
            trace!("Unverified cookie, dropping");
            // let _ = self.listener.recv_from(&mut recv_buf);
            return Ok(());
        }

        trace!("Verified client, begin client setup");

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
            ssl_stream,
            addr: src,
            con_id,
            send_buffer: VecDeque::new(),
        });

        Ok(())
    }

    fn handle_packet_on_existing_connection(&mut self, token: Token) {
        trace!("Token matching");

        if self.buffer.remaining_mut() < 1024 {
            self.buffer.reserve(4096);
        }

        let client_idx = token.0 - 1;
        let mut should_remove = false;

        if let Some(client) = self.connections.get_mut(client_idx) {
            let slice = self.buffer.chunk_mut();

            // safety: the uninitalized memory is passed to openssl and we must only read from it
            let outcome = unsafe {
                let buffer = from_raw_parts_mut(slice.as_mut_ptr(), slice.len());
                match client.ssl_stream.read(buffer) {
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
                    // trace!("RECEIVED {:?}", &buf[..]);
                    self.receive_queue.push_back(Packet {
                        buf,
                        addr: client.addr,
                    });
                    // client.buffers.push_back(buf);
                    // let _ = client.ssl_stream.write_all(&client.buffer[..len]);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    // trace!("Would block");
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
            Some(s) => s.ssl_stream.write(bytes).map(|_| ()),
            None => {
                println!("Client gone");
                Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "client vanished",
                ))
            }
        }

        // todo limit size of queue
        // let x = self.state.connections.get_by_ip_mut(addr).unwrap();
        // self.state.send_queue.push_back(Packet { buf: (), addr: () });
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        // trace!("receive");
        match self.state.receive_queue.pop_front() {
            Some(pkt) => {
                trace!(
                    "received pkt: {}: {}",
                    pkt.buf.len(),
                    EnetDissector::parse(&pkt.buf).unwrap()
                );
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

        mio_stuff
            .poll
            .poll(&mut mio_stuff.events, Some(Duration::from_micros(1)))?;

        // todo, receive globals here

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

        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::dtls_server())?;
        builder.set_private_key_file(&opts.tls.key_path, openssl::ssl::SslFiletype::PEM)?;
        builder.set_certificate_chain_file(&opts.tls.cert_path)?;

        builder.set_options(openssl::ssl::SslOptions::COOKIE_EXCHANGE);
        builder.set_cookie_generate_cb(generate_cookie);
        builder.set_cookie_verify_cb(verify_cookie);

        let acc = builder.build();

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
            tls_stuff: TlsStuff { acc },
            state: State {
                connections,
                listener,
                addr: opts.addr,
                buffer: BytesMut::with_capacity(1024 * 1024),
                receive_queue: VecDeque::new(),
                send_queue: VecDeque::new(),
            },
        };
        Ok(res)
    }
}

pub struct Client {
    pub(crate) addr: SocketAddr,
    ssl_stream: SslStream<MioUdpWrapper>,
    con_id: usize,
    send_buffer: VecDeque<Packet>,
}

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

fn generate_cookie(
    _ssl: &mut SslRef,
    cookie: &mut [u8],
) -> Result<usize, openssl::error::ErrorStack> {
    trace!("Cookie generataed");
    let secret = b"AAAAAAAAAAAAAAAA";
    cookie[..secret.len()].copy_from_slice(secret);
    Ok(secret.len())
}

fn verify_cookie(_ssl: &mut SslRef, cookie: &[u8]) -> bool {
    let secret = b"AAAAAAAAAAAAAAAA";
    let res = cookie == secret;
    trace!("Cookie verified: {res}");
    res
}
