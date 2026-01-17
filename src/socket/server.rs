use log::{trace, warn};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Registry, Token};
use openssl::ssl::{ErrorCode, Ssl, SslAcceptor, SslMethod, SslRef, SslStream};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, ErrorKind, Read, Result as IoResult, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use crate::socket::connections::Connections;
use crate::{PacketSocket, ReceiveResult};

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

        let entry = self.connections.vacant_entry();
        let token = Token(entry.key() + 1);

        registry.register(&mut mio_udp, token, Interest::READABLE)?;

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
            buffer: vec![0u8; 4096],
        });

        Ok(())
    }

    fn handle_packet_on_existing_connection(&mut self, token: Token) {
        trace!("Token matching");

        let client_idx = token.0 - 1;
        let mut should_remove = false;

        if let Some(client) = self.connections.get_mut(client_idx) {
            // Use the persistent buffer instead of stack allocation
            match client.ssl_stream.read(&mut client.buffer) {
                Ok(len) => {
                    trace!("RECEIVED {:?}", &client.buffer[..len]);
                    let _ = client.ssl_stream.write_all(&client.buffer[..len]);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    trace!("Would block");
                }
                Err(e) => {
                    trace!("Removing: {e}");
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
        todo!()
    }

    fn send(&mut self, _addr: SocketAddr, _bytes: &[u8]) -> io::Result<()> {
        todo!()
    }

    fn receive(&mut self, _buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        todo!()
    }

    fn poll(&mut self) -> io::Result<()> {
        let ServerDtlsSocket {
            mio_stuff,
            tls_stuff,
            state,
        } = self;

        mio_stuff.poll.poll(&mut mio_stuff.events, None)?;

        // todo, receive globals here

        for event in mio_stuff.events.iter() {
            match event.token() {
                LISTENER => {
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
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        // todo: allow shared poll pool to be used, passed in from the outside
        let poll = Poll::new()?;
        let events = Events::with_capacity(128);

        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::dtls_server())?;
        builder
            .set_private_key_file(&"test_data/server_key.pem", openssl::ssl::SslFiletype::PEM)?;
        builder.set_certificate_chain_file(&"test_data/server_cert.pem")?;

        builder.set_options(openssl::ssl::SslOptions::COOKIE_EXCHANGE);
        builder.set_cookie_generate_cb(generate_cookie);
        builder.set_cookie_verify_cb(verify_cookie);

        let acc = builder.build();

        let l_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        l_sock.set_reuse_address(true)?;
        l_sock.set_nonblocking(true)?;
        l_sock.bind(&addr.into())?;
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
                addr,
            },
        };
        Ok(res)
    }
}

pub struct Client {
    ssl_stream: SslStream<MioUdpWrapper>,
    buffer: Vec<u8>,
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
