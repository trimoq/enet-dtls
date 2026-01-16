use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use openssl::ssl::{Ssl, SslAcceptor, SslContext, SslMethod, SslRef, SslStream, SslStreamBuilder};
use openssl_sys::{SSL, bio_addr_st};
use socket2::{Domain, Protocol, Socket, Type};
use slab::Slab;
use std::net::SocketAddr;
use std::io::{self, ErrorKind, Read, Result as IoResult, Write};
use std::os::fd::AsRawFd;
use thiserror::Error;

const LISTENER: Token = Token(0);

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



pub trait PacketSocket {
    fn get_addr(&self) -> io::Result<SocketAddr>;
    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()>;
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult>;
    // fn bind(&mut self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError>;
    // fn connect(&mut self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError>;
    fn is_fresh(&self) ->  bool {false}
}

pub struct DtlsSocket{
    inner: Box<dyn PacketSocket>
}
struct FreshSocket{
}
impl PacketSocket for FreshSocket{
    fn is_fresh(&self) ->  bool {false}
    
    fn get_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "Socket not connected"))
    }
    
    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "Socket not connected"))
    }
    
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "Socket not connected"))
    }
    
    // fn bind(&mut self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
    //     todo!()
    // }
    
    // fn connect(&mut self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
    //     todo!()
    // }
}

struct ServerDtlsSocket{

}
impl ServerDtlsSocket{
    fn bind(addr: SocketAddr) -> io::Result<Self> {
        todo!()
    }
}

impl PacketSocket for ServerDtlsSocket{
    // fn bind(&mut self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
    //     todo!()
    // }
    fn get_addr(&self) -> io::Result<SocketAddr> {
        todo!()
    }

    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        todo!()
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        todo!()
    }
    
    // fn connect(&mut self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
    //     unimplemented!("ServerDtlsSocket cannot connect")
    // }
}

struct ClientDtlsSocket{

}
impl ClientDtlsSocket{
    fn connect(addr: SocketAddr) -> io::Result<Self> {
        todo!()
    }
}
impl PacketSocket for ClientDtlsSocket{
    fn get_addr(&self) -> io::Result<SocketAddr> {
        todo!()
    }

    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        todo!()
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        todo!()
    }
    
    // fn bind(&mut self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
    //     unimplemented!("ClientDtlsSocket cannot bind")
    // }
    
    // fn connect(&mut self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
    //     todo!()
    // }
}

impl PacketSocket for DtlsSocket {

    // fn bind(&mut self, addr: SocketAddr) -> Result<(), PacketSocketError> {
    //     let new = self.inner.bind(addr)?;
    //     self.inner = new;
    //     Ok()
    // }

    // fn connect(&mut self, addr: SocketAddr) -> Result<(), PacketSocketError> {
    //     self.inner.connect(addr)

    // }


    fn get_addr(&self) -> io::Result<SocketAddr> {
       self.inner.get_addr()
    }

    fn send(&mut self, addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        self.inner.send(addr, bytes)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveResult> {
        self.inner.receive(buffer)
    }
}

impl DtlsSocket{

    pub fn new() -> Self{
        DtlsSocket { inner: Box::new(FreshSocket{}) }
    }

    pub fn poll(&mut self) {

    }

    fn bind(&mut self, addr: SocketAddr) -> Result<(), PacketSocketError> {
        if self.inner.is_fresh(){
            self.inner = self.do_bind(addr)?;
            Ok(())
        }
        else {
            Err(PacketSocketError::SocketNotFresh)            
        }
    }

    fn connect(&mut self, addr: SocketAddr) -> Result<(), PacketSocketError> {
        if self.inner.is_fresh() {
            self.inner = self.do_connect(addr)?;
            Ok(())
        }
        else {
            Err(PacketSocketError::SocketNotFresh)            
        }
    }

    pub fn foo() -> std::io::Result<()> {
        let addr: SocketAddr = "0.0.0.0:9001".parse().unwrap();
        let mut poll = Poll::new()?;
        let mut events = Events::with_capacity(128);


        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::dtls_server())?;
        builder.set_private_key_file(&"data/server_key.pem", openssl::ssl::SslFiletype::PEM)?;
        builder.set_certificate_chain_file(&"data/server_cert.pem")?;
        
        builder.set_options(openssl::ssl::SslOptions::COOKIE_EXCHANGE);
        builder.set_cookie_generate_cb(generate_cookie);
        builder.set_cookie_verify_cb(verify_cookie);

        let acc = builder.build();
        let ctx = acc.context();

        let l_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        l_sock.set_reuse_address(true)?;
        l_sock.set_nonblocking(true)?;
        l_sock.bind(&addr.into())?;
        let mut listener = UdpSocket::from_std(l_sock.into());

        poll.registry().register(&mut listener, LISTENER, Interest::READABLE)?;

        let mut clients = Slab::new();
        let mut recv_buf = [0u8; 1500];

        let mut listen_ssl = Ssl::new(&ctx).unwrap();
        let ssl_ref: &mut SslRef = &mut listen_ssl;

        loop {
            poll.poll(&mut events, None)?;

            for event in events.iter() {
                match event.token() {
                    LISTENER => {
                        // 1. Peek to see who is knocking
                        let (len, src) = match listener.peek_from(&mut recv_buf) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };                    
                        
                        println!("NEW CON {:?}", &recv_buf[..len]);

                        let mut ssl = Ssl::new(&ctx).unwrap();
                        let ssl_ref: &mut SslRef = &mut ssl;


                        let is_verified = unsafe {
                            let bio = openssl_sys::BIO_new_dgram(listener.as_raw_fd(), 0);
                            openssl_sys::SSL_set_bio(ssl_ref.as_ptr(), bio,bio);
                            let bio_addr = openssl_sys::BIO_ADDR_new();
                            use foreign_types_shared::ForeignTypeRef;
                            let res = openssl_sys::DTLSv1_listen(ssl_ref.as_ptr(), bio_addr);
                            res > 0
                        };

                        if !is_verified {
                            println!("unverified");
                            continue;
                        }


                        println!("Verified client");

                        let c_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                        c_sock.set_reuse_address(true)?;
                        c_sock.set_nonblocking(true)?;
                        c_sock.bind(&addr.into())?;
                        c_sock.connect(&src.into())?;
                        
                        let mut mio_udp = UdpSocket::from_std(c_sock.into());
                        
                        let entry = clients.vacant_entry();
                        let token = Token(entry.key() + 1); 
                        
                        poll.registry().register(&mut mio_udp, token, Interest::READABLE)?;
                        

                        let wrapper = MioUdpWrapper(mio_udp);
                        let mut ssl_stream = SslStream::new(ssl, wrapper).unwrap();
                        match ssl_stream.accept(){
                            Ok(o) => {
                                println!("handshake accept ok")
                            },
                            Err(e) => {
                                println!("hanshake accept err: {e}")                            
                            },
                        }

                        entry.insert(Client { 
                            ssl_stream,
                            buffer: vec![0u8; 4096],
                        });
                        let _ = listener.recv_from(&mut recv_buf);
                    }
                    token => {
                        println!("Token matching");

                        let client_idx = token.0 - 1;
                        let mut should_remove = false;

                        if let Some(client) = clients.get_mut(client_idx) {
                            // Use the persistent buffer instead of stack allocation
                            match client.ssl_stream.read(&mut client.buffer) {
                                Ok(len) => {
                                    println!("RECEIVED {:?}", &client.buffer[..len]);
                                    let _ = client.ssl_stream.write_all(&client.buffer[..len]);
                                }
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                                    println!("Would block");
                                }
                                Err(e) => {
                                    println!("Removing: {e}");
                                    should_remove = true
                                },
                            }
                        }

                        if should_remove {
                            clients.remove(client_idx);
                        }                }
                }
            }
        }
    }
    
    fn do_bind(&self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
        let sock = ServerDtlsSocket::bind(addr)
            .map_err(|e| PacketSocketError::TODO)?;
        Ok(Box::new(sock))
    }
    fn do_connect(&self, addr: SocketAddr) -> Result<Box<dyn PacketSocket>, PacketSocketError> {
        let sock = ClientDtlsSocket::connect(addr)
            .map_err(|e| PacketSocketError::TODO)?;
        Ok(Box::new(sock))
    }

}

struct Client {
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

fn generate_cookie(_ssl: &mut SslRef, cookie: &mut [u8]) -> Result<usize, openssl::error::ErrorStack> {
    println!("Cookie generataed");
    let secret = b"AAAAAAAAAAAAAAAA";
    cookie[..secret.len()].copy_from_slice(secret);
    Ok(secret.len())
}

fn verify_cookie(_ssl: &mut SslRef, cookie: &[u8]) -> bool {
    let secret = b"AAAAAAAAAAAAAAAA";
    let res = cookie == secret;
    println!("Cookie verified: {res}");
    res
}

