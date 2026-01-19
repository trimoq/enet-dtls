use std::time::Duration;

use enet_dtls::{
    PacketSocket, PacketSocketWrapper, ServerSocketOptions,
    tls::{CookieConfig, ServerTlsOptions, TlsConfig, TlsConfigHandle},
};
use log::{info, warn};

fn main() {
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();

    let mut p = PacketSocketWrapper::new();
    let opts = ServerSocketOptions {
        addr: "127.0.0.1:9001".parse().unwrap(),
        tls: ServerTlsOptions {
            handle: TlsConfigHandle::new(TlsConfig::default()),
        },
    };
    p.bind(opts).unwrap();
    let mut buf = vec![0; 1024];
    loop {
        p.poll(Some(Duration::from_millis(100))).unwrap();
        match p.receive(&mut buf) {
            Ok(o) => {
                info!("Received from {} {:?}", o.saddr, &buf[..(o.len as usize)]);
                p.send(o.saddr, &buf[..(o.len as usize)]).unwrap();
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock => { /* ignore */ }
                _ => {
                    warn!("e: {e}")
                }
            },
        }
    }
}
