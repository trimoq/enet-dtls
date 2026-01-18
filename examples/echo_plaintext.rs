use enet_dtls::{
    PacketSocket, PacketSocketWrapper, ServerSocketOptions,
    tls::{CookieConfig, CookieConfigHandle, ServerTlsOptions},
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
            cert_path: "test_data/server_cert.pem".into(),
            key_path: "test_data/server_key.pem".into(),
            cookie: CookieConfigHandle::new(CookieConfig::default()),
        },
    };
    p.bind(opts).unwrap();
    let mut buf = vec![0;1024];
    loop {
        p.poll().unwrap();
        match p.receive(&mut buf){
            Ok(o) => {
                info!("Received from {} {:?}", o.saddr, &buf[..(o.len as usize)]);
                p.send(o.saddr, &buf[..(o.len as usize)]).unwrap();
            },
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock=> {/* ignore */},
                _ => {warn!("e: {e}")},
            },
        }
    }
}
