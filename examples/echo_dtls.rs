use std::time::Duration;

use enet_dtls::{
    PacketSocket, PacketSocketWrapper, ServerSocketOptions,
    tls::{CertConfig, CookieConfig, ServerTlsOptions, TlsConfig, TlsConfigHandle},
};
use log::{info, trace, warn};

fn main() {
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();

    let mut p = PacketSocketWrapper::new();

    let cch = TlsConfigHandle::new(TlsConfig {
        cookies: Some(CookieConfig { secret: 42 }),
        // cookies: None,
        connect_token: None,
        cert: Some(CertConfig {
            cert_path: "test_data/server_cert.pem".into(),
            key_path: "test_data/server_key.pem".into(),
        }),
    });

    let tls = ServerTlsOptions::new(&cch);

    let opts = ServerSocketOptions {
        addr: "127.0.0.1:9001".parse().unwrap(),
        tls,
    };
    p.bind(opts).unwrap();
    let mut buf = vec![0; 1024];
    let mut i = 0;
    loop {
        i+=1;
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
        if i % 10 == 0 {
            trace!("Updating cookie");
            let mut cfg = (**cch.load()).clone();
            cfg.cookies = Some(CookieConfig { secret: i });
            cch.update(cfg);
        }
    }
}
