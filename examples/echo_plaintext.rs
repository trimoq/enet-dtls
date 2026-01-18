use enet_dtls::{PacketSocket, PacketSocketWrapper, ServerSocketOptions, ServerTlsOptions};

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
        },
    };
    p.bind(opts).unwrap();
    loop {
        p.poll().unwrap();
    }
    println!("done")
}
