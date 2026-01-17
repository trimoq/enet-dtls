use enet_dtls::{PacketSocket, PacketSocketWrapper};

fn main() {
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();

    let mut p = PacketSocketWrapper::new();
    p.bind("127.0.0.1:9001".parse().unwrap()).unwrap();
    loop {
        p.poll().unwrap();
    }
    println!("done")
}
