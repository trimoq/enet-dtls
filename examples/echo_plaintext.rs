use enet_dtls::{PacketSocket, PacketSocketWrapper};

fn main() {
    let mut p = PacketSocketWrapper::new();
    p.bind("127.0.0.1:9001".parse().unwrap()).unwrap();
    loop {
        p.poll().unwrap();
    }
    println!("done")
}
