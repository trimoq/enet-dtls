use std::io::Write;
use std::{
    net::Ipv4Addr,
    ops::Sub,
    thread,
    time::{Duration, Instant},
};

use enet::{Address, BandwidthLimit, ChannelLimit, Enet, Event, Packet, PacketMode};
use enet_dtls::PacketSocketWrapper;
use log::{info, warn};

fn main() {
    println!("Starting");

    // let mut p = PacketSocketWrapper::new();
    // p.bind("127.0.0.1:9999".parse().unwrap()).unwrap();

    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();
    enet_dtls::ffi::force_link_symbols();
    let enet = Enet::new().unwrap();

    let local_addr = Address::new(Ipv4Addr::LOCALHOST, 9001);
    println!("aasdasdasdas");

    let mut host = enet
        .create_host::<()>(
            Some(&local_addr),
            1000,
            ChannelLimit::Maximum,
            BandwidthLimit::Unlimited,
            BandwidthLimit::Unlimited,
        )
        .expect("could not create host");
    let mut i: u32 = 0;
    println!("Looping");
    loop {
        let start = Instant::now();
        match host.service(0).expect("service failed") {
            Some(Event::Connect(ref mut _peer)) => {
                println!("new connection");
            }
            Some(Event::Disconnect(ref p, user_data)) => {
                println!("closed connection: {:?}", p.mean_rtt());
            }
            Some(Event::Receive {
                channel_id,
                ref packet,
                ref mut sender,
            }) => {
                println!(
                    "RECEIVED {:x?} on ch {} from {}",
                    packet.data(),
                    channel_id,
                    sender.address().ip()
                );
                let echo = Packet::new(packet.data(), PacketMode::ReliableSequenced).unwrap();
                let _ = sender.send_packet(echo, channel_id);
            }
            _ => {}
        }
        let elapsed = start.elapsed();
        let target = Duration::from_micros(1050);
        let limit = Duration::from_micros(1500);
        if elapsed > target {
            if elapsed > limit {
                println!("exceptional service time: {:?}", elapsed);
            }
        } else {
            let remaining_dur = target - elapsed;
            thread::sleep(remaining_dur);
        }
        i += 1;
    }
}
