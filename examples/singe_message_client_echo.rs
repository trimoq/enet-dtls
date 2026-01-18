extern crate enet;

use std::collections::HashMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use enet::*;
use enet_dtls::ffi;
use enet_dtls::ffi::local::set_client_tls_options;
use enet_dtls::tls::ClientTlsOptions;
use log::{error, info, warn};

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();
    enet_dtls::ffi::force_link_symbols();

    let enet = Enet::new().context("could not initialize ENet")?;

    let mut host = enet
        .create_host::<()>(
            None,
            10,
            ChannelLimit::Maximum,
            BandwidthLimit::Unlimited,
            BandwidthLimit::Unlimited,
        )
        .context("could not create host")?;

    let tls = ClientTlsOptions {
        ca_cert_path: "test_data/server_cert.pem".into(),
        domain: "localhost".into(),
        verify: true,
    };

    set_client_tls_options(tls);

    host.connect(&Address::new(Ipv4Addr::LOCALHOST, 9001), 1, 0)
        .context("connect failed")?;

    // Wait for connection
    let mut retries = 10;
    loop {
        retries -= 1;
        match host.service(100).context("service failed")? {
            Some(Event::Connect(_)) => {
                info!("[client] connected");
                break;
            }
            Some(Event::Disconnect(_, r)) => {
                anyhow::bail!("connection NOT successful, reason: {}", r);
            }
            Some(Event::Receive { .. }) => {
                anyhow::bail!("unexpected Receive-event while waiting for connection")
            }
            None => {}
        }
        if retries <= 0 {
            panic!("Not able to connect");
        }
    }

    let seq = 42u32;

    let mut data = vec![0u8; 5];
    data[0] = 0x01;
    data[1..5].copy_from_slice(&seq.to_le_bytes());

    let mut peer = host.peers().next().context("no connected peer?")?;

    peer.send_packet(
        Packet::new(&data, PacketMode::ReliableSequenced).unwrap(),
        0,
    )
    .context("dafuq? sending packet failed")?;

    let mut verified = false;
    let mut retries = 10;

    loop {
        retries -= 1;
        match host.service(100).context("service failed") {
            Ok(Some(e)) => match &e {
                Event::Connect(_) => info!("[client] connect event"),
                Event::Disconnect(_, _) => {
                    warn!("[client] disconnected");
                    break;
                }
                Event::Receive { packet, .. } => {
                    println!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                    let data = packet.data();
                    if data.len() >= 5 && data[0] == 0x01 {
                        let recv_seq = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                        if recv_seq == seq {
                            verified = true;
                            break;
                        }
                    } else {
                        warn!("[client] received unexpected: {:?}", data);
                    }
                }
            },
            Ok(None) => {}
            Err(e) => error!("[client] service error: {}", e),
        }
        if retries <= 0 {
            panic!("No message within a few retries");
        }
    }

    if verified {
        info!("Sent message verified, all good");
    } else {
        panic!("Sent message not verified");
    }

    Ok(())
}
