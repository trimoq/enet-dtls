use enet_dtls::{
    PacketSocket, PacketSocketWrapper, ServerSocketOptions,
    tls::{CertConfig, ServerTlsOptions, TlsConfig, TlsConfigHandle},
};
use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

fn spawn_echo_server(
    addr: SocketAddr,
    tls_config: TlsConfig,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let opts = ServerSocketOptions {
            addr,
            tls: ServerTlsOptions {
                handle: TlsConfigHandle::new(tls_config),
            },
        };
        let mut server = PacketSocketWrapper::new();
        server.bind(opts).expect("bind failed");
        let mut buf = vec![0u8; 1500];

        while running.load(Ordering::Relaxed) {
            if server.poll().is_err() {
                continue;
            }
            match server.receive(&mut buf) {
                Ok(res) => {
                    eprintln!("[server] received {} bytes from {}", res.len, res.saddr);
                    if let Err(e) = server.send(res.saddr, &buf[..res.len as usize]) {
                        eprintln!("[server] send error: {}", e);
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("[server] recv error: {}", e),
            }
        }
    })
}

fn recv_with_retry(client: &UdpSocket, buf: &mut [u8], retries: usize) -> std::io::Result<usize> {
    for i in 0..retries {
        match client.recv(buf) {
            Ok(len) => return Ok(len),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                eprintln!("[client] retry {}/{}", i + 1, retries);
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        ErrorKind::TimedOut,
        "recv timed out after retries",
    ))
}

/// Plaintext UDP echo test using UdpSocket.
#[test]
fn test_plaintext_echo_with_udpsocket() {
    let server_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let handle = spawn_echo_server(server_addr, TlsConfig::default(), running.clone());

    thread::sleep(Duration::from_millis(100));

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    client.connect(server_addr).unwrap();

    let msg = b"hello plaintext";
    client.send(msg).unwrap();

    let mut buf = [0u8; 64];
    let len = recv_with_retry(&client, &mut buf, 30).expect("recv failed after retries");
    assert_eq!(&buf[..len], msg, "echo mismatch: got {:?}", &buf[..len]);

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

/// Plaintext UDP echo test using netcat.
#[test]
fn test_plaintext_echo_with_netcat() {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let server_addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let handle = spawn_echo_server(server_addr, TlsConfig::default(), running.clone());

    thread::sleep(Duration::from_millis(100));

    let mut child = Command::new("nc")
        .args(["-u", "127.0.0.1", "9002"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn nc - is netcat installed?");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let msg = b"hello netcat\n";
    stdin.write_all(msg).expect("write to nc failed");
    stdin.flush().unwrap();

    // Read response with timeout via thread
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut buf = [0u8; 64];
        let len = stdout.read(&mut buf).unwrap_or(0);
        let _ = tx.send(buf[..len].to_vec());
    });

    let response = rx.recv_timeout(Duration::from_secs(3)).unwrap_or_default();
    assert_eq!(
        response,
        msg,
        "echo mismatch: got {:?}",
        String::from_utf8_lossy(&response)
    );

    let _ = child.kill();
    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

/// DTLS echo test using openssl s_client.
#[test]
fn test_dtls_server_with_openssl_client() {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let server_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let tls_config = TlsConfig {
        cookies: None,
        connect_token: None,
        cert: Some(CertConfig {
            cert_path: "test_data/server_cert.pem".into(),
            key_path: "test_data/server_key.pem".into(),
        }),
    };
    let running = Arc::new(AtomicBool::new(true));
    let handle = spawn_echo_server(server_addr, tls_config, running.clone());

    thread::sleep(Duration::from_millis(10));

    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-dtls1_2",
            "-connect",
            "127.0.0.1:9001",
            "-quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn openssl s_client");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // Give handshake time to complete
    thread::sleep(Duration::from_millis(100));

    let msg = b"hello dtls\n";
    stdin.write_all(msg).expect("write to openssl failed");
    stdin.flush().unwrap();

    // Read response with timeout via thread (makes )
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut buf = [0u8; 64];
        let len = stdout.read(&mut buf).unwrap_or(0);
        let _ = tx.send(buf[..len].to_vec());
    });

    let response = rx.recv_timeout(Duration::from_secs(3)).unwrap_or_default();
    assert_eq!(
        response, b"hello dtls\n",
        "echo mismatch: got {:?}",
        response
    );

    let _ = child.kill();
    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

/// Multiple clients sending to plaintext server.
/// Currently ignored due to mio polling issues - run with `cargo test -- --ignored`
#[test]
fn test_plaintext_multiple_clients() {
    let server_addr: SocketAddr = "127.0.0.1:19003".parse().unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let handle = spawn_echo_server(server_addr, TlsConfig::default(), running.clone());

    thread::sleep(Duration::from_millis(100));

    let clients: Vec<_> = (0..3)
        .map(|i| {
            let client = UdpSocket::bind("127.0.0.1:0").unwrap();
            client
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            client.connect(server_addr).unwrap();
            (client, format!("msg from client {}", i))
        })
        .collect();

    // Send one at a time with small delay
    for (client, msg) in &clients {
        client.send(msg.as_bytes()).unwrap();
        thread::sleep(Duration::from_millis(10));
    }

    for (client, msg) in &clients {
        let mut buf = [0u8; 64];
        let len = recv_with_retry(client, &mut buf, 30).expect("recv failed after retries");
        assert_eq!(&buf[..len], msg.as_bytes());
    }

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}
