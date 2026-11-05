use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

const LISTEN_ADDRESS: &str = "0.0.0.0:8116";
const MAX_DATAGRAM_SIZE: usize = 65_535;
const PREVIEW_SIZE: usize = 32;

fn address_family(address: &SocketAddr) -> &'static str {
    if address.is_ipv4() { "IPv4" } else { "IPv6" }
}

fn unix_time_millis() -> io::Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(io::Error::other)
}

fn hex_preview(data: &[u8]) -> String {
    let preview_length = data.len().min(PREVIEW_SIZE);
    let mut preview = data[..preview_length]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ");

    if data.len() > preview_length {
        preview.push_str(" ...");
    }

    if preview.is_empty() {
        preview.push_str("<empty>");
    }

    preview
}

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind(LISTEN_ADDRESS)?;
    let local_address = socket.local_addr()?;

    println!("UDP listener ready");
    println!("  Listening address : {local_address}");
    println!("  Process ID        : {}", std::process::id());
    println!("  Waiting for one datagram...");

    let mut buffer = vec![0_u8; MAX_DATAGRAM_SIZE];
    let (received_length, peer_address) = socket.recv_from(&mut buffer)?;
    let received_at = unix_time_millis()?;

    println!("UDP datagram received");
    println!("  Protocol          : UDP");
    println!("  Address family    : {}", address_family(&peer_address));
    println!("  Local address     : {}", local_address.ip());
    println!("  Local port        : {}", local_address.port());
    println!("  Remote address    : {}", peer_address.ip());
    println!("  Remote port       : {}", peer_address.port());
    println!("  Datagram bytes    : {received_length}");
    println!(
        "  Payload hex       : {}",
        hex_preview(&buffer[..received_length])
    );
    println!("  Unix time (ms)    : {received_at}");
    println!("  Listener state    : stopped");

    Ok(())
}
