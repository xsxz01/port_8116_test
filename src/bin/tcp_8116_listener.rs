use std::io;
use std::net::{SocketAddr, TcpListener};
use std::time::{SystemTime, UNIX_EPOCH};

const LISTEN_ADDRESS: &str = "0.0.0.0:8116";

fn address_family(address: &SocketAddr) -> &'static str {
    if address.is_ipv4() { "IPv4" } else { "IPv6" }
}

fn unix_time_millis() -> io::Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(io::Error::other)
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind(LISTEN_ADDRESS)?;
    let listen_address = listener.local_addr()?;

    println!("TCP listener ready");
    println!("  Listening address : {listen_address}");
    println!("  Process ID        : {}", std::process::id());
    println!("  Waiting for one connection...");

    let (stream, peer_address) = listener.accept()?;
    drop(listener);

    let local_address = stream.local_addr()?;
    let connected_at = unix_time_millis()?;

    println!("TCP connection accepted");
    println!("  Protocol          : TCP");
    println!("  Address family    : {}", address_family(&peer_address));
    println!("  Local address     : {}", local_address.ip());
    println!("  Local port        : {}", local_address.port());
    println!("  Remote address    : {}", peer_address.ip());
    println!("  Remote port       : {}", peer_address.port());
    println!("  Unix time (ms)    : {connected_at}");
    println!("  Listener state    : stopped");

    Ok(())
}
