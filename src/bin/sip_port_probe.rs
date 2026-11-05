use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_TARGET: &str = "10.7.2.19";
const DEFAULT_PORT: u16 = 5060;
const DEFAULT_TIMEOUT_MS: u64 = 3000;
const RECV_BUFFER_SIZE: usize = 8192;
const PREVIEW_SIZE: usize = 256;

struct Args {
    port: u16,
    target: IpAddr,
    timeout: Duration,
}

fn usage() {
    eprintln!(
        "Usage: sip_port_probe --port PORT [--target IP] [--timeout-ms MS]"
    );
}

fn parse_args() -> Option<Args> {
    let mut port: Option<u16> = None;
    let mut target: Option<IpAddr> = None;
    let mut timeout_ms: Option<u64> = None;

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--port" => port = iter.next().and_then(|p| p.parse().ok()),
            "--target" => target = iter.next().and_then(|t| t.parse().ok()),
            "--timeout-ms" => timeout_ms = iter.next().and_then(|t| t.parse().ok()),
            other => {
                eprintln!("Unknown argument: {}", other);
                return None;
            }
        }
    }

    Some(Args {
        port: port.unwrap_or(DEFAULT_PORT),
        target: target.unwrap_or_else(|| {
            DEFAULT_TARGET
                .parse::<Ipv4Addr>()
                .expect("DEFAULT_TARGET must be a valid IPv4 address")
                .into()
        }),
        timeout: Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
    })
}

fn random_token(len: usize) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let seed = count.wrapping_add(now).wrapping_add(process::id() as u64);
    format!("{:0width$x}", seed, width = len)
}

fn build_sip_register(target: SocketAddr, local: SocketAddr) -> String {
    let branch = format!("z9hG4bK{}", random_token(8));
    let tag = random_token(8);
    let call_id = format!("{}@{}", random_token(16), local.ip());
    let user = "probe";

    let lines = [
        format!("REGISTER sip:{user}@{target} SIP/2.0"),
        format!("Via: SIP/2.0/UDP {local};branch={branch}"),
        format!("From: <sip:{user}@{local}>;tag={tag}"),
        format!("To: <sip:{user}@{target}>"),
        format!("Call-ID: {call_id}"),
        "CSeq: 1 REGISTER".to_string(),
        "Max-Forwards: 70".to_string(),
        "Expires: 3600".to_string(),
        format!("Contact: <sip:{user}@{local}>"),
        "User-Agent: sip-port-probe/0.1".to_string(),
        "Content-Length: 0".to_string(),
    ];
    lines.join("\r\n") + "\r\n\r\n"
}

fn text_preview(data: &[u8]) -> String {
    let preview: String = data
        .iter()
        .take(PREVIEW_SIZE)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    let mut out = preview.replace('\r', "\\r").replace('\n', "\\n");
    if data.len() > PREVIEW_SIZE {
        out.push_str(" ...");
    }
    if out.is_empty() {
        out.push_str("<empty>");
    }
    out
}

fn parse_sip_status(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let first_line = text.lines().next()?;
    let trimmed = first_line.trim();
    if trimmed.starts_with("SIP/2.0") {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn probe_udp(args: &Args) -> io::Result<()> {
    let target = SocketAddr::new(args.target, args.port);

    println!("Probe configuration");
    println!("  Protocol          : UDP");
    println!("  Target address    : {}", args.target);
    println!("  Target port       : {}", args.port);
    println!("  Timeout           : {:?}", args.timeout);
    println!();

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(target)?;
    let local = socket.local_addr()?;
    socket.set_read_timeout(Some(args.timeout))?;

    println!("Stage 1: Send SIP REGISTER request");
    let sip = build_sip_register(target, local);
    let bytes_sent = socket.send(sip.as_bytes())?;
    println!("  Local address     : {}", local);
    println!("  Request bytes     : {}", bytes_sent);
    println!("  Request preview   : {}", text_preview(sip.as_bytes()));

    println!();
    println!("Stage 2: Wait for SIP response");
    let mut buffer = vec![0_u8; RECV_BUFFER_SIZE];
    match socket.recv(&mut buffer) {
        Ok(n) => {
            buffer.truncate(n);
            println!("  Result            : RECEIVED");
            println!("  Response bytes    : {}", n);
            println!("  Response preview  : {}", text_preview(&buffer));
            if let Some(status) = parse_sip_status(&buffer) {
                println!("  SIP status line   : {}", status);
                println!();
                println!("Probe complete");
                println!("  Overall result    : REACHABLE (SIP response received)");
                Ok(())
            } else {
                println!("  SIP parse         : response does not look like a valid SIP message");
                println!();
                println!("Probe complete");
                println!("  Overall result    : NON-SIP RESPONSE");
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer returned non-SIP data",
                ))
            }
        }
        Err(e) => {
            println!("  Result            : NO RESPONSE");
            println!("  Error kind        : {:?}", e.kind());
            println!("  Error message     : {}", e);
            println!("  Analysis          : UDP is connectionless; no response usually means the port is filtered, the host is unreachable, or no service is listening.");
            println!();
            println!("Probe complete");
            println!("  Overall result    : UNREACHABLE OR FILTERED");
            Err(e)
        }
    }
}

fn main() {
    let args = match parse_args() {
        Some(a) => a,
        None => {
            usage();
            process::exit(2);
        }
    };

    let result = probe_udp(&args);
    process::exit(if result.is_ok() { 0 } else { 1 });
}
