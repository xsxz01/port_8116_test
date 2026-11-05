use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::process;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const UDP_PROBE_PAYLOAD: &[u8] = b"port-probe";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            _ => Err(format!("未知协议: {}", s)),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbeParams {
    pub target: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub target: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub success: bool,
    pub duration: Duration,
    pub summary: String,
    pub detail: String,
}

impl ProbeResult {
    pub fn short_summary(&self) -> String {
        if self.success {
            format!("{} {} {} 可达（{:?}）", self.protocol, self.target, self.port, self.duration)
        } else {
            format!("{} {} {} 不可达", self.protocol, self.target, self.port)
        }
    }
}

pub fn analyze_tcp_error(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::ConnectionRefused => "目标主机可达，但指定端口没有进程在监听。",
        io::ErrorKind::ConnectionReset => "连接被对端重置，可能是服务拒绝连接。",
        io::ErrorKind::TimedOut => "连接超时，可能是防火墙丢弃、路由不可达或目标无响应。",
        io::ErrorKind::HostUnreachable => "目标主机在 IP 层不可达。",
        io::ErrorKind::NetworkUnreachable => "本机没有到达目标网络的路由。",
        _ => "详见错误信息。",
    }
}

pub fn probe_tcp(params: &ProbeParams) -> ProbeResult {
    let target = SocketAddr::new(params.target, params.port);
    let start = Instant::now();

    match TcpStream::connect_timeout(&target, params.timeout) {
        Ok(stream) => {
            let local = stream.local_addr().ok();
            let duration = start.elapsed();
            ProbeResult {
                target: params.target,
                port: params.port,
                protocol: params.protocol,
                success: true,
                duration,
                summary: "可达".to_string(),
                detail: format!(
                    "TCP 连接成功，本地地址: {}",
                    local.map(|a| a.to_string()).unwrap_or_else(|| "未知".to_string())
                ),
            }
        }
        Err(e) => ProbeResult {
            target: params.target,
            port: params.port,
            protocol: params.protocol,
            success: false,
            duration: start.elapsed(),
            summary: "不可达".to_string(),
            detail: format!("{:?}: {}。{}", e.kind(), e, analyze_tcp_error(e.kind())),
        },
    }
}

pub fn probe_udp(params: &ProbeParams) -> ProbeResult {
    let target = SocketAddr::new(params.target, params.port);
    let start = Instant::now();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult {
                target: params.target,
                port: params.port,
                protocol: params.protocol,
                success: false,
                duration: start.elapsed(),
                summary: "绑定失败".to_string(),
                detail: format!("无法绑定 UDP socket: {}", e),
            }
        }
    };

    if let Err(e) = socket.set_read_timeout(Some(params.timeout)) {
        return ProbeResult {
            target: params.target,
            port: params.port,
            protocol: params.protocol,
            success: false,
            duration: start.elapsed(),
            summary: "配置失败".to_string(),
            detail: format!("设置读取超时失败: {}", e),
        };
    }

    match socket.send_to(UDP_PROBE_PAYLOAD, target) {
        Ok(_) => {}
        Err(e) => {
            return ProbeResult {
                target: params.target,
                port: params.port,
                protocol: params.protocol,
                success: false,
                duration: start.elapsed(),
                summary: "发送失败".to_string(),
                detail: format!("UDP 发送失败: {}", e),
            }
        }
    }

    let mut buffer = [0_u8; 1024];
    match socket.recv_from(&mut buffer) {
        Ok((n, peer)) => ProbeResult {
            target: params.target,
            port: params.port,
            protocol: params.protocol,
            success: true,
            duration: start.elapsed(),
            summary: "可达（收到响应）".to_string(),
            detail: format!("收到来自 {} 的 {} 字节响应", peer, n),
        },
        Err(e) => ProbeResult {
            target: params.target,
            port: params.port,
            protocol: params.protocol,
            success: false,
            duration: start.elapsed(),
            summary: "无响应".to_string(),
            detail: format!(
                "UDP 无响应: {}。UDP 是无连接协议；无响应通常表示端口被过滤、主机不可达或服务未监听。",
                e
            ),
        },
    }
}

pub fn probe_port(params: &ProbeParams) -> ProbeResult {
    match params.protocol {
        Protocol::Tcp => probe_tcp(params),
        Protocol::Udp => probe_udp(params),
    }
}

const SIP_RECV_BUFFER_SIZE: usize = 8192;
const SIP_PREVIEW_SIZE: usize = 256;

fn sip_random_token(len: usize) -> String {
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
    let branch = format!("z9hG4bK{}", sip_random_token(8));
    let tag = sip_random_token(8);
    let call_id = format!("{}@{}", sip_random_token(16), local.ip());
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

fn sip_text_preview(data: &[u8]) -> String {
    let preview: String = data
        .iter()
        .take(SIP_PREVIEW_SIZE)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    let mut out = preview.replace('\r', "\\r").replace('\n', "\\n");
    if data.len() > SIP_PREVIEW_SIZE {
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

pub fn probe_sip_register(target: IpAddr, port: u16, timeout: Duration) -> ProbeResult {
    let target_addr = SocketAddr::new(target, port);
    let start = Instant::now();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult {
                target,
                port,
                protocol: Protocol::Udp,
                success: false,
                duration: start.elapsed(),
                summary: "绑定失败".to_string(),
                detail: format!("无法绑定 UDP socket: {}", e),
            }
        }
    };

    if let Err(e) = socket.connect(target_addr) {
        return ProbeResult {
            target,
            port,
            protocol: Protocol::Udp,
            success: false,
            duration: start.elapsed(),
            summary: "连接失败".to_string(),
            detail: format!("UDP connect 失败: {}", e),
        };
    }

    let local = match socket.local_addr() {
        Ok(a) => a,
        Err(e) => {
            return ProbeResult {
                target,
                port,
                protocol: Protocol::Udp,
                success: false,
                duration: start.elapsed(),
                summary: "本地地址获取失败".to_string(),
                detail: format!("无法获取本地地址: {}", e),
            }
        }
    };

    if let Err(e) = socket.set_read_timeout(Some(timeout)) {
        return ProbeResult {
            target,
            port,
            protocol: Protocol::Udp,
            success: false,
            duration: start.elapsed(),
            summary: "配置失败".to_string(),
            detail: format!("设置读取超时失败: {}", e),
        };
    }

    let request = build_sip_register(target_addr, local);
    if let Err(e) = socket.send(request.as_bytes()) {
        return ProbeResult {
            target,
            port,
            protocol: Protocol::Udp,
            success: false,
            duration: start.elapsed(),
            summary: "发送失败".to_string(),
            detail: format!("UDP 发送失败: {}", e),
        };
    }

    let mut buffer = vec![0_u8; SIP_RECV_BUFFER_SIZE];
    match socket.recv(&mut buffer) {
        Ok(n) => {
            buffer.truncate(n);
            if let Some(status) = parse_sip_status(&buffer) {
                ProbeResult {
                    target,
                    port,
                    protocol: Protocol::Udp,
                    success: true,
                    duration: start.elapsed(),
                    summary: status,
                    detail: format!(
                        "收到 {} 字节 SIP 响应，预览: {}",
                        n,
                        sip_text_preview(&buffer)
                    ),
                }
            } else {
                ProbeResult {
                    target,
                    port,
                    protocol: Protocol::Udp,
                    success: false,
                    duration: start.elapsed(),
                    summary: "非 SIP 响应".to_string(),
                    detail: format!(
                        "收到 {} 字节非 SIP 数据，预览: {}",
                        n,
                        sip_text_preview(&buffer)
                    ),
                }
            }
        }
        Err(e) => ProbeResult {
            target,
            port,
            protocol: Protocol::Udp,
            success: false,
            duration: start.elapsed(),
            summary: "无响应".to_string(),
            detail: format!(
                "UDP 无响应: {}。UDP 是无连接协议；无响应通常表示端口被过滤、主机不可达或服务未监听。",
                e
            ),
        },
    }
}
