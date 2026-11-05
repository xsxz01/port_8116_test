use std::env;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use std::time::Duration;

use port_8116_test::{probe_port, ProbeParams, Protocol};

const DEFAULT_TIMEOUT_MS: u64 = 3000;

struct Args {
    target: IpAddr,
    start_port: u16,
    end_port: u16,
    protocol: Protocol,
    timeout: Duration,
}

fn usage() {
    eprintln!("用法:");
    eprintln!("  单端口: port_probe --target IP --port PORT --protocol tcp|udp [--timeout-ms MS]");
    eprintln!("  范围  : port_probe --target IP --start-port START --end-port END --protocol tcp|udp [--timeout-ms MS]");
}

fn parse_args() -> Option<Args> {
    let mut target: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    let mut start_port: Option<u16> = None;
    let mut end_port: Option<u16> = None;
    let mut protocol: Option<String> = None;
    let mut timeout_ms: Option<u64> = None;

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--target" => target = iter.next().and_then(|t| t.parse().ok()),
            "--port" => port = iter.next().and_then(|p| p.parse().ok()),
            "--start-port" => start_port = iter.next().and_then(|p| p.parse().ok()),
            "--end-port" => end_port = iter.next().and_then(|p| p.parse().ok()),
            "--protocol" => protocol = iter.next(),
            "--timeout-ms" => timeout_ms = iter.next().and_then(|t| t.parse().ok()),
            other => {
                eprintln!("未知参数: {}", other);
                return None;
            }
        }
    }

    let target = target?;
    let protocol = protocol
        .as_deref()
        .and_then(|p| Protocol::from_str(p).ok())?;
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));

    let (start_port, end_port) = match (port, start_port, end_port) {
        (Some(p), None, None) => (p, p),
        (None, Some(s), Some(e)) => (s, e),
        _ => {
            eprintln!("请指定 --port（单端口）或 --start-port 与 --end-port（范围）");
            return None;
        }
    };

    if start_port > end_port {
        eprintln!("起始端口不能大于结束端口");
        return None;
    }

    Some(Args {
        target,
        start_port,
        end_port,
        protocol,
        timeout,
    })
}

fn run_probe(params: &ProbeParams) -> bool {
    println!("探测 {} {} {} ...", params.protocol, params.target, params.port);
    let result = probe_port(params);
    println!("  结果: {}", result.summary);
    println!("  耗时: {:?}", result.duration);
    println!("  详情: {}", result.detail);
    println!();
    result.success
}

fn main() {
    let args = match parse_args() {
        Some(a) => a,
        None => {
            usage();
            process::exit(2);
        }
    };

    println!("探测配置");
    println!("  目标地址: {}", args.target);
    println!("  协议    : {}", args.protocol);
    println!("  端口范围: {} - {}", args.start_port, args.end_port);
    println!("  超时    : {:?}", args.timeout);
    println!();

    let mut success_count = 0;
    let total = args.end_port - args.start_port + 1;

    for port in args.start_port..=args.end_port {
        let params = ProbeParams {
            target: args.target,
            port,
            protocol: args.protocol,
            timeout: args.timeout,
        };
        if run_probe(&params) {
            success_count += 1;
        }
    }

    println!("探测完成");
    println!("  总计: {} 个端口", total);
    println!("  可达: {} 个", success_count);
    println!("  不可达/无响应: {} 个", total - success_count);

    process::exit(if success_count > 0 { 0 } else { 1 });
}
