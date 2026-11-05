use std::env;
use std::error::Error;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const TARGET: Ipv4Addr = Ipv4Addr::new(10, 7, 2, 19);
const FILTER: &str = "host 10.7.2.19 and (port 5060 or port 5061)";
const PROBE_TIMEOUT_MS: u64 = 3000;
const CAPTURE_POST_DELAY_MS: u64 = 500;
const CAPTURE_START_DELAY_MS: u64 = 300;

#[derive(Clone, Default)]
struct ComboStats {
    total_packets: usize,
    outbound_packets: usize,
    inbound_packets: usize,
    sip_requests: usize,
    sip_responses: usize,
    payload_bytes: usize,
}

struct PacketInfo {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: &'static str,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct CapturedPacket {
    #[allow(dead_code)]
    timestamp: Instant,
    data: Vec<u8>,
    #[allow(dead_code)]
    cap_len: u32,
    #[allow(dead_code)]
    orig_len: u32,
}

fn is_npcap_installed() -> bool {
    let candidates = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
        r"C:\Windows\SysWOW64\wpcap.dll",
    ];
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

fn probe_exe_path() -> Option<PathBuf> {
    let mut path = env::current_exe().ok()?;
    path.pop();
    path.push("sip_port_probe.exe");
    Some(path)
}

fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    if data.len() < 14 {
        return None;
    }

    let mut offset = 14_usize;
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // Handle a single 802.1Q VLAN tag.
    if ethertype == 0x8100 {
        if data.len() < offset + 4 {
            return None;
        }
        offset += 4;
        let inner = u16::from_be_bytes([data[offset - 2], data[offset - 1]]);
        if inner != 0x0800 {
            return None;
        }
    } else if ethertype != 0x0800 {
        return None;
    }

    // IPv4 header
    if data.len() < offset + 20 {
        return None;
    }
    let version_ihl = data[offset];
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0F) as usize * 4;
    if version != 4 || data.len() < offset + ihl {
        return None;
    }
    let protocol = data[offset + 9];
    let src_ip = Ipv4Addr::new(
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    );
    let dst_ip = Ipv4Addr::new(
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    );
    offset += ihl;

    match protocol {
        6 => {
            // TCP
            if data.len() < offset + 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let data_offset = (data[offset + 12] >> 4) as usize * 4;
            if data.len() < offset + data_offset {
                return None;
            }
            let payload = data[offset + data_offset..].to_vec();
            Some(PacketInfo {
                src_ip,
                dst_ip,
                protocol: "TCP",
                src_port,
                dst_port,
                payload,
            })
        }
        17 => {
            // UDP
            if data.len() < offset + 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let payload = data[offset + 8..].to_vec();
            Some(PacketInfo {
                src_ip,
                dst_ip,
                protocol: "UDP",
                src_port,
                dst_port,
                payload,
            })
        }
        _ => None,
    }
}

fn is_sip_request(payload: &[u8]) -> bool {
    let text = String::from_utf8_lossy(payload);
    let first = text.lines().next().unwrap_or("").trim();
    first.starts_with("OPTIONS ")
        || first.starts_with("INVITE ")
        || first.starts_with("REGISTER ")
        || first.starts_with("ACK ")
        || first.starts_with("BYE ")
        || first.starts_with("CANCEL ")
        || first.starts_with("SUBSCRIBE ")
        || first.starts_with("NOTIFY ")
}

fn is_sip_response(payload: &[u8]) -> bool {
    let text = String::from_utf8_lossy(payload);
    let first = text.lines().next().unwrap_or("").trim();
    first.starts_with("SIP/2.0")
}

fn matches_combo(info: &PacketInfo, protocol: &str, port: u16) -> bool {
    info.protocol.eq_ignore_ascii_case(protocol)
        && ((info.dst_ip == TARGET && info.dst_port == port)
            || (info.src_ip == TARGET && info.src_port == port))
}

fn run_probes<'a>(
    probe_exe: &'a PathBuf,
    combos: &'a [(&'a str, u16)],
    packets: Arc<Mutex<Vec<CapturedPacket>>>,
    stop: Arc<AtomicBool>,
) -> Result<Vec<((&'a str, u16), bool, String)>, Box<dyn Error>> {
    let device = pcap::Device::lookup()?
        .ok_or_else(|| "no capture device found; check that npcap is installed and a network adapter is available")?;

    println!("Capture device    : {}", device.name);
    println!("Capture filter    : {}\n", FILTER);

    let packets_for_thread = Arc::clone(&packets);
    let stop_for_thread = Arc::clone(&stop);
    let capture_thread = thread::spawn(move || -> Result<(), pcap::Error> {
        let mut cap = pcap::Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()?;
        cap.filter(FILTER, true)?;

        while !stop_for_thread.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(pkt) => {
                    packets_for_thread.lock().unwrap().push(CapturedPacket {
                        timestamp: Instant::now(),
                        data: pkt.data.to_vec(),
                        cap_len: pkt.header.caplen,
                        orig_len: pkt.header.len,
                    });
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });

    thread::sleep(Duration::from_millis(CAPTURE_START_DELAY_MS));

    let mut results = Vec::with_capacity(combos.len());
    for &(proto, port) in combos {
        println!("--- Running probe: {} {} ---", proto.to_uppercase(), port);
        let output = Command::new(probe_exe)
            .arg("--protocol")
            .arg(proto)
            .arg("--port")
            .arg(port.to_string())
            .arg("--target")
            .arg(TARGET.to_string())
            .arg("--timeout-ms")
            .arg(PROBE_TIMEOUT_MS.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let success = output.status.success();

        println!(
            "Exit code         : {}",
            output.status.code().map(|c| c.to_string()).unwrap_or_else(|| "<unknown>".to_string())
        );
        println!("Reachable         : {}", if success { "YES" } else { "NO" });
        if !stdout.is_empty() {
            println!("Probe output:\n{}", stdout);
        }
        if !stderr.is_empty() {
            println!("Probe stderr:\n{}", stderr);
        }
        println!();

        results.push(((proto, port), success, stdout));
    }

    thread::sleep(Duration::from_millis(CAPTURE_POST_DELAY_MS));
    stop.store(true, Ordering::Relaxed);
    match capture_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => println!("Capture ended with error: {}\n", e),
        Err(_) => println!("Capture thread panicked\n"),
    }

    Ok(results)
}

fn analyze_capture(
    packets: &[CapturedPacket],
    combos: &[(&str, u16)],
    probe_results: &[((&str, u16), bool, String)],
) {
    let mut stats: std::collections::HashMap<(&str, u16), ComboStats> =
        std::collections::HashMap::new();

    for pkt in packets {
        if let Some(info) = parse_packet(&pkt.data) {
            for &(proto, port) in combos {
                if matches_combo(&info, proto, port) {
                    let entry = stats.entry((proto, port)).or_default();
                    entry.total_packets += 1;
                    entry.payload_bytes += info.payload.len();
                    if info.dst_ip == TARGET && info.dst_port == port {
                        entry.outbound_packets += 1;
                        if is_sip_request(&info.payload) {
                            entry.sip_requests += 1;
                        }
                    } else if info.src_ip == TARGET && info.src_port == port {
                        entry.inbound_packets += 1;
                        if is_sip_response(&info.payload) {
                            entry.sip_responses += 1;
                        }
                    }
                }
            }
        }
    }

    println!("=== Per-combo capture analysis ===");
    for &(proto, port) in combos {
        let s = stats.get(&(proto, port)).cloned().unwrap_or_default();
        let (_, success, _) = probe_results
            .iter()
            .find(|((p, po), _, _)| *p == proto && *po == port)
            .expect("probe result must exist for every combo");

        println!("\n{} {}", proto.to_uppercase(), port);
        println!("  Captured packets       : {}", s.total_packets);
        println!("  Outbound packets       : {}", s.outbound_packets);
        println!("  Inbound packets        : {}", s.inbound_packets);
        println!("  SIP requests seen      : {}", s.sip_requests);
        println!("  SIP responses seen     : {}", s.sip_responses);
        println!(
            "  Probe reported reachable : {}",
            if *success { "YES" } else { "NO" }
        );

        let conclusion = if *success && s.sip_responses > 0 {
            "Network path is open and a SIP response was received from the target."
        } else if *success && s.total_packets > 0 {
            "Network path is open, but no SIP response was identified in the capture; the service may be non-SIP or the parser missed the payload."
        } else if !*success && s.inbound_packets > 0 {
            "Traffic returned from the target, yet the probe did not succeed; the port may be open but the service did not accept the SIP request."
        } else if !*success && s.outbound_packets > 0 {
            "Packets left this host but no reply was captured; the traffic is likely filtered, dropped, or the target service is not listening."
        } else {
            "No relevant traffic was captured; verify routing, local firewall, npcap device selection, or physical connectivity."
        };
        println!("  Conclusion             : {}", conclusion);
    }
}

fn print_summary(results: &[((&str, u16), bool, String)]) {
    println!("\n=== Summary ===");
    for &((proto, port), success, _) in results {
        println!(
            "  {} {:5} -> {}",
            proto.to_uppercase(),
            port,
            if success {
                "REACHABLE"
            } else {
                "UNREACHABLE / FILTERED"
            }
        );
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== SIP port probe with npcap ===\n");

    if !is_npcap_installed() {
        println!("Npcap status      : NOT INSTALLED");
        println!("Npcap is required for packet capture.");
        println!("Please download and install Npcap from https://nmap.org/npcap/");
        println!("After installation, run this program again.");
        process::exit(1);
    }
    println!("Npcap status      : INSTALLED");

    let probe_exe = probe_exe_path().ok_or("failed to determine probe executable path")?;
    if !probe_exe.exists() {
        println!("Probe executable not found: {}", probe_exe.display());
        println!("Make sure sip_port_probe.exe is in the same directory as this program.");
        process::exit(1);
    }
    println!("Probe executable  : {}\n", probe_exe.display());

    let combos: Vec<(&str, u16)> = vec![("tcp", 5060), ("tcp", 5061), ("udp", 5060), ("udp", 5061)];

    let stop = Arc::new(AtomicBool::new(false));
    let packets = Arc::new(Mutex::new(Vec::new()));

    let probe_results = run_probes(&probe_exe, &combos, Arc::clone(&packets), Arc::clone(&stop))?;

    let all_packets = packets.lock().unwrap().clone();
    println!("Captured {} packets matching the filter.\n", all_packets.len());

    analyze_capture(&all_packets, &combos, &probe_results);
    print_summary(&probe_results);

    Ok(())
}
