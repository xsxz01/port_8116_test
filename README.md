# Port 8116 one-shot listeners

This project builds standalone Windows executables:

- `tcp_8116_listener.exe` listens on TCP `0.0.0.0:8116`, reports the first
  accepted connection, and exits.
- `udp_8116_listener.exe` listens on UDP `0.0.0.0:8116`, reports the first
  received datagram, and exits.

UDP is connectionless, so its first received datagram is treated as the first
connection event.

## Generic port probe

`port_probe.exe` checks TCP or UDP connectivity to an arbitrary host and port.
It prints a step-by-step report with timing and analysis.

```powershell
port_probe.exe --target 10.7.2.140 --port 8116 --protocol tcp
port_probe.exe --target 10.7.2.140 --port 8116 --protocol udp
port_probe.exe --target 10.7.2.140 --port 8116 --protocol tcp --timeout-ms 5000

# 端口范围检测
port_probe.exe --target 10.7.2.140 --start-port 8000 --end-port 9000 --protocol tcp
```

### GUI version

`port_probe_gui.exe` provides a graphical interface based on GPUI. It supports
range scanning and displays results in a scrollable list.

```powershell
port_probe_gui.exe
```

## SIP port probes

Two additional tools are provided for diagnosing connectivity to
`10.7.2.19:5060` and `10.7.2.19:5061`:

- `sip_port_probe.exe` tests a single protocol/port combination. It opens a
  TCP connection (or a connected UDP socket), sends a SIP `REGISTER` request,
  and reports any response together with a step-by-step analysis. UDP is used
  when `--protocol` is omitted.

  ```powershell
  sip_port_probe.exe --protocol tcp --port 5060
  sip_port_probe.exe --protocol udp --port 5061
  sip_port_probe.exe --protocol tcp --port 5060 --target 10.7.2.19 --timeout-ms 3000
  ```

- `sip_port_probe_npcap.exe` runs the four combinations
  (TCP/UDP × 5060/5061) by calling `sip_port_probe.exe`, captures the
  resulting traffic with npcap, and prints a combined connectivity and packet
  analysis report.

  ```powershell
  sip_port_probe_npcap.exe
  ```

  If npcap is not installed, the program informs the user and exits cleanly.

## Building

Build all executables with a statically linked C runtime:

```powershell
cargo build --release
```

The resulting single-file executables are written to `target\release`.

### npcap requirements

`sip_port_probe_npcap.exe` links against npcap via the `pcap` crate.

- The **Npcap SDK** is bundled in this repository under `npcap-sdk-1.16\Lib\x64`.
  `.cargo\config.toml` automatically sets `LIBPCAP_LIBDIR`, so no extra
  environment configuration is needed to build.
- The **Npcap runtime** must still be installed on any machine that runs
  `sip_port_probe_npcap.exe`. Because `wpcap.dll` is imported at load time,
  a missing runtime makes the executable exit with `0xC0000135`
  (`STATUS_DLL_NOT_FOUND`) before `main` runs, so install Npcap first rather
  than relying on the in-program hint.

The other executables do not require npcap.

## Documentation

- [用 Rust 写一套端口与 SIP 连通性诊断工具链](docs/rust-port-probe-toolchain.md)
  — project walkthrough, CLI reference, GPUI notes, and npcap packet-capture
  analysis (Chinese).
