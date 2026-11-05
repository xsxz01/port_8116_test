# 【一起学Rust | 项目实战】用Rust写一套Windows端口与SIP连通性诊断工具链

## 前言

做内网项目的人大概都遇到过这种对话：

> “服务已经起了，你那边连一下 10.7.2.140:8116。”
> “连不上。”
> “我这边是好的啊。”

然后就是漫长的扯皮。Windows 上想验证一个端口通不通，其实并不顺手：`telnet` 默认没装，`Test-NetConnection` 只能测 TCP，UDP 和 SIP 这种“发了不一定有回音”的协议更是没法用一条命令说清楚。至于“到底是防火墙拦了、路由不通、还是对面根本没监听”，普通工具也只会给你一句超时。

这次的项目就是为解决这类问题写的：一套用 Rust 编译出来的单文件小工具，覆盖 TCP/UDP 端口探测、端口段扫描、一次性监听、SIP 信令探测，以及基于 npcap 的抓包取证。写完之后现场排障基本是“拷过去、跑一下、看输出”三步走，不用装运行时，也不用配环境。

项目地址：<https://github.com/xsxz01/port_8116_test>

---

## 一、先想清楚要造哪几把锤子

排障链路其实可以拆成三个问题，对应三类工具：

| 问题 | 工具 | 说明 |
| --- | --- | --- |
| 对面端口通不通？ | `port_probe` | 单端口 / 端口段，TCP 或 UDP，带错误归因 |
| 我这边到底能不能被连上？ | `tcp_8116_listener` / `udp_8116_listener` | 监听 `0.0.0.0:8116`，收到第一个连接/数据报就打印并退出 |
| 端口通了，但业务不通？ | `sip_port_probe` / `sip_port_probe_npcap` | 发 SIP 请求看有没有响应，再用 npcap 抓包核对线上证据 |
| 不想敲命令行？ | `port_probe_gui` | GPUI 写的图形界面，支持端口段扫描和国标 SIP 端口测试 |

一个仓库、一个 `Cargo.toml`、六个 bin，公共逻辑全部沉到 `src/lib.rs`。这样 CLI 和 GUI 用的是同一套探测代码，不会出现“命令行能通、界面说不通”的尴尬。

---

## 二、工程骨架：单包多 bin

`Cargo.toml` 里没有 workspace，就是一个 package 挂多个 `[[bin]]`：

```toml
[package]
name = "port_8116_test"
version = "0.1.0"
edition = "2024"

[dependencies]
pcap = "2.4"
gpui = "0.2"
gpui-component = "0.5"

[[bin]]
name = "port_probe"
path = "src/bin/port_probe.rs"

[[bin]]
name = "sip_port_probe"
path = "src/bin/sip_port_probe.rs"

# 其余 bin 省略
```

目录结构也很直白：

```text
port_8116_test/
├── Cargo.toml
├── .cargo/config.toml          # 指向 npcap SDK 的 Lib 目录
├── src/
│   ├── lib.rs                  # 探测核心：TCP/UDP/SIP
│   └── bin/
│       ├── tcp_8116_listener.rs
│       ├── udp_8116_listener.rs
│       ├── port_probe.rs
│       ├── port_probe_gui.rs
│       ├── sip_port_probe.rs
│       └── sip_port_probe_npcap.rs
└── README.md
```

真正让这些工具“拷过去就能用”的，是 release profile：

```toml
[profile.release]
codegen-units = 1
lto = true
opt-level = "z"
panic = "abort"
strip = "symbols"
```

| 配置 | 作用 |
| --- | --- |
| `codegen-units = 1` | 牺牲编译时间换更好的跨模块优化 |
| `lto = true` | 打开链接时优化，顺手删掉用不到的死代码 |
| `opt-level = "z"` | 以体积为优先，工具类程序不需要极致算力 |
| `panic = "abort"` | panic 直接终止，省掉 unwind 表和展开逻辑 |
| `strip = "symbols"` | 去掉符号表，exe 更小，也不容易被逆出内部结构 |

再加上 Windows 下默认静态链接 CRT，最终产物就是 `target\release` 里的几个独立 exe，发给现场同事不需要附带任何 DLL。

---

## 三、把“通不通”变成结构化数据

很多脚本写探测，喜欢直接 `println!` 一把梭，结果是输出给人看还行，想二次加工就没法用了。这个项目的第一步，是先定义清楚输入和输出：

```rust
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
```

有了 `ProbeResult`，CLI 可以逐行打印，GUI 可以直接塞进 `Vec` 渲染，后面做端口段汇总也只是 `iter().filter(|r| r.success).count()` 的事。协议本身用一个枚举收口：

```rust
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
```

调度层只有一个 match，以后要加 ICMP 或者 QUIC，改动面也很小：

```rust
pub fn probe_port(params: &ProbeParams) -> ProbeResult {
    match params.protocol {
        Protocol::Tcp => probe_tcp(params),
        Protocol::Udp => probe_udp(params),
    }
}
```

### TCP 的错误不能只报“超时”

`TcpStream::connect_timeout` 本身会返回 `io::ErrorKind`，但把 `TimedOut` 直接甩给用户等于没说。所以我加了一层归因，把错误类型翻译成排障时真正有用的判断：

```rust
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
```

对应到现场就是三种完全不同的处理方式：

| 错误类型 | 大概率原因 | 下一步找谁 |
| --- | --- | --- |
| `ConnectionRefused` | 主机通、端口没服务 | 找应用侧确认进程和监听地址 |
| `TimedOut` | 防火墙丢包 / 路由不通 | 找网络侧查策略和路由 |
| `HostUnreachable` | IP 层就不通 | 先解决链路，别在端口上耗 |

这里还有一个容易被忽略的细节：`connect_timeout` 接收的是 `SocketAddr`，也就是**必须先解析成 IP**。所以 CLI 的 `--target` 类型是 `IpAddr` 而不是 `&str`，工具不替你处理 DNS。现场排障时这反而是好事——域名解析失败和端口不通是两码事，不该混在一个超时里。

---

## 四、TCP 和 UDP 的“通”根本不是一回事

这是整个项目里最值得写下来的一点。

TCP 的判断很干脆：`connect` 返回 `Ok`，说明三次握手完成，对端确实有东西在 listen（不考虑中间设备做代理的情况）。所以代码里拿到连接后顺手把本地地址也打出来：

```rust
match TcpStream::connect_timeout(&target, params.timeout) {
    Ok(stream) => {
        let local = stream.local_addr().ok();
        ProbeResult {
            success: true,
            summary: "可达".to_string(),
            detail: format!(
                "TCP 连接成功，本地地址: {}",
                local.map(|a| a.to_string()).unwrap_or_else(|| "未知".to_string())
            ),
            ..
        }
    }
    Err(e) => ProbeResult { /* 走上面的错误归因 */ }
}
```

UDP 就麻烦多了。`send_to` 成功只代表**本机协议栈把包发出去了**，对端收没收到、端口开没开，它一概不知。所以 UDP 探测必须发一个可识别的载荷，然后等回包：

```rust
const UDP_PROBE_PAYLOAD: &[u8] = b"port-probe";

socket.send_to(UDP_PROBE_PAYLOAD, target)?;
socket.set_read_timeout(Some(params.timeout))?;

let mut buffer = [0_u8; 1024];
match socket.recv_from(&mut buffer) {
    Ok((n, peer)) => ProbeResult {
        success: true,
        summary: "可达（收到响应）".to_string(),
        detail: format!("收到来自 {} 的 {} 字节响应", peer, n),
        ..
    },
    Err(e) => ProbeResult {
        success: false,
        summary: "无响应".to_string(),
        detail: format!(
            "UDP 无响应: {}。UDP 是无连接协议；无响应通常表示端口被过滤、主机不可达或服务未监听。",
            e
        ),
        ..
    },
}
```

注意这里 `success = false` 的语义是“**没拿到证据**”，而不是“端口关闭”。UDP 无响应至少有三种可能：端口被防火墙静默丢弃、主机不可达、服务在监听但压根不回这个载荷。所以输出里我特意把这句话写全，避免现场拿着一张“UDP 不通”的截图去下结论。

也正因为这个差异，后面的 SIP 探测才要分两层：先确认端口层面有没有反应，再确认协议层面能不能拿到合法响应。

---

## 五、反向验证：只收一次的监听器

排查“连不上”时，经常需要回答另一个方向的问题：**我这边到底有没有收到包？**

`tcp_8116_listener` 的逻辑就三行核心代码：

```rust
let listener = TcpListener::bind("0.0.0.0:8116")?;
let (stream, peer_address) = listener.accept()?;
drop(listener);
```

绑定 `0.0.0.0` 而不是 `127.0.0.1`，是为了让局域网内的其他机器也能连进来。收到第一个连接后立刻 `drop(listener)`，然后把本地地址、对端地址、地址族、Unix 毫秒时间戳全部打出来：

```text
TCP listener ready
  Listening address : 0.0.0.0:8116
  Process ID        : 23184
  Waiting for one connection...
TCP connection accepted
  Protocol          : TCP
  Address family    : IPv4
  Local address     : 10.7.2.140
  Local port        : 8116
  Remote address    : 10.7.2.19
  Remote port       : 51234
  Unix time (ms)    : 1762300000000
  Listener state    : stopped
```

UDP 版本同理，只是把 `accept` 换成 `recv_from`，并且用 65535 字节的缓冲区接住完整数据报，再取前 32 字节做十六进制预览：

```rust
let mut buffer = vec![0_u8; MAX_DATAGRAM_SIZE];
let (received_length, peer_address) = socket.recv_from(&mut buffer)?;
```

十六进制预览这个设计在现场很实用：有些设备发过来的根本不是你以为的协议，看到 `16 03 01 ...` 就知道是 TLS 而不是明文，省得在应用层瞎猜。

为什么只收一次就退出？因为这类工具的使用场景是“排查动作”，不是“常驻服务”。抓完即走，既不用管进程回收，也不会因为长期占用端口被杀软或者防火墙策略盯上。

---

## 六、命令行：手写参数解析，但把退出码做对

`port_probe` 没有引入 clap。一方面是依赖越少、产物越小，另一方面这个工具的参数就那么几个，手写反而更可控：

```rust
"--target" => target = iter.next().and_then(|t| t.parse().ok()),
"--port" => port = iter.next().and_then(|p| p.parse().ok()),
"--start-port" => start_port = iter.next().and_then(|p| p.parse().ok()),
"--end-port" => end_port = iter.next().and_then(|p| p.parse().ok()),
"--protocol" => protocol = iter.next(),
"--timeout-ms" => timeout_ms = iter.next().and_then(|t| t.parse().ok()),
```

单端口和端口段是互斥的，靠模式匹配直接约束住，不给你写出“既传了 `--port` 又传了 `--start-port`”这种模糊状态：

```rust
let (start_port, end_port) = match (port, start_port, end_port) {
    (Some(p), None, None) => (p, p),
    (None, Some(s), Some(e)) => (s, e),
    _ => {
        eprintln!("请指定 --port（单端口）或 --start-port 与 --end-port（范围）");
        return None;
    }
};
```

用法：

```powershell
port_probe.exe --target 10.7.2.140 --port 8116 --protocol tcp
port_probe.exe --target 10.7.2.140 --port 8116 --protocol udp
port_probe.exe --target 10.7.2.140 --start-port 8000 --end-port 9000 --protocol tcp --timeout-ms 5000
```

输出长这样：

```text
探测配置
  目标地址: 10.7.2.140
  协议    : TCP
  端口范围: 8116 - 8116
  超时    : 3s

探测 TCP 10.7.2.140 8116 ...
  结果: 可达
  耗时: 12.4ms
  详情: TCP 连接成功，本地地址: 10.7.2.5:51230

探测完成
  总计: 1 个端口
  可达: 1 个
  不可达/无响应: 0 个
```

最后一段的退出码是有意设计的：

| 退出码 | 含义 |
| --- | --- |
| `0` | 至少有一个端口可达 |
| `1` | 全部不可达 / 无响应 |
| `2` | 参数错误 |

这样在 PowerShell 或者 CI 里就能直接判断结果，不用去 grep 中文输出：

```powershell
.\port_probe.exe --target 10.7.2.140 --port 8116 --protocol tcp
if ($LASTEXITCODE -ne 0) { Write-Host "端口不可达" }
```

---

## 七、GPUI：把阻塞探测挪出 UI 线程

GUI 版本用的是 GPUI + gpui-component。选它而不是 Tauri，主要是因为这个工具不需要 WebView，也不想为了一个输入框背一整套前端构建链。

界面上半部分是端口段扫描，下半部分单独放了一个“国标 SIP 端口测试”区块。所有输入都用 `Entity<InputState>` 管理：

```rust
target_input: cx.new(|cx| InputState::new(window, cx).default_value("10.7.2.140")),
start_port_input: cx.new(|cx| InputState::new(window, cx).default_value("8116")),
```

真正需要注意的是**别在 UI 线程里做阻塞 IO**。`TcpStream::connect_timeout` 一卡就是几秒，直接调用的话整个窗口会假死。所以扫描逻辑丢进 `background_executor`，每完成一个端口再回主线程更新状态：

```rust
cx.spawn(move |this: gpui::WeakEntity<Self>, cx: &mut gpui::AsyncApp| {
    let mut cx = cx.clone();
    async move {
        for port in start_port..=end_port {
            let params = ProbeParams { target, port, protocol, timeout };
            let result = cx
                .background_executor()
                .spawn(async move { probe_port(&params) })
                .await;

            this.update(&mut cx, |this, cx| {
                this.results.push(result);
                cx.notify();
            })
            .ok();
        }

        this.update(&mut cx, |this, cx| {
            this.running = false;
            this.status = format!(
                "探测完成：{} 个可达，{} 个不可达/无响应",
                this.results.iter().filter(|r| r.success).count(),
                this.results.iter().filter(|r| !r.success).count()
            ).into();
            cx.notify();
        }).ok();
    }
}).detach();
```

这里有两个小心思：

1. **逐个回填结果**，而不是等整段扫完一次性渲染。扫 8000-9000 这种区间时，用户能实时看到进度，体验差别很大。
2. `cx.notify()` 只在数据变化时调用，避免无谓重绘。

结果列表用固定高度 + `overflow_y_scrollbar()`，每行按“协议 / 地址:端口 / 结论 / 耗时与详情”四列排布，成功绿色、失败红色，一眼扫过去就知道哪些端口是活的。

如果要说不足，目前扫描是**串行 for 循环**，扫一个大端口段的耗时约等于“端口数 × 超时”。真要扫全端口，正确做法是起一个固定大小的并发池（比如 64 个 worker + `futures::stream::buffer_unordered`），这一点留给后续版本。

---

## 八、SIP：端口通了，不代表服务活着

SIP 服务器（GB28181 场景里很常见）通常监听 5060/5061。用 TCP 探测只能证明“有进程在 listen”，但对面是不是真的 SIP 服务、有没有被中间设备改成别的协议，就需要发一条真正的信令。

`sip_port_probe` 选择发 `REGISTER`，报文完全手工拼：

```rust
fn build_sip_register(target: SocketAddr, local: SocketAddr, transport: Transport) -> String {
    let branch = format!("z9hG4bK{}", random_token(8));
    let tag = random_token(8);
    let call_id = format!("{}@{}", random_token(16), local.ip());
    let user = "probe";

    let lines = [
        format!("REGISTER sip:{user}@{target} SIP/2.0"),
        format!("Via: SIP/2.0/{} {local};branch={branch}", transport.name()),
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
```

几个协议细节不能省：

- 行分隔必须是 `\r\n`，结尾还要多一个空行，否则很多 SIP 实现直接丢弃；
- `branch` 必须以 `z9hG4bK` 开头（RFC 3261 的 magic cookie）；
- `Call-ID`、`tag`、`branch` 每次都要变，否则会被当成重传；
- `Content-Length: 0` 对没有 body 的请求是必须的。

随机串没有引入 `rand`，而是用“原子计数器 + 纳秒时间 + 进程 ID”拼一个种子：

```rust
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
```

一次性探测对随机性要求不高，这样既够用又少一个依赖。

收到响应后，只看首行是不是 `SIP/2.0` 开头：

```rust
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
```

**这里有个容易误判的点：收到 `401 Unauthorized` 或者 `403 Forbidden`，说明服务是活的，只是要求鉴权。** 只有“完全没响应”或者“回了一堆不是 SIP 的字节”才说明链路或服务有问题。工具里把这两种情况分开输出：

| 结果 | 含义 |
| --- | --- |
| `REACHABLE (SIP response received)` | 拿到了合法 SIP 状态行，服务在线 |
| `NON-SIP RESPONSE` | 有回包但首行不是 `SIP/2.0`，可能被别的服务占用端口 |
| `UNREACHABLE OR FILTERED` | 超时无响应，结合抓包再判断 |

为了让排障时能看清对面到底回了什么，预览函数会把不可打印字符替换成 `.`，并把换行转义：

```rust
fn text_preview(data: &[u8]) -> String {
    let preview: String = data
        .iter()
        .take(PREVIEW_SIZE)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                b as char
            } else {
                b'.'
            }
        })
        .collect();
    let mut out = preview.replace('\r', "\\r").replace('\n', "\\n");
    if data.len() > PREVIEW_SIZE {
        out.push_str(" ...");
    }
    out
}
```

运行效果（UDP 模式）：

```powershell
sip_port_probe.exe --port 5060 --target 10.7.2.19 --timeout-ms 3000
```

```text
Probe configuration
  Protocol          : UDP
  Target address    : 10.7.2.19
  Target port       : 5060
  Timeout           : 3s

Stage 1: Send SIP REGISTER request
  Local address     : 10.7.2.5:51231
  Request bytes     : 375
  Request preview   : REGISTER sip:probe@10.7.2.19:5060 SIP/2.0\r\nVia: ...

Stage 2: Wait for SIP response
  Result            : RECEIVED
  Response bytes    : 421
  Response preview  : SIP/2.0 401 Unauthorized\r\n...
  SIP status line   : SIP/2.0 401 Unauthorized

Probe complete
  Overall result    : REACHABLE (SIP response received)
```

---

## 九、npcap：让抓包给探测结果作证

单看探测输出，还是会有“到底包发出去没有”的疑问。`sip_port_probe_npcap` 的思路是把四种组合（TCP/UDP × 5060/5061）依次跑一遍，同时开一个抓包线程，最后把**探测结论**和**线上抓到的包**放在一起对照。

先说环境。npcap 要区分两个东西：

| 名称 | 用途 | 本项目处理方式 |
| --- | --- | --- |
| Npcap SDK | 编译期需要 `wpcap.lib` | 把 SDK 解压到 `npcap-sdk-1.16/`，`.cargo/config.toml` 会自动指向它（SDK 本身不随仓库提交） |
| Npcap 运行时 | 运行期需要 `wpcap.dll` | 程序启动时检测常见安装路径，缺失就打印提示并退出 |

```toml
[env]
LIBPCAP_LIBDIR = { value = "npcap-sdk-1.16/Lib/x64", relative = true }
```

这样只要把 SDK 放在约定位置，`cargo build --release` 就不需要额外配环境变量，也不用改系统 PATH。

运行时检测覆盖了 64 位和 32 位两种安装位置：

```rust
fn is_npcap_installed() -> bool {
    let candidates = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
        r"C:\Windows\SysWOW64\wpcap.dll",
    ];
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}
```

抓包线程本身不复杂，关键是把 BPF 过滤器写窄，避免把整块网卡的流量都堆进内存：

```rust
const FILTER: &str = "host 10.7.2.19 and (port 5060 or port 5061)";

let mut cap = pcap::Capture::from_device(device)?
    .promisc(true)
    .snaplen(65535)
    .timeout(100)
    .open()?;
cap.filter(FILTER, true)?;

while !stop.load(Ordering::Relaxed) {
    match cap.next_packet() {
        Ok(pkt) => packets.lock().unwrap().push(...),
        Err(pcap::Error::TimeoutExpired) => continue,
        Err(e) => return Err(e),
    }
}
```

这里用 `AtomicBool` 控制退出，`timeout(100)` 让 `next_packet` 定期返回 `TimeoutExpired`，否则没有流量时线程会一直阻塞，主线程 `join` 不掉。

真正费点功夫的是**手写报文解析**。没有引入 `etherparse` 之类的库，而是按字节偏移自己走一遍：

1. 先看 14 字节以太网头，取 `ethertype`；
2. 如果是 `0x8100`，说明带一层 802.1Q VLAN 标签，偏移再加 4；
3. 只处理 `0x0800`（IPv4），用 `IHL` 算出 IP 头长度；
4. 协议号 `6` 走 TCP，按 `data offset` 算载荷；`17` 走 UDP，固定 8 字节头。

```rust
let version_ihl = data[offset];
let version = version_ihl >> 4;
let ihl = (version_ihl & 0x0F) as usize * 4;
if version != 4 || data.len() < offset + ihl {
    return None;
}
let protocol = data[offset + 9];
```

拿到载荷之后再做协议归类：首行以 `OPTIONS`、`INVITE`、`REGISTER`、`ACK`、`BYE`、`CANCEL`、`SUBSCRIBE`、`NOTIFY` 开头的算请求，以 `SIP/2.0` 开头的算响应。

最后按“方向 + 是否抓到 SIP 报文”给出结论矩阵：

| 探测结果 | 抓包情况 | 结论 |
| --- | --- | --- |
| 成功 | 抓到 SIP 响应 | 链路通，且对端确实是 SIP 服务 |
| 成功 | 只有包，没有 SIP 响应 | 链路通，但服务可能不是 SIP，或解析没命中载荷 |
| 失败 | 有回程包 | 端口可能开着，但服务不接受这条 SIP 请求 |
| 失败 | 只有去程包 | 包发出去了没回音，大概率被过滤 / 丢弃 |
| 失败 | 一个包都没有 | 查路由、本机防火墙、抓包网卡选择 |

这套组合拳的价值在于：**探测结果负责给结论，抓包负责给证据。** 再遇到“我这边明明是好的”，直接把每个方向的包数和 SIP 请求/响应计数甩过去，比争论有用得多。

---

## 十、几个踩过的坑

**1. UDP 的“无响应”不等于“端口关闭”**

前面已经说过，但值得再强调一次。UDP 没有握手，防火墙静默丢包和端口未监听在探测端看起来一模一样。所以工具里统一输出“无响应”，而不是“关闭”。

**2. 端口通 ≠ 服务可用**

SIP 场景里 `401` 也是好消息。判断服务是否存活，要看有没有合法协议响应，而不是看端口能不能连上。

**3. npcap 的 SDK 和运行时是两回事**

编译期找不到 `wpcap.lib` 是 SDK 没配好；运行期报错是没装 npcap 驱动。这两个错误信息很像，但解决方式完全不同，所以程序启动时先做一次显式检测，给出明确提示。

**4. Windows 上重定向到 `NUL` 会留下垃圾文件**

调试编译命令时如果写成 `rustc ... > nul`，某些情况下会在当前目录生成 `nul.pdb`、`nul.*.rcgu.o` 这类文件。它们不是源码，提交前一定要清掉。本项目已经在 `.gitignore` 里加了 `*.o`、`*.pdb`、`*.rcgu.*` 和 `/nul*`。

**5. 串行扫描的耗时是乘法**

`--start-port 1 --end-port 65535 --timeout-ms 3000` 在最坏情况下要跑很久。小范围排障够用，全端口扫描要么调小超时，要么上并发。

---

## 十一、构建与使用

```powershell
cargo build --release
```

产物都在 `target\release`：

| 文件 | 用途 |
| --- | --- |
| `tcp_8116_listener.exe` | TCP 8116 一次性监听 |
| `udp_8116_listener.exe` | UDP 8116 一次性监听 |
| `port_probe.exe` | 命令行端口探测（单端口 / 端口段） |
| `port_probe_gui.exe` | 图形界面版 |
| `sip_port_probe.exe` | SIP 单端口探测 |
| `sip_port_probe_npcap.exe` | 四组合探测 + npcap 抓包分析 |

现场使用建议按这个顺序：

1. 先在**服务端**跑 `tcp_8116_listener.exe`，确认端口确实被监听；
2. 在**客户端**跑 `port_probe.exe`，看是拒绝、超时还是主机不可达；
3. 如果是 SIP 场景，再跑 `sip_port_probe.exe`，看能不能拿到 `SIP/2.0` 响应；
4. 两边结论对不上，再上 `sip_port_probe_npcap.exe`，用抓包把去程/回程摆出来。

---

## 总结

这套工具本身不复杂，核心代码量不大，但把几件容易含糊的事情做扎实了：

- 用 `ProbeParams` / `ProbeResult` 把“通不通”变成结构化数据，CLI 和 GUI 共用一套逻辑；
- 明确区分 TCP 和 UDP 的“可达”语义，不把 UDP 的无响应误报成端口关闭；
- 把 `io::ErrorKind` 翻译成现场能直接执行的判断，而不是甩一句超时；
- 用一次性监听器验证反方向连通性，排除“本机根本没收到包”的可能；
- SIP 探测不满足于端口层面，真的构造信令报文并解析状态行；
- 用 npcap 抓包给探测结论补上证据链。

Rust 在这里的优势也很直接：`std::net` 足够用，编译出来是单文件 exe，静态链接 CRT，拷到没有装任何运行时的 Windows 机器上照样能跑；需要抓包时再通过 `pcap` crate 接上 npcap，成本可控。

如果你也经常在“通不通”这件事上和人扯皮，不妨把这套工具拿去改一改，把默认地址换成自己现场的那几个 IP，剩下的逻辑基本可以原样复用。
