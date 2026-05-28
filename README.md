# Ghost Proxifier

进程级透明代理工具。通过 DLL 注入 Hook Winsock API，将目标进程的所有网络流量透明转发到 **HTTP** 代理，无需修改路由表、无需指定路由规则。

## 项目背景

日常开发中，经常需要同时使用**科学上网代理**和**公司 VPN** 访问不同的网络资源。比如：

- 使用 **Clash Meta** 的 TUN 模式跑 Antigravity 等 AI 编程工具
- 使用公司 VPN 访问内网资源、提交代码

两个 VPN 同时运行时，**路由表经常冲突** — 必须手动在 Clash Meta 里配置路由规则排除公司内网的 IP 段。这样做不仅繁琐，而且不稳定，偶尔公司 VPN 的连接还会莫名断开。

Ghost Proxifier 换了一个思路：**不用 TUN，不动路由表**。只需要把 Clash Meta 开一个 HTTP 入站端口，Ghost Proxifier 针对需要走代理的进程单独注入，其他进程和公司 VPN 完全不受影响。

## 为什么需要 Ghost Proxifier

现有的代理方案各有痛点：

- **系统代理 / PAC** — 依赖应用主动读取代理设置，很多程序不遵守，流量直接泄露
- **VPN / TUN 全局代理** — TUN 网卡内核态与用户态频繁切换，处理慢且连接容易断；多个 VPN 同时使用时路由表冲突，流量走向不可控

Ghost Proxifier 直接 Hook 目标进程的网络函数，在 **Winsock API 层** 拦截所有连接，做到：

- **对应用完全透明** — 无需应用支持代理，任何使用 Winsock 的程序都能代理
- **基于 HTTP 代理** — 兼容主流代理软件（V2Ray、Clash、NekoBox 等均支持 HTTP 入站）
- **进程粒度控制** — 只代理指定进程，不影响系统其他流量，与公司 VPN 和平共存
- **自建 DNS 解析** — 防止 DNS 泄露和 DNS 污染，确保域名解析的纯净性

## 整体架构

```
                          Ghost Proxifier 架构
┌─────────────────────────────────────────────────────────────┐
│                      目标进程 (e.g. Chrome)                  │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ DNS 请求     │  │ TCP 连接      │  │ 数据发送           │  │
│  │ getaddrinfo  │  │ connect()    │  │ send() / WSASend() │  │
│  │ GetAddrInfoW │  │ ConnectEx()  │  │                    │  │
│  │ sendto(53)   │  │ WSAConnect() │  │                    │  │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘  │
│         │ HOOK             │ HOOK               │ HOOK        │
├─────────┼─────────────────┼─────────────────────┼────────────┤
│         ▼                 ▼                     ▼            │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ Local DNS   │  │ 重定向到代理  │  │ Lazy Handshake     │  │
│  │ Proxy       │  │ 保存目标信息  │  │                    │  │
│  │             │  │ 到 Pending   │  │ 1. 检查 PendingMap │  │
│  │ UDP → TCP   │  │ Map          │  │ 2. HTTP CONNECT    │  │
│  │ 转发到      │  │              │  │ 3. 发送原始数据    │  │
│  │ 8.8.8.8:53  │  │ 非阻塞返回   │  │                    │  │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘  │
│         │                 │                     │            │
│         │    ghost_core.dll (注入到目标进程)      │            │
└─────────┼─────────────────┼─────────────────────┼────────────┘
          │                 │                     │
          ▼                 ▼                     ▼
   ┌─────────────────────────────────────────────────────┐
   │              上游 HTTP CONNECT 代理                  │
   │          (V2Ray / Clash / NekoBox / ...)             │
   │                 127.0.0.1:2080                       │
   │                                                     │
   │  ┌──────────┐  ┌────────────────────────────────┐   │
   │  │ DNS 查询  │  │ CONNECT www.google.com:443     │   │
   │  │ TCP 53   │  │                                │   │
   │  │ → 8.8.8.8│  │ → 建立隧道 → 转发加密流量      │   │
   │  └──────────┘  └────────────────────────────────┘   │
   └─────────────────────────────────────────────────────┘
```

## 核心机制

### 1. HTTP 代理协议

Ghost Proxifier 使用 **HTTP CONNECT** 方法与上游代理通信。这是一个广泛支持的标准隧道协议：

```
# 反查到域名时（优先）
客户端 → 代理:  CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n

# 反查不到域名时（fallback）
客户端 → 代理:  CONNECT 142.251.45.10:443 HTTP/1.1\r\nHost: 142.251.45.10:443\r\n\r\n

代理 → 客户端:  HTTP/1.1 200 Connection Established\r\n\r\n
                （此后代理变为透明隧道，双向转发原始数据）
```

在 Hook 场景下，`connect()` 拿到的是 **IP 地址**而非域名。Ghost Proxifier 通过 DNS 解析时建立的 `IP → 域名` 映射表进行反查，**优先使用域名**发送 CONNECT 请求，让上游代理能基于域名做精确分流。

当反查不到域名时（如注入前已缓存的 DNS），则回退为使用 IP 发送 CONNECT，此时上游代理只能依赖 **GeoIP 规则** 判断流量走向。如果 DNS 被污染返回了错误的 IP，GeoIP 判定也会跟着出错（例如国内域名被污染为海外 IP，导致不必要地走代理）。这正是 **Local DNS 防污染**至关重要的原因 — 确保拿到真实 IP，无论走域名还是 GeoIP 分流都能得到正确结果。

### 2. 延迟握手（Lazy Handshake）

传统做法在 `connect()` 时同步完成代理连接 + HTTP CONNECT 握手，会阻塞应用的 IO 线程。Chrome 等现代浏览器使用非阻塞 IO，被阻塞后会认为进程卡死并重启。

Ghost Proxifier 的解决方案：

| 阶段 | 操作 | 阻塞？ |
|------|------|--------|
| `connect()` | 重定向到代理地址，保存目标信息到 PendingMap | ❌ 非阻塞 |
| 等待连接 | 应用事件循环正常运行 | ❌ |
| `send()` 首次调用 | 从 PendingMap 取出目标信息，完成 HTTP CONNECT | ✅ 短暂阻塞（< 5ms） |
| 后续 `send()` | 直接转发 | ❌ |

### 3. 自建 Local DNS

**为什么不用系统 DNS：**
- **DNS 泄露** — 系统 DNS 直接发给 ISP，暴露访问意图
- **DNS 污染** — 部分地区 ISP 返回虚假 IP（如 GFW 投毒），导致无法连接真实服务器

**Ghost Proxifier 的 DNS 方案：**

```
应用 DNS 请求 (UDP)
    ↓ Hook 拦截
Local DNS Proxy (127.0.0.1:随机端口)
    ↓ UDP → TCP 转换
通过上游代理建立 CONNECT 隧道到 8.8.8.8:53
    ↓ TCP DNS 查询
Google DNS 返回真实结果
    ↓ 记录 IP→域名 映射（供 connect 时反查）
返回给应用
```

同时记录 `IP → 域名` 映射表，使得 `connect(IP)` 时能反查到域名，让上游代理收到的是 `CONNECT domain:port` 而非纯 IP，确保 GeoIP 分流规则正常工作。

### 4. DoH（DNS-over-HTTPS）阻断

Chrome 等浏览器会尝试使用 DNS-over-HTTPS（DoH），直接通过 HTTPS 查询 DNS，绕过我们的 Local DNS Proxy。

Ghost Proxifier 通过识别已知 DoH 服务器 IP（如 `8.8.8.8:443`、`1.1.1.1:443`）并在 `connect()` 阶段直接返回 `WSAECONNREFUSED`，强制浏览器回退到标准 DNS，确保所有 DNS 查询都走 Local DNS Proxy。

```
Chrome → connect(8.8.8.8:443)  → DoH 请求
                ↓ Hook 识别为 DoH 服务器
            返回 WSAECONNREFUSED
                ↓ Chrome 回退
Chrome → sendto(8.8.8.8:53)   → 标准 DNS → 被 Local DNS Proxy 接管 ✅
```

## 构建

由于项目依赖 MinHook 子模块，克隆时请加上 `--recursive` 参数：

```cmd
git clone --recursive https://github.com/liliBestCoder/ghost-proxifier.git
cd ghost-proxifier
```

**依赖：**
- Windows 10+
- Visual Studio 2022（含 C++ 桌面开发工具）
- CMake 3.15+

```cmd
compile.bat
```

产物输出到 `bin/` 目录：
- `ghost_core.dll` — 注入到目标进程的 Hook DLL
- `ghost-proxifier.exe` — 注入器 & 日志服务器

## 使用

### 基本用法

```cmd
# 注入指定进程（自动补全 .exe）
ghost-proxifier.exe -p chrome -u 127.0.0.1:2080

# 注入指定 PID
ghost-proxifier.exe -p 12345 -u 127.0.0.1:2080

# 持续监控，自动注入新进程
ghost-proxifier.exe -p chrome -u 127.0.0.1:2080 --watch

# 指定上游代理
ghost-proxifier.exe -p chrome -u 127.0.0.1:2080

# 查看已注入的进程
ghost-proxifier.exe -s

# 仅启动日志服务器
ghost-proxifier.exe -l
```

### 完整参数

| 参数 | 说明 |
|------|------|
| `-p <name\|pid>` | 目标进程名或 PID，可多次指定 |
| `-u <addr:port>` | 上游 HTTP CONNECT 代理地址（**必填**），如 127.0.0.1:2080 |
| `--watch` | 持续扫描并注入新匹配的进程 |
| `-s, --status` | 列出所有已注入 ghost_core.dll 的进程 |
| `-l, --log-only` | 仅启动日志服务器，不注入 |
| `-h, --help` | 显示帮助 |

### 日志示例

```
[14:08:09] [Init] Hooks installed successfully (PID: 3188)
[14:08:19] [DNS-Proxy] GetAddrInfoW: play.googleapis.com -> [216.239.32.223] (1 IPs)
[14:08:19] [hook] ConnectEx: 216.239.32.223:443 | play.googleapis.com
[14:08:19] [Proxy] Handshake OK: 216.239.32.223:443 | play.googleapis.com
[14:10:06] [DNS] Query: www.googleapis.com. -> A: [142.250.72.234, 142.251.45.10]
[14:10:06] [DNS] Query: www.googleapis.com. -> AAAA: [2607:f8b0:4004:800::200e]
```

## 实战示例

### 代理 Antigravity AI 编程助手

Antigravity 的 AI 大模型通信走 `language_server_windows_x64.exe` 进程，直接注入即可：

```cmd
ghost-proxifier.exe -p language_server_windows_x64 -u 127.0.0.1:2080
```

注入后，AI 对话、代码补全等所有请求都会通过代理转发，无需配置 TUN 或系统代理。

### 代理 Chrome 浏览器

Chrome 的网络请求由 **Network Service** 子进程处理。首先找到它的 PID：

```cmd
wmic process where "name='chrome.exe'" get ProcessId,CommandLine | findstr "network.mojom.NetworkService"
```

输出示例：
```
"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=utility --utility-sub-type=network.mojom.NetworkService ...  17964
```

然后用 PID 注入：

```cmd
ghost-proxifier.exe -p 17964 -u 127.0.0.1:2080
```

> **提示：** 建议在 Chrome 设置中关闭安全 DNS（`chrome://settings/security`），避免 DoH 重试带来的额外延迟。

### 验证注入状态

注入后可以随时查看哪些进程已加载了 `ghost_core.dll`：

```cmd
ghost-proxifier.exe -s
```

输出示例：
```
=========================================================
  Injected Processes (ghost_core.dll)
=========================================================
  PID       Process Name
---------------------------------------------------------
  17964     chrome.exe
  3188      language_server_windows_x64.exe
---------------------------------------------------------
  Total: 2 process(es)
=========================================================
```

## 已测试应用

| 应用 | 状态 | 备注 |
|------|------|------|
| Antigravity (AI 编程) | ✅ | 注入 `language_server_windows_x64` 进程 |
| Chrome | ✅ | 注入 Network Service 进程，建议关闭安全 DNS |
| Telegram Desktop | ✅ | |

## Hook 函数列表

| 函数 | 用途 |
|------|------|
| `connect` / `WSAConnect` / `ConnectEx` | 重定向到代理，延迟握手 |
| `send` / `WSASend` | 首次发送前完成 HTTP CONNECT |
| `sendto` / `WSASendTo` | DNS 请求重定向到 Local DNS Proxy |
| `recvfrom` / `WSARecvFrom` | DNS 响应拦截 & IP-域名映射 |
| `getaddrinfo` / `GetAddrInfoW` / `gethostbyname` | DNS 解析通过代理转发 |

## 项目结构

```
ghost-proxifier/
├── ghost_core.cpp       # Hook DLL 核心源码（DNS/连接/发送 Hook）
├── ghost_injector.cpp   # 注入器 & 日志服务器
├── CMakeLists.txt       # 构建配置
├── compile.bat          # 一键编译脚本
├── MinHook/             # MinHook 库（函数 Hook 引擎）
└── bin/                 # 编译产物
    ├── ghost_core.dll
    └── ghost-proxifier.exe
```

## License

MIT

---

## Configuration: multiple processes and direct rules

`ghost-proxifier.exe` now supports reading `ghost.conf` to decide which processes to inject, which upstream proxy to use, and which domains/IP ranges should be connected directly without proxy tunneling.

### Basic example

Create `ghost.conf` beside `ghost-proxifier.exe` and `ghost_core.dll`:

```ini
[global]
# HTTP CONNECT (default):
# proxy=127.0.0.1:2080
# SOCKS5 (no-auth):
proxy=socks5://127.0.0.1:7890
# or:
# proxy_type=socks5
# proxy=127.0.0.1:1080
process=Codex.exe

# Direct connection rules. Subdomains are matched automatically.
# Local loopback is direct by default so the app can still talk to local services.
direct_ip=127.0.0.1
# direct_domain=*.corp.example.com
# direct_domain=intranet.local
# direct_ip=172.16.0.0/12
direct_ip=192.168.0.0/16
```

Run:

```powershell
.\ghost-proxifier.exe -c .\ghost.conf --watch
```

### Per-process proxy example

A process-specific section can override the global proxy and add extra direct rules. The section name may use either process name or PID.

```ini
[global]
proxy=127.0.0.1:2080
process=chrome.exe
process=Code.exe

direct_ip=10.0.0.0/8
direct_domain=*.company.local

[process:chrome.exe]
proxy=127.0.0.1:2080
direct_domain=accounts.company.local

[process:Code.exe]
proxy=127.0.0.1:2081
direct_ip=192.168.50.0/24

[process:12345]
proxy=127.0.0.1:2082
```

Rules:

- `process=` can be repeated or comma-separated, for example `process=chrome.exe,msedge.exe`.
- `[process:<name-or-pid>]` also marks that process as an injection target.
- `proxy=` / `upstream=` accepts `127.0.0.1:2080` or `http://127.0.0.1:2080` for HTTP CONNECT, and `socks5://127.0.0.1:1080` for SOCKS5 no-auth. You may also use `proxy_type=socks5` with `proxy=127.0.0.1:1080`, or `socks5=127.0.0.1:1080`.
- `direct_domain=` / `bypass_domain=` matches the exact domain and all subdomains. `*.example.com`, `.example.com`, and `example.com` are treated as the same suffix rule.
- `direct_ip=` / `bypass_ip=` supports IPv4 or CIDR, for example `192.168.1.25` or `192.168.0.0/16`.
- `direct=` / `bypass=` accepts a comma-separated mixed list, for example `direct=*.local,10.0.0.0/8,192.168.1.2`.
- The old single-line format is still accepted as HTTP CONNECT: `127.0.0.1:2080`.

SOCKS5 handshakes are now completed before the first `send`, `WSASend`, `recv`, or `WSARecv`. This matters for clients that use `ConnectEx` with initial data and then wait for a response; those connections should now appear in the upstream SOCKS5 proxy log as soon as the first socket I/O happens. If the target app only connects to `127.0.0.1`/LAN addresses covered by `direct_ip`, those connections are intentionally direct and will not appear in the SOCKS5 proxy log.

Note: the injected DLL always loads `ghost.conf` from the directory that contains `ghost_core.dll`. When `-c <file>` or `-u <proxy>` is used, the injector writes/copies the runtime config to that directory before injection.

Domains in direct rules use system DNS and direct sockets, so they can go through your normal LAN/VPN route instead of the upstream proxy.

## Double-click and system tray

- Put `ghost-proxifier.exe`, `ghost_core.dll`, and `ghost.conf` in the same directory, then double-click `ghost-proxifier.exe` to start.
- When started with no arguments, it automatically reads `ghost.conf` and enables `--watch`.
- A `Ghost Proxifier` icon is added to the Windows system tray.
- Minimize the console window to hide it to the tray; double-click the tray icon to restore it.
- Right-click the tray icon to choose `Open` or `Exit`.
- Use `--no-tray` to disable the tray icon/minimize-to-tray behavior.

## DNS and exit behavior

- `dns=proxy` (default) forwards DNS through the configured upstream proxy to `dns_server`.
- `dns=system` disables Ghost's DNS proxy and uses the normal system/process DNS path.
- `dns_server=8.8.8.8:53` selects the DNS server used by `dns=proxy`.
- `dns_ipv6=off` is the default; AAAA/IPv6 DNS queries return quickly with an empty answer to avoid slow IPv6 failures. Use `dns_ipv6=on` if IPv6 is required.
- Clicking the console close button now hides the window to the tray instead of quitting.
- Use the tray icon right-click menu `Exit` to quit; on exit the injector unloads `ghost_core.dll` from injected processes so they stop using the proxy.
- `ghost-proxifier.exe --unload` can be used to restore already-injected processes manually.
