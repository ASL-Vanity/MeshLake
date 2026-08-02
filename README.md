# MeshLake（连接万物的湖泊）

[![CI](https://github.com/ASL-Vanity/MeshLake/actions/workflows/ci.yml/badge.svg)](https://github.com/ASL-Vanity/MeshLake/actions/workflows/ci.yml)

MeshLake 是一个可自托管的加密虚拟局域网项目：让一台设备同时加入多个彼此隔离的虚拟网络，并为多层 NAT、运营商级 NAT（CGNAT）环境准备直连与公网中继能力。

> 本项目由 ChatGPT 5.6 开发。

本项目以 Apache License 2.0 开源。仓库中的 Wintun 预编译文件适用 WireGuard LLC 的独立许可证，详见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。安全问题请阅读 [`SECURITY.md`](SECURITY.md)，贡献说明见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

当前优先支持 Windows；核心与协议层使用 Rust 编写，为后续 Linux、macOS、Android 和 iOS 共用。MeshLake 的后台服务无需图形界面即可运行；Windows GUI 仅通过本机 API 管理该服务。

## 当前进度

已经实现：

- `meshlaked`：Windows/Linux 无界面后台代理，提供仅监听本机回环地址的管理 API，可持久化设备身份并加入多个网络；Windows 支持以 SYSTEM 权限随系统启动，Linux 支持 systemd。
- `meshlake-cli`：无图形界面的命令行客户端，可查询状态、管理网络及控制虚拟网卡会话。
- `meshlake-controller`：自托管控制器，可创建双栈网络、发放一次性入网令牌、分配虚拟 IPv4/IPv6 地址，并使用 Ed25519 签发成员证书；支持直接加载 PEM 证书和私钥提供原生 HTTPS。
- `meshlake-relay`：可选 UDP 协调与中继服务。成员先用控制器签发的证书注册；服务会交换经验证成员的观察到的 UDP 地址以协助打洞，并仅按网络与设备标识转发密文，不持有任何虚拟网络密钥。
- `meshlake-core`：共享的数据模型、Ed25519/X25519/HKDF/XChaCha20-Poly1305 会话协议、成员证书校验和 UDP 中继帧定义。
- `MeshLake`：原生 Windows 图形管理端，与同一个后台代理协作，可查看状态、控制网卡及安全加入控制器网络。
- Wintun：代理可动态加载签名的 `wintun.dll`，创建/关闭虚拟网卡会话，且已具备官方 API 的 IP 数据包读写封装。
- 已验证成员目录：根据控制器签名证书把虚拟 IPv4/IPv6 地址映射到设备 ID，普通数据只发送给目标设备；详见 [`docs/unicast-routing.md`](docs/unicast-routing.md)。
- 成对加密会话：成员使用长期 Ed25519 设备身份签名一次性 X25519 握手，并为两个传输方向派生不同的临时密钥；详见 [`docs/pairwise-sessions.md`](docs/pairwise-sessions.md)。
- 在线授权与成员吊销：证书具有唯一 ID 和网络密钥版本；`meshlaked` 每约 20 秒刷新控制器签名的 90 秒授权清单，在密钥 epoch 变化时用设备签名请求新证书与网络密钥。删除本机成员会停用网络、虚拟地址和路由并重建传输；对端不再被授权时不会进入成员目录或会话。Root/Relay 注册也必须携带有效授权清单；详见 [`docs/authorization-revocation.md`](docs/authorization-revocation.md)。
- 每网络控制面：每个已加入网络分别保存控制器 URL、钉扎公钥、签名授权清单以及经验证的 Planet 根节点、中继和 STUN 配置；来自不同 Planet 的网络不再共用一份设备全局配置。旧状态会在启动时自动迁移。
- 传输热重载：加入新网络或修改手动 Planet/中继配置后，后台代理会自动重建 UDP 传输线程，不再要求退出或重启 `meshlaked`。
- 多 Root/多 Relay 故障切换：健康状态按虚拟网络与公网端点隔离；首选节点失效后会确定性选择健康备用节点，共享同一公网端点的不同网络不会互相借用健康结论。
- 已签名 NAT 候选传播：Relay 只分发设备签名注册中、且公网 IP 与 Relay 实际观察一致的 PCP、NAT-PMP、UPnP 或 STUN 候选；未签名、跨网络、非法地址和超量候选会失败关闭。
- 适配器事务安全：Linux TUN 只有在接口成功启用后才发布会话，并严格校验双栈前缀与跨网络重复地址；daemon 串行化入网、退网、授权刷新、激活与关闭操作，新建会话配置失败时会自动回滚。
- 状态文件保护：Windows 上的 agent 与 controller 状态使用机器级 DPAPI 加密信封，旧明文 JSON 会在首次读取后自动升级；Linux 既有文件和新写入文件都会收紧为 `0600`。状态路径使用进程级独占锁，Windows 通过 `ReplaceFileW` 原子替换并保留目标安全属性，避免自启动与手动实例并发损坏状态。详见 [`docs/state-protection.md`](docs/state-protection.md)。
- 安全状态备份：agent 与 controller 可用隐藏口令交互导出跨 Windows/Linux、可跨机器恢复的备份包；格式使用 Argon2id 派生密钥和 XChaCha20-Poly1305 认证加密，错误口令、篡改、截断、类型混用和保留路径别名都会失败关闭。恢复后 Windows 重新写入 DPAPI，Linux 保持 `0600`。
- 签名 DNS 与自定义路由：控制器发布 Ed25519 签名的 `NetworkPolicyManifest`；非默认 IPv4/IPv6 路由必须由当前成员证书的 `allowed_routes` 明确覆盖，客户端联合验证钉扎控制器、授权清单和网关证书后才应用。Windows/Linux 平台配置采用事务更新，回滚无法确认时会停用虚拟网卡数据面。详见 [`docs/network-policy.md`](docs/network-policy.md)。
- 会话可观测性：本机 `GET /v1/sessions` 与 `meshlake-cli sessions [--json]` 提供按网络隔离的 pending/established/expired、直连/中继路径、队列和安全计数，不暴露密钥、握手包、端点或数据内容。另有不连接外部主机的 Windows/Linux 系统测试计划框架，详见 [`docs/session-observability.md`](docs/session-observability.md)。

尚未实现，因此当前版本**不能作为正式虚拟局域网产品使用**：

- 默认路由/出口节点、网关主机自动开启 IP forwarding、防火墙或 NAT；
- macOS、Android、iOS 客户端，以及 Linux Secret Service/TPM 等更强的平台密钥库集成；
- 提权真实 Windows/Linux 主机上的路由、DNS、双栈、故障切换与吊销跨主机验收。

## 架构

```text
MeshLake GUI ─────────┐
meshlake-cli ─────────┼──> meshlaked ──> Wintun/TUN ──> IPv4/IPv6 加密数据面
                      │          │
                      │          ├──> root（签名会合与候选发现）
                      │          └──> relay（不可直连时盲转发密文）
                      └──> controller（入网、地址与成员证书）
```

每个逻辑网络都有独立的网络 ID、地址前缀、成员证书、控制器信任、公网发现配置与中继策略。单台设备的一个后台代理可保存来自不同 Planet 的多个已加入网络；Windows 上的一个三层虚拟网卡承载这些逻辑网络，这也适配移动系统通常只允许一个 VPN 接口的限制。

## 安全模型（当前）

控制器首次启动会生成两项内容：管理员令牌与 Ed25519 控制器公钥。管理员令牌只能用于控制器管理接口；控制器公钥应通过可信渠道分发给设备和中继服务。入网时，设备会把收到的成员证书与该公钥进行匹配并验证签名，不能仅因证书“自签名正确”就接受它。

每个虚拟网络另有独立的 32 字节网络密钥，由控制器在成功入网响应中发给成员。它现在只作为设备间 HKDF 会话派生的附加 PSK，不再直接加密成员间 IP 数据。生产控制器必须使用原生 HTTPS 或置于 HTTPS 反向代理之后。Windows 正式状态已接入机器级 DPAPI；Linux 正式状态目前依赖 `0600` 文件权限。两端都可另行导出使用 Argon2id 与 XChaCha20-Poly1305 保护的跨机器备份，但 Linux Secret Service、TPM 和运行时内存强化仍未完成，因此仍不应存放高价值生产凭据。

两个成员首次传输时，会用证书绑定的 Ed25519 设备身份认证一次性 X25519 公钥，并通过 HKDF-SHA256 派生两个方向各自独立的 XChaCha20-Poly1305 密钥。数据帧的网络 ID、源/目标设备 ID、会话 ID 和包序号均作为 AEAD 附加认证数据。每个会话最长使用 1 小时，接收端维护 64 包滑动窗口拒绝重复和过旧数据包。

中继只看到路由所需的网络 ID、源/目标设备 ID、会话 ID、包序号及密文，不持有网络密钥、设备私钥或成对会话密钥。单个已授权恶意成员不再能仅凭全网共享密钥伪造其他设备的数据帧，但它仍可从自己的授权地址攻击同一虚拟网络。控制器删除成员后，正常客户端通常在下一次约 20 秒刷新内断线；拒绝配合的旧客户端至多可重放尚未过期的授权清单，因此严格 Root/Relay 的最坏吊销窗口由当前 90 秒授权有效期限定。TLS、私有 CA 和状态保护改动已通过工作区编译与自动测试；跨主机原生 HTTPS 部署、Linux 原生运行和真实数据面仍需验证，系统密钥库仍是生产化前必须完成的安全工作。

当前控制器的默认地址是 `127.0.0.1:51822`，中继默认地址是 `127.0.0.1:51820`。未配置原生 TLS 时，控制器默认只允许回环地址；绑定 `0.0.0.0`、局域网地址或公网地址会拒绝启动，除非显式使用仅供隔离开发环境的 `--allow-insecure-public-http`。公网部署仍需访问控制和受保护的持久化存储，详见 [`docs/controller-tls.md`](docs/controller-tls.md)。

## Windows Wintun 驱动

开发版本内含已经核验的 AMD64 `wintun.dll`。代理会优先加载 `meshlaked.exe` 同目录的 DLL；若没有，则将内置 DLL 原样写入 `%LOCALAPPDATA%\MeshLake\wintun.dll`。也可通过 `--wintun-dll <路径>` 指定位置。

在管理员权限的 Windows 会话中执行 `meshlake adapter start`，可以创建或打开 MeshLake 虚拟网卡。

后台代理启动网卡时会把控制器分配的 IPv4/IPv6 地址配置到 MeshLake 适配器，并安装相应的直连网段路由。经验证的控制器策略还可安装非默认自定义路由和 split-DNS/search domain；本阶段明确拒绝 `0.0.0.0/0` 与 `::/0`。来自 Wintun 的 IPv4 与 IPv6 包都会按最长前缀和本机已分配源地址选择唯一逻辑网络并进入加密传输层。

## 图形界面与无界面运行

构建后可运行 `MeshLake.exe` 打开 Windows 管理界面；它仅使用 `http://127.0.0.1:51821` 与 `meshlaked.exe` 通信。隐藏或最小化 GUI 不会中断后台服务；选择“完全退出 MeshLake”则会同时停止相关后台进程。

GUI 会优先加载 Windows 的 Noto Sans SC、黑体或微软雅黑字体以完整显示简体中文。首次启动时若本机后台代理尚未运行，GUI 会在无命令行窗口的状态下启动同目录的 `meshlaked.exe`；点击窗口关闭按钮会按设置弹出选择或最小化到系统托盘。右键托盘图标可选择“显示 MeshLake”或“完全退出 MeshLake”；完全退出会结束 `meshlaked.exe`、`meshlake-controller.exe`、`meshlake-root.exe`、`meshlake-relay.exe` 和 GUI 自身。

GUI 的“控制器网络管理”页可创建、列出和删除控制器网络，生成一次性入网令牌，查看成员及从控制器记录中移除成员。移除成员会轮换网络密钥 epoch；在线代理在下一次授权刷新时自动停用该网络，其他成员也会拒绝已删除证书重新进入目录。该机制是短时授权租约，不是零延迟推送：正常刷新周期约 20 秒，拒绝配合的客户端旧授权最多持续到 90 秒清单过期。

无需 GUI 时可单独运行：

```powershell
meshlaked.exe run
meshlaked.exe autostart install
meshlake agent stop
meshlake-cli.exe sessions --json
```

`autostart install` 需要在管理员终端执行，会创建随 Windows 启动、以 SYSTEM 权限运行的任务计划，并把当前状态文件与 Wintun DLL 的绝对路径固定到启动命令中。可以使用 `autostart status` 检查，或用 `autostart uninstall` 停止并移除任务。`meshlake agent stop` 会通过本机 API 正常关闭传输工作线程和虚拟网卡会话。

安全备份要求对应 agent/controller 进程先释放状态锁。默认隐藏提示口令，恢复默认拒绝覆盖：

```powershell
meshlaked.exe --state-file C:\MeshLake\agent.json state backup D:\Backup\agent.mlb
meshlaked.exe --state-file C:\MeshLake\agent.json state restore D:\Backup\agent.mlb --force

meshlake-controller.exe --state-file C:\MeshLake\controller.json state backup D:\Backup\controller.mlb
meshlake-controller.exe --state-file C:\MeshLake\controller.json state restore D:\Backup\controller.mlb --force
```

自动化环境可显式使用 `--password-stdin` 从标准输入读取一行口令；不要把口令放入命令行参数、脚本源码或 CI 日志。完整边界见 [`docs/state-protection.md`](docs/state-protection.md)。

## 构建

安装稳定版 Rust 工具链和 Windows C++ Build Tools 后，在项目根目录执行：

```powershell
cargo build --workspace
cargo test --workspace
```

Linux x86_64 客户端和服务器端的构建、TUN 要求与 systemd 使用方法见 [`docs/linux-client.md`](docs/linux-client.md)。

GitHub Actions 会在推送到 `main` 或提交 Pull Request 时运行 Windows/Linux 测试和 release 模式构建，并上传名为 `MeshLake-Windows-x64` 与 `MeshLake-Linux-x64` 的 CI 产物。工作流当前只保留这些产物 14 天；它们是特定提交的自动构建快照，不等同于 GitHub **Releases** 页面中的正式版本。正式发布仍需由维护者单独创建 Release、附加产物并记录对应提交或标签。

## 控制器与中继试运行

启动本机控制器：

```powershell
cargo run -p meshlake-controller
```

首次启动会把管理员令牌输出到当前进程的标准错误，并在每次启动时输出控制器公钥（Base64）。请在受控终端完成首次初始化并立即安全保存管理员令牌；不要让首次启动输出进入公开日志、共享终端记录或无人管理的日志采集系统。

使用正式 PEM 证书和私钥直接启动 HTTPS 控制器：

```powershell
meshlake-controller.exe `
  --bind 0.0.0.0:51822 `
  --tls-certificate C:\MeshLake\tls\fullchain.pem `
  --tls-private-key C:\MeshLake\tls\private-key.pem `
  --planet-controller-url https://planet.example.com `
  --planet-relay-endpoint 203.0.113.10:51820
```

证书必须覆盖客户端使用的域名。使用公共 CA 时由客户端系统信任；使用自建 CA 时，再提供 `--tls-client-ca-certificate C:\MeshLake\tls\root-ca.pem`，控制器会把公开 CA 证书放进入网链接。客户端收到后只信任该 CA，并将其按网络保存，用于首次入网、Planet 下载和后续授权刷新。使用 HTTPS 反向代理时，控制器继续绑定 `127.0.0.1:51822`，无需提供原生 TLS 证书参数，但仍可用 `--tls-client-ca-certificate` 发布反向代理的私有 CA。

无需 GUI 即可创建和管理双栈网络：

```powershell
meshlake-cli.exe controller public-key `
  --controller http://127.0.0.1:51822

meshlake-cli.exe controller network create `
  --controller http://127.0.0.1:51822 `
  --admin-token <管理员令牌> `
  --name home `
  --ipv4-prefix 100.64.50.0/24 `
  --ipv6-prefix fd42:4d4c:50::/64 `
  --relay-policy preferred

meshlake-cli.exe controller network list `
  --controller http://127.0.0.1:51822
```

删除网络使用 `controller network delete --network <网络ID>`，并同样提供控制器地址与管理员令牌。

控制器还提供签名策略管理 API，用于先给指定网关成员显式授权 `allowed_routes`，再发布非默认路由与 DNS/search domain。策略必须使用 `x-meshlake-admin-token` 管理头，默认路由会被拒绝；请求格式和失败关闭边界见 [`docs/network-policy.md`](docs/network-policy.md)。

中继需要显式钉扎该控制器公钥：

```powershell
cargo run -p meshlake-relay -- --controller-public-key-base64 <控制器公钥>
```

在每台 Windows 设备上保存中继 UDP 地址；后台代理会自动重载传输配置，无需重启：

```powershell
meshlake relay set --endpoint <中继公网IP或域名:51820>
```

Windows GUI 的“UDP 协调 / 中继地址”默认启用 **UPnP IGD 自动映射 UDP 端口**。启用后，代理会尝试在本地路由器创建一个 30 分钟租约的 UDP 映射，并在后台代理正常关闭时删除该映射；路由器不支持或禁用 UPnP 时会自动跳过，仍可使用普通 UDP 打洞和中继回退。该选项仅应在你信任当前家庭/办公路由器时启用。

客户端传输层会同时绑定独立的 IPv4 与 IPv6 UDP socket，并按中继、根节点、STUN 服务器或对端候选的地址族自动选择对应 socket，因此 Planet 可以混合配置 IPv4 与 `[2001:db8::1234]:51820` 形式的 IPv6 端点。IPv6 本身通常不需要 UPnP 映射，但仍需系统防火墙允许 UDP 通信，并需要可访问的地址交换渠道；系统无法绑定 IPv6 时会保留 IPv4 传输并记录诊断信息。

中继模式下，代理每 20 秒用成员证书更新一次 UDP 映射。中继把同一网络中其他已验证成员的观察地址通知给客户端；客户端从对应地址族的 UDP socket 发送探测包，打洞成功后优先直接传输，无法直连时自动继续走中继。Wintun/TUN 的 IPv4 与 IPv6 出站包使用目标成员专属的临时会话密钥加密；中继只看见路由元数据和密文。

这使两台没有公网 IP 的设备可以尝试直接通信，但仍需要一台双方可访问的协调/中继服务器。对称 NAT、运营商级 NAT 或严格企业防火墙可能禁止打洞，届时中继是保证连通性的必要回退，而不是可由客户端软件消除的限制。

设备加入网络时同样必须给出已核验的控制器公钥：

```powershell
meshlake-cli network join `
  --controller http://127.0.0.1:51822 `
  --network <网络ID> `
  --token <一次性入网令牌> `
  --controller-public-key-base64 <控制器公钥>
```

当前 CLI 只能通过命令行参数接收 `--admin-token`、`--token` 和 `network join-link --link` 的完整邀请链接，尚不支持从标准输入或令牌文件读取。这些敏感值可能出现在进程参数、PowerShell/Bash 历史或终端日志中；只应在受控管理终端使用，不要把真实命令复制到 Issue、脚本、聊天或 CI 日志，并在使用后按所在系统的安全策略清理相关历史记录。

## 下一步

下一阶段将重点完成提权真实 Windows/Linux 主机上的双栈直连、直连转 Relay、Root/Relay 故障切换、吊销、daemon 重启、路由/DNS 回滚验收，并继续推进出口节点、Linux Secret Service/TPM 与移动客户端。阶段 2 的并行开发、主线审查和剩余风险记录见 [`docs/stage2-parallel-development.md`](docs/stage2-parallel-development.md)。即使不安装 GUI，`meshlaked` 与 `meshlake-cli` 仍可独立运行。
