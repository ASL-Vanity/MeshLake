<img src="docs/assets/meshlake-mark.svg" width="64" height="64" alt="MeshLake 双岸标志">

# MeshLake

**自托管的加密虚拟局域网。** 让 Windows 与 Linux 设备加入同一个虚拟网络，通过直连或中继通信；控制器、客户端和中继均可自行部署。

[![CI](https://github.com/ASL-Vanity/MeshLake/actions/workflows/ci.yml/badge.svg)](https://github.com/ASL-Vanity/MeshLake/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ASL-Vanity/MeshLake)](https://github.com/ASL-Vanity/MeshLake/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[下载程序](https://github.com/ASL-Vanity/MeshLake/releases/latest) · [完整使用说明](docs/user-guide.md) · [v0.1.0 发布说明](docs/releases/v0.1.0.md) · [报告问题](https://github.com/ASL-Vanity/MeshLake/issues)

## 下载与运行要求

| 发布包 | 适用场景 | 运行要求 |
| --- | --- | --- |
| `MeshLake-Windows-x64.zip` | Windows 图形管理、命令行客户端与自托管服务 | x64 Windows、VC++ x64/UCRT 运行库；GUI 需要正常的图形驱动；创建虚拟网卡需要管理员权限 |
| `MeshLake-Linux-x64.tar.gz` | Linux 无界面客户端与自托管服务 | x86_64、glibc 2.17+；客户端需要 TUN、`iproute2` 和网络管理权限 |

下载后先解压，保留完整目录。Windows 包提供 `MeshLake.exe`、五个配套命令行程序及 Wintun；GUI 的服务与维护操作会调用同目录程序。每个包都附带离线文档、许可证和文件校验清单，Release 页面另有压缩包的 `SHA256SUMS.txt`。

v0.1.0 是首个公开版本。Windows GUI 与当前 CLI 的功能入口已完成开发；完整跨主机、出口防泄漏和干净系统安装验收仍有未覆盖场景，具体范围见[发布说明](docs/releases/v0.1.0.md)。目前不提供 macOS、移动端或 Linux GUI。

## Windows 快速开始

已有管理员提供的入网邀请时：

1. 解压 Windows 完整包，打开 `MeshLake.exe`。若要由 GUI 启动 Agent 并创建虚拟网卡，请以管理员身份运行。
2. 打开 **维护工具 → 本机服务**，选择 **Agent** 并点击 **启动服务**。已有 Agent 正在运行时直接连接即可。
3. 在 **加入网络** 中粘贴或导入邀请，核对控制器信息后加入。
4. 在 **连接与网卡** 中启动网卡，然后到 **概览** 查看虚拟地址、成员与会话。
5. 在另一台设备使用单独签发的邀请加入同一网络，通过虚拟 IP 访问目标服务。

GUI 默认连接 `http://127.0.0.1:51821/v1`。打开界面不会自动启动后台，也不会自动提权；关闭或退出 GUI 后，独立运行的 Agent、Controller、Root、Relay 会继续运行。

没有控制器或邀请时，按[首次部署与创建网络](docs/user-guide.md#4-自建-controller-与创建网络)完成控制器初始化，再给设备签发邀请。MeshLake 不内置公共托管网络。

## Linux 快速开始

```bash
tar -xzf MeshLake-Linux-x64.tar.gz
cd MeshLake-Linux-x64
sudo ./meshlaked run
```

在另一个终端进入同一目录：

```bash
./meshlake-cli status
./meshlake-cli network join-link --link-prompt
./meshlake-cli adapter start
./meshlake-cli sessions
```

在隐藏提示中输入邀请，避免把入网凭据写入 shell 历史。长期运行、状态目录和 systemd 配置见 [Linux 使用说明](docs/linux-client.md)。

## 可以做什么

| 功能 | 使用入口 |
| --- | --- |
| 查看连接状态、虚拟地址、成员与加密会话，导出脱敏 JSON | **概览** |
| 控制网卡，配置 Relay、STUN、端口映射与 Planet | **连接与网卡** |
| 使用邀请或手动信息入网，管理本机网络 | **加入网络** |
| 创建网络，签发邀请与令牌，管理成员、授权路由、DNS 和出口候选 | **控制器管理** |
| 显式选择出口，配置本机网关及转发 | **出口与网关** |
| 诊断、加密备份与恢复、修复旧状态、自启动及四类独立服务管理 | **维护工具** |

GUI 内置 MiSans 字体和统一矢量图标，支持中英文、浅色/深色/跟随系统、松石绿/湖蓝/靛紫/玫瑰/琥珀五种配色。缩放通过 80%、90%、100%、110%、125%、150% 固定选项调整，设置会保存。

CLI 可独立完成网络、控制器和维护操作。使用 `meshlake-cli --help` 查看命令，`meshlake-cli <命令> --help` 查看参数；常用示例见[完整使用说明](docs/user-guide.md)。

## 组件与部署

| 程序 | 职责 |
| --- | --- |
| `MeshLake.exe` | Windows 图形管理端 |
| `meshlake-cli` | 无界面管理客户端 |
| `meshlaked` | 设备 Agent，维护身份、虚拟网卡、路由和加密传输 |
| `meshlake-controller` | 网络管理、入网凭据、成员证书、地址和签名策略 |
| `meshlake-root` | 成员发现与协调 |
| `meshlake-relay` | 转发加密流量，提供无法直连时的回退路径 |

每台需要加入虚拟网络的设备运行 Agent；GUI 和 CLI 通过本机回环 API 管理它。Controller、Root、Relay 可部署在双方能够访问的服务器上。每个逻辑网络保存各自的控制器信任、成员授权、地址与发现配置。

控制器使用 HTTPS，管理员令牌和入网邀请通过可信渠道交付。Root/Relay 按签名信息验证成员，Relay 转发密文，不持有成员间的会话密钥。网络策略与出口操作会修改系统网络设置，配置前请阅读相应使用步骤。

- [控制器 HTTPS 与首次初始化](docs/controller-tls.md)
- [Root 部署](docs/root-server.md) · [Planet 配置](docs/planet.md)
- [路由与 DNS](docs/network-policy.md) · [TURN](docs/turn.md) · [TLS Relay](docs/tls-relay.md)
- [状态保护与备份](docs/state-protection.md) · [授权与吊销](docs/authorization-revocation.md)

## 从源码构建

Windows 需要 Rust 与 C++ Build Tools。完整构建：

```powershell
cargo build --workspace --release --locked
```

Linux 无界面组件：

```bash
cargo build --release --locked \
  -p meshlaked -p meshlake-cli -p meshlake-controller \
  -p meshlake-root -p meshlake-relay
```

构建输出位于 `target/release/`。Windows GUI 无需另行安装字体。修改代码的检查要求见 [CONTRIBUTING.md](CONTRIBUTING.md)；CI 的构建快照与 Release 发布包分别提供。

## 许可证与反馈

项目源码采用 [Apache License 2.0](LICENSE)。Wintun 与 MiSans 分别采用其原始许可，详见 [第三方组件说明](THIRD_PARTY_NOTICES.md)，发布包保留对应许可证。

普通问题请提交 Issue，并附上系统、版本、复现步骤及已检查的诊断信息。不要公开管理员令牌、邀请、状态文件或私钥。安全问题请按 [SECURITY.md](SECURITY.md) 报告。
