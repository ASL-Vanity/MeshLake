# MeshLake 标准 TURN（Planet V5）

MeshLake 的 Planet V5 可发布控制器签名的标准 TURN 端点。TURN 只转运已经由 MeshLake 成员会话端到端加密的 Relay 帧；coturn 和网络中继都不持有虚拟网络密钥、成员私钥或解密后的 IP 流量。

## 当前实现范围

- 客户端支持标准 **UDP TURN**：RFC 5766/RFC 8656 兼容的 `Allocate`、`CreatePermission`、`Send Indication`、`Data Indication` 与 `Refresh`。
- 认证使用 coturn REST 静态密钥模式。控制器在 HTTPS 入网和成员刷新响应中签发短期凭据，格式为 `过期Unix秒:设备ID` 与 `Base64(HMAC-SHA1(static-auth-secret, username))`。
- 凭据仅保存在运行中的 `meshlaked` 内存；不会写入 agent 状态、Planet、CLI 输出、GUI、本地状态 API 或日志。过期前会随成员刷新重新获取。
- Planet 可以同时发布 UDP、TCP 与 TLS TURN 端点；当前数据面只启用 UDP 项。TCP/TLS 项不会被降级为 UDP，也不会在未实现时被伪装为可用。

路径优先级为：

```text
UDP 直连 -> 已认证 UDP TURN -> 已认证 MeshLake UDP Relay -> Planet TLS Relay
```

`RelayPolicy::Disabled` 仍会禁止 TURN、MeshLake UDP Relay 和 TLS Relay 回退；`RelayPolicy::Required` 会跳过成员直连。

## coturn 配置

在公网 Linux 服务器的 `/etc/turnserver.conf` 使用 REST 认证，而不是固定 `user=` 账户：

```ini
listening-port=3478
fingerprint
lt-cred-mech
use-auth-secret
static-auth-secret=从受限文件安全复制的高熵随机值
realm=turn.example.com
no-loopback-peers
no-multicast-peers
min-port=49160
max-port=49200
```

防火墙至少需要放行 UDP `3478` 以及 UDP 中继端口范围（示例为 `49160-49200`）。不要把静态认证密钥传入命令行、Git 仓库、聊天记录、服务日志或 CI；应放入仅服务账户可读的受限文件。

## 控制器发布

控制器将 TURN 端点签入 Planet V5，并从受限文件读取同一个 coturn `static-auth-secret`：

```powershell
meshlake-controller.exe `
  --planet-controller-url https://planet.example.com `
  --planet-relay-identity RELAY_UUID@RELAY_PUBLIC_KEY_BASE64@203.0.113.10:51820 `
  --planet-root-identity ROOT_UUID@ROOT_PUBLIC_KEY_BASE64@203.0.113.11:51819 `
  --planet-turn-server udp@203.0.113.12:3478 `
  --turn-static-auth-secret-file C:\MeshLake\secrets\coturn-rest.secret
```

TLS TURN 描述符格式为：

```text
--planet-turn-server tls@IP:PORT@SERVER_NAME@BASE64_SHA256_CERT_PIN
```

UDP/TCP TURN 描述符不得携带 SNI 或证书指纹。TLS 项要求非空 SNI 和精确 32 字节叶证书 SHA-256 指纹。Planet 校验会拒绝回环、私有、链路本地、未指定、多播或端口为零的 TURN 端点。

## 验收边界

离线测试会验证 TURN 认证报文、地址编码、权限创建和数据指示往返。正式发布前仍须在获授权的可丢弃公网、Windows 和 Linux 环境执行 coturn 真机验收，包括对称 NAT、IPv4/IPv6、凭据轮换、UDP 阻断、故障恢复及清理。
