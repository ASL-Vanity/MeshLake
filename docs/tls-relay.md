# MeshLake TLS Relay（Planet V4）

TLS Relay 是 MeshLake 在 UDP 被封锁或严重受限时的**受控加密回退**。它不是标准 TURN 服务，也不接受通用 TURN Allocate、Refresh、Permission 或 ChannelBind 请求。

## 安全边界

- Planet V4 由已钉扎的控制器 Ed25519 公钥签名。每个 TLS Relay 同时绑定既有 Relay 的 `service_id`、数值 `IP:PORT`、SNI 和叶证书 DER 的 SHA-256 指纹。
- 客户端不使用系统根证书，也不会因为公共 CA、企业代理 CA 或名称匹配而接受替代证书；叶证书指纹必须与 Planet 中的值逐字节一致。
- TLS 仅保护客户端到 Relay 的受限网络传输。虚拟网络 IP 数据仍使用成员间 Ed25519/X25519/HKDF/XChaCha20-Poly1305 成对会话端到端加密；Relay 不持有网络密钥、会话密钥或明文。
- 长度帧最大为 `u16::MAX` 字节。无效长度、TLS 握手失败、证书指纹不匹配、断线和拥塞都按传输失败处理，不会降级到未认证 TCP。

## 路径选择

```text
UDP 直连 -> Planet V5 UDP TURN（如已配置） -> Planet V5 TLS TURN（如已配置） -> 已认证 UDP Relay -> Planet V4 TLS Relay
```

`RelayPolicy::Disabled` 禁止所有 TURN/Relay 回退；`RelayPolicy::Required` 跳过直连。标准 UDP TURN 与 TLS TURN 优先于 MeshLake Relay；明文 TCP TURN 因会暴露短期凭据而始终失败关闭。对于 V3/V4/V5 Relay，只有收到对应网络、服务身份和 nonce 的已验证注册确认后，UDP Relay 才会被视为健康；UDP 未健康且 TURN 不可用而 TLS Relay 已完成指纹钉扎连接时，客户端才把加密帧写入 TLS 流。TURN 的部署和凭据边界见 [`turn.md`](turn.md)。

## 服务端与控制器配置

Relay 的 TLS 监听复用同机 UDP Relay，因此成员注册、授权验证、成员目录和密文路由全部沿用同一实现：

```powershell
meshlake-relay.exe `
  --bind 0.0.0.0:51820 `
  --tcp-tls-bind 0.0.0.0:443 `
  --tcp-tls-certificate C:\MeshLake\tls\relay-fullchain.pem `
  --tcp-tls-private-key C:\MeshLake\tls\relay-private-key.pem `
  --controller-public-key-base64 <控制器公钥>
```

控制器使用下列参数发布 V4 项；`RELAY_UUID` 必须同时出现在 `--planet-relay-identity`，指纹是证书**叶证书 DER** 的 SHA-256，以 Base64 编码：

```text
--planet-tls-relay RELAY_UUID@IP:PORT@SERVER_NAME@BASE64_SHA256_CERT_PIN
```

TLS Relay 公网端口、证书公钥和指纹属于可公开分发的 Planet 信息；私钥、控制器管理员令牌、成员入网令牌和状态文件不得写入命令行历史、日志或仓库。

## Linux systemd 部署

Relay 可以使用独立的 `meshlake` 服务账户运行。请显式指定 `--identity-file`，使长期 Relay 身份位于 systemd 管理的状态目录；该文件会被 Unix 身份校验要求为服务账户拥有的普通 `0600` 文件。

```ini
# /etc/systemd/system/meshlake-relay.service
[Unit]
Description=MeshLake encrypted relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=meshlake
Group=meshlake
StateDirectory=meshlake
ExecStart=/opt/meshlake/meshlake-relay --bind 0.0.0.0:51820 --identity-file /var/lib/meshlake/relay-identity.json --controller-public-key-base64 <CONTROLLER_PUBLIC_KEY_BASE64>
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/meshlake

[Install]
WantedBy=multi-user.target
```

若使用 TLS Relay，可在同一 `ExecStart` 追加 `--tcp-tls-bind`、`--tcp-tls-certificate` 和 `--tcp-tls-private-key`。监听特权端口（例如 TCP 443）时，优先使用反向代理或由管理员审查后最小化授予 `CAP_NET_BIND_SERVICE`；不要为了绑定端口而把 Relay 长期作为完整 root 服务运行。修改 unit 后执行 `sudo systemctl daemon-reload && sudo systemctl enable --now meshlake-relay.service`。

## 可观测性与运维

`meshlake-cli status` 与本机状态 API 只显示已配置/已连接 TLS Relay 数、连接失败数、已写入/接收帧数和队列丢弃数，不显示 TLS 端点、证书、SNI、凭据或业务数据。会话路径会显示为 `tls_relay`。

生产部署前仍须在受控测试环境验证：证书轮换后 Planet 更新的收敛、TCP 443 限制网络、IPv4/IPv6、断线重连、UDP 到 TLS 回退、出口 kill switch 的 TLS 端点例外，以及服务端故障恢复。
