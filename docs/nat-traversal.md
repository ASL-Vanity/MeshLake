# MeshLake NAT 穿透与中继说明

## 当前可用的数据路径

MeshLake 现在按以下顺序建立传输路径：

1. 优先尝试 PCP 自动映射当前 UDP socket；不支持时依次尝试 NAT-PMP 和 UPnP IGD。
2. 同一 UDP socket 向所有已认证的 MeshLake 根节点和中继服务注册，交换对端的可达候选地址。
3. 若设置了 STUN 服务器，使用 RFC 5389 Binding 请求获取本机的 server-reflexive 候选地址，并经根节点/已认证中继分发给同一虚拟网络的成员。
4. 对所有已知候选并发发送 UDP 探测；直连建立后优先直接发送端到端加密数据。
5. 直连不可用时，自动选择仍在正常确认的最高优先级 `meshlake-relay` 转发加密数据。中继不持有虚拟网络流量密钥。

PCP 和 NAT-PMP 直接与默认 IPv4 网关的 UDP 5351 端口通信；UPnP 使用网关的 IGD 服务。映射租约会定期续订，公网端口发生变化后会更新根节点候选信息。网关不支持某种协议时会自动尝试下一种，不会阻止 STUN、普通 UDP 打洞或中继回退。

## 直连路径探测与选择

同一成员可能同时拥有局域网地址、IPv4 公网映射、STUN 地址和 IPv6 地址。MeshLake 会保留最多 16 个候选，并每 5 秒向所有候选发送一次轻量 UDP Punch 探测：

- 收到响应后记录往返时间（RTT），使用 `7/8` 旧值加 `1/8` 新样本的 EWMA 平滑短时抖动。
- 路径分数由平滑 RTT 与连续探测失败惩罚组成；每次超时增加 250 毫秒等价惩罚。
- 数据优先发送到最近 45 秒内仍然活跃且分数最低的候选，路径质量变化时会自动切换。
- 探测等待 3 秒仍无响应时记为一次失败；一次探测只会记一次失败。
- `RELAY_PUNCH` 只回复一个 `RELAY_PUNCH_ACK`，ACK 不再回复，避免两端形成 UDP 无限回声。

该评分只决定已发现直连候选之间的选择；所有候选均失效时仍会回退到健康的 MeshLake 中继。

执行 `meshlake-cli status` 可以查看每个对端当前选中的直连端点、平滑 RTT 和连续失败次数，用于判断实际走的是 IPv4、IPv6 还是仍在等待直连。

可在 GUI 的“STUN 服务器（可选）”中填写逗号分隔的 `主机:端口`，或使用无界面命令：

```powershell
meshlake relay set --endpoint relay.example.com:51820 `
  --stun stun.example.com:3478 `
  --stun stun-backup.example.com:3478
```

自动端口映射默认开启。如果当前网络不可信或管理员明确禁止路由器自动映射，可以添加：

```powershell
meshlake relay set --endpoint relay.example.com:51820 --disable-port-mapping
```

保存后 `meshlaked` 会自动重建 UDP 传输线程。STUN 仅用于提高直连成功率；它不是中继，也不能穿透所有对称 NAT/CGNAT。

## Windows 防火墙

Windows 往往把 Wintun 识别为“未识别的公用网络”。代理启用网卡时会维护名为 `MeshLake.VirtualLan.Inbound` 的入站规则，只作用于 `MeshLake` 虚拟网卡，不修改任何物理网卡或默认防火墙策略。删除该规则会导致解密后的入站虚拟局域网流量被 Windows 拦截。

## coturn / 标准 TURN

标准 TURN（RFC 8656）适合对称 NAT、运营商级 NAT 与严格企业网络；推荐在公网服务器上部署 coturn，并优先开放 UDP 3478，同时保留 TCP/TLS 443 作为受限网络的最后回退。

当前 MeshLake Windows 版本的可靠回退是内置 `meshlake-relay` 加密中继，**尚未把 coturn 的 TURN Allocate/Permission/ChannelData 客户端接入数据面**。因此不要把 coturn 地址填入“UDP 协调/中继地址”；那里只能填 MeshLake 中继的 `主机:端口`。coturn 可以先按下列配置预部署，待 TURN 客户端模块接入后再启用。

最小化的 coturn 配置示例（Linux `/etc/turnserver.conf`）：

```ini
listening-port=3478
tls-listening-port=5349
fingerprint
lt-cred-mech
realm=turn.example.com
user=meshlake:请替换为高强度密码
min-port=49160
max-port=49200
no-loopback-peers
no-multicast-peers
```

防火墙需开放：UDP 3478、TCP 3478、TCP 5349（配置 TLS 时）以及中继端口范围 `49160-49200` 的 UDP。生产环境还应配置正式 TLS 证书、日志轮转和长期凭据/REST API 凭据轮换。

## IPv6

若中继或根节点使用 IPv6，请将地址写成 `[2001:db8::1234]:51820`。客户端同时维护独立的 IPv4 与 IPv6 UDP socket，并按每个根节点、中继、STUN 服务器和对端候选的地址族自动选择对应 socket，因此同一个 Planet 可以混合部署双栈端点。两个 socket 的 STUN 映射和直连探测互不混用；某一地址族不可用不会停止另一地址族的传输。

IPv6 一般无需 NAT 打洞或 UPnP，但仍需要双方具备可路由的 IPv6 地址，并在本机与上游防火墙允许相应 UDP 流量。PCP、NAT-PMP 与 UPnP 自动端口映射目前只服务于 IPv4 socket。
