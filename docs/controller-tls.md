# MeshLake 控制器 TLS

控制器的管理令牌、一次性入网凭据、成员证书和网络 PSK 都经过 TCP 控制面传输。公网或不可信局域网部署必须使用 HTTPS，不能直接暴露纯 HTTP。

## 原生 HTTPS

`meshlake-controller` 可以直接加载 PEM 格式的证书链和私钥：

```powershell
meshlake-controller.exe `
  --bind 0.0.0.0:51822 `
  --state-file C:\MeshLake\controller.json `
  --tls-certificate C:\MeshLake\tls\fullchain.pem `
  --tls-private-key C:\MeshLake\tls\private-key.pem `
  --planet-controller-url https://planet.example.com `
  --planet-relay-endpoint 203.0.113.10:51820
```

规则：

- `--tls-certificate` 与 `--tls-private-key` 必须同时提供。
- 启用原生 TLS 后，`--planet-controller-url` 必须使用 `https://`。
- 证书的 SAN 必须覆盖公开控制器域名，证书链必须能被 Windows、Linux 和后续移动客户端信任。
- 私钥文件不应放进程序目录、便携包或 Git 仓库；只授予控制器服务账户读取权限。
- 控制器状态文件包含管理员令牌、签名私钥和网络 PSK。Windows 文件使用机器级 DPAPI，Linux 文件使用 `0600`；自定义路径仍必须限制 ACL。Windows DPAPI 文件不能直接作为跨机器备份，详见 [`state-protection.md`](state-protection.md)。

## 自建 CA 与邀请链接钉扎

没有公共域名证书时，可以用自己的根 CA 为控制器域名签发服务器证书。启动时额外指定公开的根 CA 证书：

```powershell
meshlake-controller.exe `
  --bind 0.0.0.0:51822 `
  --tls-certificate C:\MeshLake\tls\server-fullchain.pem `
  --tls-private-key C:\MeshLake\tls\server-private-key.pem `
  --tls-client-ca-certificate C:\MeshLake\tls\root-ca.pem `
  --planet-controller-url https://planet.example.internal `
  --planet-relay-endpoint 192.0.2.10:51820
```

生成的一键入网链接会携带 Base64 编码的公开 CA PEM。该内容不是私钥，可以发送给成员，但邀请链接同时包含一次性入网令牌，整体仍必须按密码保护。

客户端收到私有 CA 后会：

1. 关闭该控制器请求的系统内置根证书集合；
2. 只把邀请链接中的 CA PEM 作为 HTTPS 信任锚；
3. 使用同一信任配置完成首次入网和 Planet 下载；
4. 把 CA 保存到该虚拟网络的控制面记录；
5. 后续每约 20 秒的授权刷新继续使用该 CA。

一个 PEM 文件可以包含多张 CA 证书，便于在证书轮换期间同时信任旧、新根。不要在邀请链接里放服务器私钥，也不要使用“忽略证书错误”。

管理员通过命令行管理私有 CA 控制器时使用全局参数：

```powershell
meshlake-cli.exe `
  --tls-ca-certificate C:\MeshLake\tls\root-ca.pem `
  controller invite `
  --controller https://planet.example.internal `
  --network <网络ID> `
  --admin-token-file C:\MeshLake\secrets\administrator.token `
  --invite-link-file C:\MeshLake\secrets\member.invite
```

管理员令牌可通过隐藏提示、`--admin-token-stdin` 或 Linux mode/Windows ACL 均受限的 `--admin-token-file` 提供；这些来源互斥。邀请链接必须显式写入默认拒绝覆盖的 `--invite-link-file`，或使用只允许附着 stdout 终端的 `--claim-invite-link`。旧 `--admin-token` 仅为兼容保留并输出弃用警告，不要把真实令牌或完整 join link 放入 argv、脚本、Issue、聊天或 CI 日志。

控制器首次创建状态时也必须显式选择 `--claim-initial-admin-token` 或 `--initial-admin-token-file <SECRET_FILE>`；非 TTY 不会把令牌写到 stderr。文件目的地会受限创建且默认拒绝覆盖；如果随后状态写入失败，本次刚创建的令牌文件会被清理。

## HTTPS 反向代理

如果使用 Caddy、Nginx、Traefik 或云负载均衡器终止 TLS，让控制器保持默认回环监听：

```powershell
meshlake-controller.exe `
  --bind 127.0.0.1:51822 `
  --planet-controller-url https://planet.example.com `
  --planet-relay-endpoint 203.0.113.10:51820
```

反向代理把 `https://planet.example.com` 转发到 `http://127.0.0.1:51822`。不要把 `51822/TCP` 对公网开放，只开放反向代理的 HTTPS 端口。

## 明文开发模式

未配置 TLS 时，控制器只允许绑定回环地址。确实需要在隔离测试网中监听非回环地址时，必须显式确认风险：

```powershell
meshlake-controller.exe `
  --bind 192.168.1.10:51822 `
  --allow-insecure-public-http
```

此模式会在终端输出警告。它会明文传输管理令牌、入网响应和网络 PSK，不得用于公网、共享 Wi-Fi 或任何不可信网络。

## 当前边界

- 未携带私有 CA 的网络继续使用系统/WebPKI 信任链；携带私有 CA 的网络只信任被邀请链接钉扎的 PEM CA 集合。
- 原生 TLS、证书/私钥参数组合、非回环明文拒绝和私有 CA 信任路径已通过工作区编译与自动测试；跨主机原生 HTTPS 部署和真实公网环境仍待验证。
- Root 和 Relay 仍使用各自经过签名认证的 UDP 协议；本页的 TLS 只保护控制器 HTTP API。
