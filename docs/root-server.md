# MeshLake Root 服务器（`meshlake-root`）

`meshlake-root` 是 Windows/Linux 通用的 UDP 节点发现与 NAT 协调服务：它验证成员注册并交换同网络对等候选地址；它不是控制器，也不转发虚拟网络数据或持有网络流量密钥。加密数据中继由 `meshlake-relay` 提供。

默认端口：

- `51819/UDP`：Root 注册、发现与候选交换；
- `51820/UDP`：Relay 加密数据中继；
- `51822/TCP`：控制器 HTTPS API（原生 TLS 或回环监听后的 HTTPS 反向代理）。

## Root 服务身份与文件保护

Root 第一次启动会生成持久化 Ed25519 服务身份。它有稳定的 Root UUID（`root_id`）和私钥；Planet V3 只发布 UUID 与公钥，绝不发布身份文件。

```powershell
meshlake-root.exe `
  --identity-file C:\ProgramData\MeshLake\root-identity.json `
  --print-identity
```

身份文件包括私钥，不能复制到 Planet、仓库、日志、命令行参数或备份以外的受保护介质。实现对身份状态和中断原子替换留下的 `.bak` 恢复文件均失败关闭：

- **Windows**：Root/Relay 身份使用机器级 DPAPI 保护；当前格式的明文身份文件或未受保护备份会被拒绝，不会静默升级。
- **Unix/Linux**：文件必须为 `0600`（没有组/其他权限），并且拥有者必须是运行服务的有效 Unix 用户；权限宽松或所有者不符会被拒绝。
- 路径必须是安全的真实路径；符号链接/重解析点、错误服务种类、错误服务 ID、未知 schema 或不安全备份均不被接纳。

默认身份路径遵循 `MESHLAKE_STATE_DIR`，否则 Windows 为 `%LOCALAPPDATA%\MeshLake\root-identity.json`，Unix 为 `$XDG_STATE_HOME/meshlake/root-identity.json` 或 `~/.local/state/meshlake/root-identity.json`。生产部署建议显式指定仅服务帐户可访问的路径，例如 `C:\ProgramData\MeshLake` 或 `/var/lib/meshlake`。

## Planet V3 配置与双签轮换

把 Root 身份中的公开字段写入控制器的 Planet V3：

```powershell
meshlake-controller.exe `
  --bind 127.0.0.1:51822 `
  --planet-controller-url https://planet.example.com `
  --planet-root-identity '<ROOT_UUID>@<CURRENT_PUBLIC_KEY_B64>@203.0.113.10:51819' `
  --planet-relay-identity '<RELAY_UUID>@<RELAY_PUBLIC_KEY_B64>@203.0.113.10:51820'
```

轮换时先创建与 current **相同** `root_id` 的 next 身份。下面的 `--print-identity` 命令只生成/检查公开字段并退出，不会启动服务：

```powershell
meshlake-root.exe `
  --identity-file C:\ProgramData\MeshLake\root-current.json `
  --transition-identity-file C:\ProgramData\MeshLake\root-next.json `
  --print-identity
```

将输出的 current/next 公钥和明确的 Unix 秒窗口发布为：

```text
<ROOT_UUID>@<CURRENT_KEY_B64>@<NEXT_KEY_B64>@<NOT_BEFORE>@<NOT_AFTER>@203.0.113.10:51819
```

客户端在 `NOT_BEFORE` 前只接受 current，在 `[NOT_BEFORE, NOT_AFTER]` 内要求 current+next 两个签名，窗口结束后则拒绝仍处于 transition 状态的策略。Root 本身不会读取这些时间戳：只要启动参数含 `--transition-identity-file`，它就一直双签。因此实际切换必须按受控维护流程执行：

1. 先发布带未来 `NOT_BEFORE` 的 transition Planet，并保持 Root 仅以 current 身份运行，让客户端刷新策略；
2. 到达 `NOT_BEFORE` 后，重启 Root 并加入 `--transition-identity-file`，在窗口内双签；
3. `NOT_AFTER` 前安排切换，把 next 文件作为唯一 `--identity-file`、移除 transition 参数，并发布新的 stable 策略，同时撤销旧公钥；
4. 由于旧 transition 策略要求双签，而新 stable 策略只接受 next，切换期间可能出现有界的注册/健康状态中断，必须预留客户端 Planet 刷新时间并监控收敛，不能宣称自动无缝轮换。

stable/revoked 描述符为：

```text
<ROOT_UUID>@<NEXT_KEY_B64>@<OLD_CURRENT_KEY_B64>@203.0.113.10:51819
```

Relay 使用同样的流程与 `--transition-identity-file`、`--print-identity`，但其身份类型必须为 Relay，不能共用 Root 身份文件；当前 Relay CLI 即使只打印身份也仍要求提供 `--controller-public-key-base64`。Planet V3 具体信任与刷新规则见 [`planet.md`](planet.md)。

## 启动 Root

从可信渠道取得控制器公钥，然后启动公开 UDP 监听：

```powershell
meshlake-root.exe `
  --bind 0.0.0.0:51819 `
  --identity-file C:\ProgramData\MeshLake\root-identity.json `
  --controller-public-key-base64 <控制器公钥Base64>
```

可重复 `--controller-public-key-base64` 以服务多个可信控制器。Root 只接受其成员证书和授权清单可由这些控制器验证的注册。

持久化配置与启动项：

```powershell
meshlake-root.exe `
  --bind 0.0.0.0:51819 `
  --identity-file C:\ProgramData\MeshLake\root-identity.json `
  --controller-public-key-base64 <控制器公钥Base64> `
  --write-config C:\ProgramData\MeshLake\root.json

meshlake-root.exe --config C:\ProgramData\MeshLake\root.json run
meshlake-root.exe --config C:\ProgramData\MeshLake\root.json autostart install
meshlake-root.exe autostart status
```

在 Linux 使用相同 JSON 配置，再通过 systemd 集成：

```bash
sudo meshlake-root --config /etc/meshlake/root.json autostart install
meshlake-root autostart status
sudo meshlake-root --config /etc/meshlake/root.json autostart uninstall
```

systemd 单元会限制文件系统写入范围，所以 `identity_file` 必须位于配置文件所在目录内。运行服务的帐户必须拥有身份文件，且该文件保持 `0600`。

## 注册协议与失败关闭

客户端以当前 UDP 映射向 Planet 中每个 Root 发送设备签名注册。Root 对每个注册验证：成员证书、设备公钥与设备 ID、控制器签名授权清单、网络密钥 epoch、到期时间、候选地址、nonce 防重放与时钟偏差。

对于 Planet V3，客户端使用**目标绑定注册 V2**（target-bound registration V2）；注册还必须绑定目标 **Root** 服务种类和 Planet 中的 `root_id`。Root 返回由自身服务身份签名的响应，客户端仅在以下条件全部成立后才使用响应：

1. 请求 nonce 仍存在且未超时；
2. UDP 源端点与原始目标 Root 相同；
3. Root 仍属于该网络当前 Planet，公钥、服务 ID 和轮换策略均一致；
4. 响应符合 current/next 双签规则（如在轮换窗口内）。

通过验证的 `Registered` 响应才会刷新该 `(network, endpoint)` 的 Root 健康状态、观察到的地址和同网络对等候选。跨网络、跨 Root、重放、过期或签名失败响应没有副作用。Root 将网络内对等注册保留约 90 秒，客户端会周期性重新注册；多 Root 不复制内存状态，客户端向全部已配置 Root 注册以获得故障切换。

Root 可能携带控制器签名的 authorization epoch hint，但它只通知客户端执行完整刷新，绝不直接更改本地授权或信任状态。

客户端的 Root/Relay 注册以 `(network, endpoint, kind)` 独立退避：约 20 秒起、带确定性抖动、最高 120 秒。某个成功 Root 响应只重置该 Root 目标；不会将一个网络或 Relay 的成功误作另一目标健康。

## Legacy V1 仅限显式迁移

`meshlake-root` 默认 `allow_legacy_registration=false`，拒绝 legacy V1 注册。在已经计划退出的 V1/V2 Planet 迁移窗口内，才可显式启动：

```powershell
meshlake-root.exe `
  --bind 0.0.0.0:51819 `
  --identity-file C:\ProgramData\MeshLake\root-identity.json `
  --controller-public-key-base64 <控制器公钥Base64> `
  --allow-legacy-registration
```

此开关只允许短期兼容旧注册，不降低 Planet V3 的验证要求，也不能让未签名旧响应成为 V3 健康证据。迁移完成后应删除该参数（或配置中的同名字段）并重新启动；旧证书若没有设备公钥绑定，成员必须使用新邀请链接重新加入。
