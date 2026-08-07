# MeshLake Planet（V4）

Planet 是由控制器 Ed25519 私钥签名的**每网络**引导清单，而不是数据中继。它发布控制器 URL、Root、Relay 与可选 STUN，并把这些服务与该网络已钉扎的控制器公钥绑定。客户端先验证 Planet 签名与控制器 URL，再把经验证的配置原子保存到该网络控制面；不同 Planet 的网络绝不共享信任或健康结论。

Planet V3 在 V2 的多 Root/多 Relay 排序基础上，强制为每个 Root、Relay 发布稳定的服务 ID 和服务身份策略。Planet V4 在此基础上可发布 TLS Relay：每项绑定既有 Relay 的 `service_id`、数值 TCP 端点、SNI 与叶证书 DER 的 SHA-256 指纹。V3/V4 缺少服务身份、服务 ID 不匹配、签名不完整、已撤销密钥或轮换窗口无效，均失败关闭。

> MeshLake 保持无 GUI 优先：正常加入可通过一次性 join link；Planet 的手工设置命令仅适用于迁移或受控运维。

## 客户端验证、刷新与到期

- 客户端仅信任入网材料或本地显式配置中已钉扎的控制器公钥；Planet 自称的公钥不是信任来源。
- 每个已加入网络约每 **60 秒**刷新一次 Planet，使用该网络保存的控制器 URL、私有 CA（如有）和钉扎公钥。
- 刷新前验证签名、有效期、控制器 URL、V3/V4 服务身份、TLS Relay 证书指纹以及版本、`issued_at` 与语义摘要的单调性。拒绝版本回退、`issued_at` 回退，或相同版本/时间却改变语义的清单。
- 下载、验证或受保护状态落盘失败时，保留最后一次已验证的配置，不把候选配置部分写入内存或磁盘。
- 若最后一次已验证的 Planet 到期，该网络的 Root、Relay 和 Planet STUN 配置会被移出传输配置；已接受过 Planet 的网络不会回退使用旧全局/手工端点。

授权 epoch hint 只是控制器签名的“可能有更新”提示：只有它针对本网络、通过钉扎控制器验证且 epoch 更高时，才触发完整的已签名授权刷新。hint 本身绝不安装权限、密钥、Root、Relay 或 Planet。

## V3 服务身份与轮换

每个 Root/Relay 都有独立的长期 Ed25519 服务身份：

- `service_id` 在轮换中保持不变；Root 身份不能作为 Relay 身份使用，反之亦然。
- Planet 发布 `current_public_key`；轮换期间还发布 `next_public_key`、`NOT_BEFORE`、`NOT_AFTER`。
- 客户端在 `NOT_BEFORE` 之前只接受 **current** 签名，在 `[NOT_BEFORE, NOT_AFTER]` 内要求每个 Root 响应或 Relay ACK 按顺序同时携带 **current 与 next** 签名；重复、缺失或多余签名都会被拒绝。`NOT_AFTER` 之后，仍声明轮换中的 Planet 策略整体失败关闭。
- Root/Relay 进程只要配置 `--transition-identity-file` 就会持续双签，并不会自行按 Planet 时间窗切换。因此运维方必须在 `NOT_BEFORE` 前保持服务仅使用 current，在进入窗口后才启用 transition 身份；退出窗口时，把 next 身份提升为唯一 current、移除 transition 参数，并同步发布 stable/revoked Planet。该切换需要受控维护与客户端刷新收敛，不能把它描述成服务端自动、无缝轮换。
- 完成轮换后，把 next 提升为 current，并在 Planet 中把旧密钥列入 `revoked_public_keys`，防止旧服务身份重新出现。

控制器使用以下描述符发布 V3 身份（端点必须是数值 `IP:PORT`）：

```text
SERVICE_UUID@CURRENT_KEY_BASE64@IP:PORT
SERVICE_UUID@CURRENT_KEY_BASE64@NEXT_KEY_BASE64@NOT_BEFORE@NOT_AFTER@IP:PORT
SERVICE_UUID@CURRENT_KEY_BASE64@REVOKED_OLD_KEY_BASE64@IP:PORT
```

相应启动参数为 `--planet-root-identity` 与 `--planet-relay-identity`。不要与旧的 `--planet-root` 或 `--planet-relay-endpoint` 混用；后两者产生的是 V1/V2 兼容 Planet，不能满足 V3 服务身份验证。

```powershell
meshlake-controller.exe `
  --bind 127.0.0.1:51822 `
  --planet-controller-url https://planet.example.com `
  --planet-root-identity '<ROOT_UUID>@<ROOT_CURRENT_B64>@<ROOT_NEXT_B64>@<NOT_BEFORE>@<NOT_AFTER>@203.0.113.10:51819' `
  --planet-relay-identity '<RELAY_UUID>@<RELAY_CURRENT_B64>@<RELAY_NEXT_B64>@<NOT_BEFORE>@<NOT_AFTER>@203.0.113.10:51820' `
  --planet-stun stun.example.com:3478
```

服务的 `--print-identity` 输出仅包含可公开发布的 ID 和公钥；不得把身份文件、私钥或输出之外的秘密放进 Planet、命令历史、Issue 或日志。

## V3 注册与响应验证

客户端向 Root/Relay 发送成员证书、设备签名、当前授权清单、随机 nonce 和候选地址。对 Planet V3，客户端使用**目标绑定注册 V2**（target-bound registration V2），并明确绑定：

- 目标服务种类（Root 或 Relay）；
- Planet 中的目标 `service_id`；
- 网络、设备、成员证书、授权清单和本次 nonce。

因此有效的 Root 注册不能转发给 Relay，反之亦然；错误网络、设备、服务 ID、过期授权、吊销成员、落后网络密钥 epoch、重放 nonce 或未钉扎身份都会被拒绝。

Relay 的 V3 `RELAY_REGISTER_ACK` 是服务身份签名的确认，绑定网络、设备、Relay ID、请求 nonce、观察到的 UDP 源端点与短有效期。客户端仅在 ACK 与仍在等待的本地事务、目标 Relay、Planet V3 身份和时间窗口全部一致时，将该 `(network, endpoint)` 标为可用。旧的未签名 ACK 不能为 V3 Relay 建立健康状态。

Root 响应同样带服务身份签名。客户端仅接受匹配仍在等待的 nonce、发出请求的 Root 端点、该网络 Planet 中的 Root 公钥/身份和事务时限的响应；验证成功后才使用观察地址、对等候选与授权 hint。响应中的任意其他字段不会成为新的信任根。

Root/Relay 注册重试按 **`(network, endpoint, kind)`** 独立跟踪，使用带确定性 0–25% 抖动的指数退避（约 20 秒起、最高 120 秒）。一个端点/服务成功只重置它自己的失败计数，不会掩盖其他 Root、Relay 或网络的故障。

## 安全的手工 Planet 配置

正常加入请使用管理员经可信渠道交付的一次性 join link。需要显式配置时：

```powershell
meshlake-cli.exe planet set `
  --manifest https://planet.example.com/v1/planet `
  --controller-public-key-base64 <可信渠道获得的控制器公钥>
```

私有 CA 必须在子命令之前提供，并会保存到对应网络的控制面：

```powershell
meshlake-cli.exe `
  --tls-ca-certificate C:\MeshLake\tls\root-ca.pem `
  planet set `
  --manifest https://planet.example.internal/v1/planet `
  --controller-public-key-base64 <可信渠道获得的控制器公钥>
```

不要把纯 HTTP 控制器直接暴露到公网；生产环境使用原生 HTTPS 或仅监听回环地址的控制器加 HTTPS 反向代理。

## V1/V2 迁移边界

Root 与 Relay 默认**拒绝** legacy V1 注册。仅当迁移一个仍使用 V1/V2 Planet 的旧网络时，才可在受控、短期维护窗口以 `--allow-legacy-registration` 显式启用服务端兼容；完成迁移后立即移除该参数并重新启动服务。

该开关不是降级 V3 的方式：V3 客户端仍要求 target-bound 注册及签名服务响应；没有 V3 身份的服务不能被 V3 Planet 视为健康。旧成员证书不含新协议所需的设备公钥绑定时，应退出网络并使用新邀请链接重新加入。

Root 部署、身份文件保护和轮换示例见 [`root-server.md`](root-server.md)。
