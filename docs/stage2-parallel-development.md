# 阶段 2 主线合并与安全审查

阶段 2 于 2026-08-02 从 `main@8ba37d9` 启动三个独立 Codex worktree，主线按“安全状态备份 → 签名 DNS/自定义路由 → 会话可观测/系统测试”的顺序审查和合并。各分支未连接用户服务器或虚拟机，也没有修改 GUI 或会话加密格式。

## 已合并内容

### 安全状态备份

- agent/controller 共用版本化 Argon2id + XChaCha20-Poly1305 备份格式。
- 隐藏终端口令或显式 `--password-stdin`，不接受口令命令行参数。
- 全程持有 `StateFileLock`，默认拒绝覆盖，覆盖前完整验证。
- Windows 恢复后重新写入 DPAPI；Linux 保持 `0600`。
- 主线审查发现 Unix 不存在父目录中的 `missing/../state` 可绕过保留路径比较；修复后统一解析 `.`、`..`、既有组件与符号链接，并使用解析后的路径实际读写。

主线提交：`1ba65b6`、`6f846ca`。

### 签名 DNS 与自定义路由

- 新增 `NetworkPolicyManifest`、IPv4/IPv6 最长前缀、split-DNS/search domain 与 Windows/Linux 平台事务。
- 策略联合绑定钉扎控制器、当前授权清单和网关成员证书；默认路由被拒绝。
- 主线审查阻止了策略签发时自动向证书追加 `allowed_routes` 的隐式扩权，改为管理员显式授权端点。
- 主线审查补齐网关 LAN 返回流量验证，并要求平台 rollback 无法确认时关闭适配器数据面。

主线提交：`f4147dd`、`e3cc01c`。

### 会话可观测与系统测试框架

- 新增 `/v1/sessions` 和 `meshlake-cli sessions [--json]`，输出按 `(NetworkId, DeviceId)` 隔离并稳定排序。
- 只暴露会话状态、路径、年龄、队列与安全计数；不暴露密钥、PSK、握手包、端点或数据内容。
- transport revision、授权或身份变化会清除旧安全上下文；自然过期只保留最多五分钟的净化 tombstone。
- 新增 Windows/Linux 离线系统场景计划：双栈直连、直连转 Relay、Root/Relay 故障切换、吊销与 daemon 重启。
- 主线审查发现 `encrypted_packets_sent` 原先由已消耗序列号推导，会把本地发送失败也计为成功；修复后序列号仍单调消耗，计数仅在本地 UDP `send_to` 成功时增加。

主线提交：`d95223b`、`486adea`。

## 已保持的安全边界

- 成员证书、钉扎控制器、授权 epoch、网络密钥 epoch、成对会话、重放窗口和 Planet/Root/Relay 隔离未被绕过。
- 普通单元测试不依赖公网、管理员权限或外部服务器。
- `0.0.0.0/0`、`::/0` 和出口节点仍不属于阶段 2。
- 会话 API 与系统测试框架不包含真实凭据、用户服务器地址或一次性邀请链接。

## 剩余运行风险

- 尚未在提权真实 Windows/Linux 主机上执行路由/DNS 部分失败、rollback 失败、adapter shutdown 和异常断电恢复测试。
- 系统测试框架当前只验证场景与生成离线执行计划，不执行 SSH、WinRM、VM 或云操作。
- 网关主机的 IP forwarding、LAN 防火墙与可选 NAT 仍由管理员负责。
- Linux 正式状态仍依赖 `0600`，尚未接入 Secret Service/TPM。
- 备份采用整文件内存处理，异常巨大的不可信文件可能造成内存压力。

## 主线质量门禁

每次合并后运行定向测试；全部合并后统一运行：

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo build --workspace --release --locked
```

此外验证系统场景文件、执行敏感信息扫描，并通过 GitHub Actions 的 Windows/Linux CI。真实跨主机验收需用户单独授权测试环境后再执行。
