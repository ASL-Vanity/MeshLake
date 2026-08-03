# 阶段 3 并行开发合并与审查记录

**记录日期：**2026-08-03

**范围：**阶段 3 的 secure operations、system executor、Root/Relay hardening 三条并行线，以及主线集成收尾。

**外部连接状态：**本审查和现有执行器验证均未连接外部主机、VM、云资源、SSH 或 WinRM 端点。

## 合并结果

| 线 | 提交 | 合并结论 |
| --- | --- | --- |
| Secure operations | `3216561` `secure operational secret inputs`；`d523b95` `add fail-closed Linux state key providers`；`75720e9` `close secure operations downgrade paths` | 已合入。秘密不再必须出现在 argv；Linux provider 不能因错误静默退回明文。 |
| System executor | `50e588e` `test: add gated system scenario executor`；`c695391` `fix: bind system execution authorization` | 已合入。默认保持计划/校验；执行必须显式请求，且授权结果绑定到经审查的场景、目标和 backend。 |
| Root/Relay | `41213e4` `Harden root relay authorization convergence`；`20fba37` `Harden service identity and Planet convergence`；`177d648` `Harden root relay trust convergence`；`1c9f992` `Fail closed legacy registration recovery`；`bbf8f45` `Reject parent directory state paths` | 已合入。授权、服务身份、Planet 收敛和身份文件恢复按失败关闭原则收紧。 |
| Main integration fixes | `5f91006` `Fix stage three integration test support`；`0da69c0` `Keep live Planet state on persistence failure` | 已单独提交。前者恢复 test-only 状态写入辅助函数；后者把周期 Planet 刷新改为 candidate 落盘成功后才替换 live state。 |

## 审查退回问题与闭环

### Secure operations

1. 初始秘密输入改造后仍需逐项封住兼容和降级路径，不能让非交互输入、错误 provider 或旧状态格式回落到明文，或通过错误/日志泄露可恢复片段。该问题由 `75720e9` 的补充收紧闭环。
2. Linux state key 必须来自显式 provider（systemd credential 或受限外部 key file），拒绝权限过宽、错误长度、错误 key、与 state 同目录的 key 文件、篡改 envelope、未知版本及未经授权的明文迁移；失败时不得静默降级。
3. 秘密文件、token、join link 和首次初始化输出需要保持最小暴露：同一秘密只能采用一种输入来源，inventory/日志/错误信息不得保存密码、token、私钥、PSK 或完整邀请链接。

### System executor

1. 执行器必须默认零副作用：没有 `--execute` 时只做声明式场景和 inventory 校验/规划，不启动远端连接或破坏性动作。
2. 第一版执行门禁之后，审查要求修复“验证过的授权对象可与后续场景、目标或 backend 脱钩”的风险；`c695391` 将执行授权绑定到场景摘要、角色目标、所需 capabilities 和 backend，并拒绝伪造、篡改或错配的授权。
3. `--execute` 还要求恰好一个场景、schema v2 inventory、UUID v4 `lab_id` 的逐字确认、无通配符且精确匹配的可丢弃目标 allowlist。所有破坏性动作都要有超时、反向顺序 cleanup 和明确的 cleanup 目标绑定；主动作失败也继续清理，cleanup 失败单独报告。
4. 当前 backend 是 simulated backend。它不构成 SSH/WinRM、真实适配器、路由、DNS、服务启停或跨主机网络的验收证据。

### Root/Relay 与授权收敛

1. Relay 注册/健康确认不能只依赖源地址和随机 nonce。实现改为验证与 network、device、Relay identity、请求 nonce、endpoint 和短时有效期绑定的服务身份签名，并保持授权 epoch/签名清单为最终边界。
2. Planet 收敛、服务身份轮换、旧身份吊销、Root/Relay 故障恢复、乱序响应、过期 epoch、重放、时钟偏差和服务重启必须失败关闭；不能把“已收到提示”误当成已授权或无限延长旧授权。
3. 旧注册恢复和身份 state 不能因可读 JSON 或旧 schema 被自动接纳。Windows 当前 schema identity 必须是 DPAPI 保护；Unix 身份必须是当前 owner 的普通 `0600` 文件；错误 purpose/kind/service ID、明文/legacy/未知 schema、权限过宽和异常大内容都拒绝。
4. 身份恢复必须先以 no-follow 方式捕获 `.bak` bytes 并验证其 metadata、保护和内容，再安装该已验证字节；符号链接、Windows reparse point 和任何含 `..`（`ParentDir`）的身份/备份路径都拒绝。此处不把 agent/controller 的 Linux state-key provider 支持外推为 Root/Relay 已使用 systemd credential provider：后者尚未接入。
5. 文档复核发现周期 Planet 刷新曾先修改内存、再写受保护状态，落盘失败会留下未持久化的 live trust。`0da69c0` 改为 clone candidate、验证并应用更新、成功落盘后再原子替换 live state；失败时不触发 transport reload，并有真实 refresh 路径回归测试。

## 安全边界

- `main` 上的离线 Rust/Python 单元测试与 simulated executor 只能证明代码路径和门禁语义，不能证明远端可达性、真实服务账户权限、DPAPI 跨身份行为、systemd 配置、路由回滚或数据面互通。
- 无明确授权时，不创建真实 inventory，不传入外部主机名/IP，不运行 SSH/WinRM，不启动网络适配器，也不改动路由、DNS、服务、NAT 或防火墙。
- inventory 和结果 artifact 只允许非秘密连接引用、提交哈希、平台版本、场景结果、耗时、脱敏日志及计数器；不得包含地址、账户、密码、token、join link、私钥或 PSK。
- Windows DPAPI 的机器范围不是访问控制替代品；ACL 和服务账户边界仍然必要。Unix `0600` + owner 保护也不等同于防御 root 或能读取服务进程内存的攻击者。

## 定向验证清单

以下项目是本次合并审查应保持的定向门槛；执行时使用为本工作指定的 `CARGO_TARGET_DIR`，不提交目标目录。

### Secure operations / state protection

- `cargo test -p meshlake-core state_protection --locked`
- `cargo test -p meshlake-core service_identity --locked`
- `cargo test -p meshlake-cli --locked`
- `cargo test -p meshlake-controller --locked`
- `cargo test -p meshlaked --locked`
- 覆盖：秘密来源互斥、敏感输入/错误脱敏、Linux provider fail-closed、明文迁移显式授权、错误 key/权限/同目录 key 拒绝、DPAPI identity、Unix `0600`/owner、no-follow/reparse、captured-bytes backup recovery、明文/legacy identity 拒绝和 `ParentDir` 拒绝。

### System executor

- `python tests/system/test_runner.py`
- `python tests/system/runner.py --validate-all`
- 仅使用示例或本地测试 JSON 验证 `--execute` 的拒绝分支：缺失确认、错误 `lab_id`、通配符/不精确 allowlist、秘密 inventory 字段、场景篡改、授权对象错配、无 cleanup 与 cleanup target 错配。
- 如验证 simulated 执行，必须显式传入一个测试 scenario、schema v2 inventory、完整精确 allowlist 和匹配的 UUID v4 `--confirm-lab-id`；输出应显示 simulated backend，不能当作远程执行记录。

### Root/Relay

- `cargo test -p meshlake-core authorization --locked`
- `cargo test -p meshlake-core relay --locked`
- `cargo test -p meshlake-core root --locked`
- `cargo test -p meshlake-core service_identity --locked`
- `cargo test -p meshlaked transport_health --locked`
- 覆盖：伪造/重放/跨 Relay 确认、旧 epoch、吊销身份、Planet 收敛、服务身份轮换、legacy 恢复拒绝、身份类型/服务 ID/purpose 绑定和安全路径恢复。

## 全量验证清单

主线集成收尾后，以同一工作区运行：

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo build --workspace --release --locked
git diff --check
python tests/system/test_runner.py
python tests/system/runner.py --validate-all
```

2026-08-03 的本地结果：上述 Rust 门禁全部通过，workspace 共 229 项测试通过；Python `unittest` 共 15 项通过，`run.ps1 -ValidateAll` 校验 10 个场景，10 个场景的 gated simulated 执行也全部通过，均报告未进行网络访问且 cleanup failure 为 0。敏感信息扫描未发现真实密码、token、私钥、PSK、Bearer 凭据或可用 join link。

同时审查：

- `git status --short`：除本记录所覆盖的文档收尾外，不应混入无关变更；
- 敏感信息扫描：argv、日志、错误、fixtures、inventory、文档和测试输出不得出现真实 token、密码、私钥、PSK 或 join link；
- Windows/Linux CI 的 test、release build、packaging 与 artifact 上传（若 CI 已配置）必须独立通过；CI 不得隐式启动真实执行器或连接外部主机。

## 未完成的真实验收与风险

真实 Windows/Linux 跨主机验收尚未获得用户授权，因而**未执行**。待授权后，用户必须提供可丢弃目标的明确清单、允许动作、连接引用和一次性 `lab_id` 确认；届时至少覆盖：

| 维度 | 授权后最低验收 |
| --- | --- |
| 主机组合 | Windows→Windows、Linux→Linux、Windows→Linux |
| 地址与数据路径 | IPv4、IPv6、双栈；直连、直连失败转 Relay、Relay 故障切换 |
| 控制面 | Root 故障恢复、Controller TLS、授权刷新、成员吊销、身份轮换/撤销 |
| 生命周期 | daemon/service 重启、升级/回滚、DPAPI/服务账户访问、Linux `0600`/owner、异常替换后的 identity backup 恢复 |
| 网络策略 | 路由/DNS 部分失败、回滚失败后的适配器关闭，以及最终清理 |

剩余风险不是“代码已知绕过即被接受”，而是未在真实权限、真实服务管理器、实际网络栈和多主机时钟/故障条件下测量的运行风险。特别是：Linux Root/Relay identity 目前未接入 systemd credential provider；system executor 目前没有真实 SSH/WinRM backend；DPAPI 与 Windows SYSTEM/服务账户的互操作、systemd 单元配置和异常断电恢复仍只能在授权环境中确认。
