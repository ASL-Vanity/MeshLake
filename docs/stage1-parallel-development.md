# 阶段 1 树状并行开发

阶段 1 在同一个已验证主干上使用三个独立 Git worktree。主任务负责公共接口、代码审查、合并、全工作区回归和 CI；各分支不得绕过已签名的成员资格、Planet 或成对会话安全边界。

## 第一轮完成状态（2026-08-02）

- 数据面：Linux TUN 会话只在接口成功启用后发布；IPv4/IPv6 前缀、地址归属、同网络去重和跨网络重复地址均严格校验。
- Planet/Relay 高可用：Root 与 Relay 健康状态按 `(NetworkId, SocketAddr)` 隔离，Root 事务严格绑定网络，共享端点采用保守聚合，首选节点失效后可选择健康备用节点。
- NAT 穿透：Relay 只传播设备签名注册中与实际观察公网 IP 一致的映射候选；未签名、非法、跨网络或超量候选不会进入成员目录。
- Relay 活性事务：注册确认回显签名 nonce，并绑定网络、设备、目标 Relay 与 30 秒有效期；错误、过期和重放确认不会刷新健康状态。
- 适配器事务：入网、退网、授权刷新、激活与关闭共用生命周期锁；新建会话配置失败会回滚，shutdown 开始后不能重新激活。
- 本地合并门禁：格式检查、全工作区 `check`、测试及 release 构建均通过。真实 Linux TUN、跨 NAT 和公网故障切换仍按下文作为独立运行验收。

## 分支与文件所有权

### `stage1/data-plane`

- 主要文件：`crates/meshlaked/src/adapter.rs`、`adapter/linux.rs` 和数据面纯测试。
- 第一轮目标：Linux TUN 激活失败回滚、IPv4/IPv6 前缀严格校验、可测试的 `ip` 命令生成。
- 不修改 Root、Relay、Planet、会话加密或控制器协议。

### `stage1/planet-failover`

- 主要文件：新建的运行时健康/选择模块及最小的 `meshlaked/src/main.rs` 接入点。
- 第一轮目标：健康状态按 `(NetworkId, SocketAddr)` 隔离；主节点过期后确定性选择健康备用节点。
- 不修改 NAT 映射实现、平台适配器或数据包加密格式。

### `stage1/nat-traversal`

- 主要文件：`crates/meshlake-relay/src/main.rs`。
- 第一轮目标：Relay 验证并传播成员注册中签名携带的端口映射候选，使没有 Root 的部署也能利用 PCP、NAT-PMP 或 UPnP 映射。
- 不修改平台适配器、控制器状态或会话密钥格式。

## 冻结接口

- NAT 层只产生候选更新，不接触成员私钥、网络密钥或数据包密文。
- 路径健康只能由已验证的 Relay ACK、Root 响应或已知直连候选响应更新。
- 健康、事务和选择状态必须按网络隔离；相同公网端点不能在不同网络之间共享健康结论。
- 数据面必须使用本机已分配的源地址唯一确定虚拟网络；重叠或歧义时失败关闭。
- 会话 ID、序号、重放窗口、成员证书和加密数据格式在本阶段保持不变。
- transport revision 变化后必须丢弃旧 generation 的事务、候选和健康状态。

## 合并门禁

每个分支至少需要：

1. `cargo fmt --all -- --check`
2. 对应 crate 的 `cargo test --locked`
3. `git diff --check`
4. 主任务审查安全边界和失败关闭路径

合并到 `main` 后统一运行：

```powershell
cargo check --workspace --locked
cargo test --workspace --locked
cargo build --workspace --release --locked
```

真实 Linux TUN、跨 NAT 和公网故障切换测试属于后续运行验收，需要单独的测试环境；普通单元测试不得要求 root、`CAP_NET_ADMIN` 或外部公网服务器。
