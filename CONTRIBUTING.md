# 参与 MeshLake 开发

感谢参与 MeshLake。当前项目优先开发无界面的 Windows/Linux 核心、协议安全、NAT 穿透和可靠中继；GUI 不是核心功能的依赖。

## 开发要求

- 使用稳定版 Rust。
- 修改后运行 `cargo fmt --check` 和 `cargo test --workspace`。
- 不要提交 `target`、`dist`、IDE 工作区、控制器状态、设备身份、管理员令牌或真实邀请链接。
- 协议变更应包含单元测试、兼容性说明和安全边界说明。
- 中文文档是项目正式文档的一部分，相关功能变化需要同步更新。

## 提交建议

一个提交尽量只处理一个明确问题。提交信息使用简洁的祈使句，例如：

```text
Add signed membership revocation manifest
Fix relay registration replay handling
```

提交贡献即表示你同意按照项目根目录的 Apache License 2.0 授权该贡献。仓库中的 Wintun 预编译文件适用其自身许可证，不属于 MeshLake 的 Apache-2.0 授权范围。
