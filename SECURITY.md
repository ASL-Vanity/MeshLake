# MeshLake 安全策略

MeshLake 仍处于早期开发阶段，当前版本不应直接用于保存高价值凭据或承载关键生产网络。

## 报告安全问题

请不要在公开 Issue 中披露尚未修复的漏洞、私钥、管理员令牌或可用的入网邀请链接。如果仓库已启用 GitHub Private Vulnerability Reporting，请使用 GitHub Security 页面中的 **Report a vulnerability** 入口提交私密报告：[`https://github.com/ASL-Vanity/MeshLake/security/advisories/new`](https://github.com/ASL-Vanity/MeshLake/security/advisories/new)。如果该入口不可用，说明当前仓库尚未提供这条私密报告通道；请先通过维护者 GitHub 个人资料中经过核验的私密联系方式建立联系，不要改为在公开 Issue 中发送漏洞细节。

报告中建议包含：受影响版本、复现步骤、攻击前提、实际影响以及可行的缓解建议。请使用测试网络和虚构凭据复现，不要提交真实用户数据。

## 当前已知边界

- 控制器原生 TLS、非回环纯 HTTP 拒绝和私有 CA 信任路径已通过工作区编译与自动测试；跨主机原生 HTTPS 部署仍待验证，公网部署仍需要访问控制。
- 私有 CA 可以随可信邀请链接钉扎并按网络保存；带私有 CA 的控制器请求不会继续信任系统根证书。邀请链接同时含有一次性令牌，仍属于敏感凭据。
- Windows agent/controller 状态已接入机器级 DPAPI，并已通过工作区编译、明文迁移和状态保护自动测试；Linux 当前依赖 `0600` 文件权限，其原生权限行为仍需在 Linux 环境验证。TPM、Linux Secret Service 和安全跨机器导出尚未接入。
- 当前 CLI 会把管理员令牌、一次性入网令牌或完整邀请链接作为命令行参数接收，尚无标准输入或令牌文件接口；这些值可能进入进程参数、shell 历史或终端日志。控制器首次创建状态时也会把初始管理员令牌写入标准错误，因此首次初始化必须在受控终端完成。
- 在线成员吊销使用约 20 秒刷新和 90 秒授权租约；它不是零延迟推送，失陷客户端在旧签名授权清单到期前仍存在有限窗口。
- Windows/Linux 跨主机真实数据面尚需进一步运行验证。

项目会在修复可用后协调披露安全问题。
