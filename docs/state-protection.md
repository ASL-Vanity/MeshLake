# MeshLake 状态文件保护

MeshLake 的状态文件包含长期设备身份、控制器签名私钥、管理员令牌、虚拟网络 PSK、成员证书和控制面信任配置。它们不能按普通配置文件对待。

## Windows

Windows 上的 `meshlaked` 和 `meshlake-controller` 会先把完整状态序列化，再使用机器级 Windows DPAPI 加密；正常运行时的正式状态文件只保存版本化信封和 Base64 密文。旧明文迁移在替换完成后若遭遇异常退出，可能暂时留下明文 `.bak`；下次启动仅会在主文件成功解密并通过校验后清理它。

采用机器级范围是为了让交互式管理员启动的程序和以 SYSTEM 身份运行的开机任务能够使用同一个状态文件。其安全边界是：

- 密文与当前 Windows 计算机绑定，直接复制到另一台计算机通常无法解密。
- 同一台计算机上能够读取文件的账户仍可能调用机器级 DPAPI，因此 NTFS 目录和文件 ACL 仍然重要。
- 默认 `%LOCALAPPDATA%\MeshLake` 目录应保留 Windows 的用户访问限制；使用自定义 `--state-file` 时，管理员必须限制该文件及父目录权限。
- DPAPI 返回的原始缓冲区会在释放前以 volatile 写入清零；复制到 Rust 的序列化/解密缓冲区使用 `Zeroizing`，成功和错误返回路径都会在释放前清零。运行中的对象内存仍属于受信任边界。

旧版明文 `agent.json` 或 `controller.json` 会在成功读取、完成结构迁移后自动重写为 DPAPI 信封。迁移失败时不会主动删除原文件。

## Linux

Linux 支持版本化 XChaCha20-Poly1305 状态信封。主密钥必须是 32 字节原始随机数据，并通过以下一种显式 provider 提供：

- `--state-key-systemd-credential <NAME>`：从 systemd 设置的 `$CREDENTIALS_DIRECTORY/<NAME>` 读取，适合 headless system service。
- `--state-key-file <PATH>`：从权限不宽于 `0600` 的外部受限文件读取。该文件不得与状态文件位于同一目录，避免把明文 key 和密文作为同一份状态一起复制或泄露。

systemd unit 可使用：

```ini
[Service]
LoadCredential=meshlake-state-key:/etc/meshlake-secrets/state.key
ExecStart=/usr/local/bin/meshlaked --state-file /var/lib/meshlake/agent.json --state-key-systemd-credential meshlake-state-key run
```

配置 provider 后，既有阶段 2 明文 JSON 会在完整解码和 schema 校验后原子迁移为加密信封。缺少 credential、文件权限过宽、key 长度错误、key 文件与状态同目录、错误 key、密文篡改或未知信封版本都会失败关闭；不会静默退回明文。

未配置 provider 时保留 `0600` 明文兼容模式，以便现有部署显式迁移。程序启动会输出当前等级：

- `linux-systemd-credential-envelope`
- `linux-restricted-external-key-envelope`
- `linux-0600-plaintext-compatibility`

兼容模式只依赖文件权限，不等同于静态加密。程序在读取任何既有状态前，以及每次创建临时文件和完成替换后，都会把权限收紧为 `0600`；从旧版本复制来的 `0644` 状态文件也会被修正。

当前 provider 边界不包含 TPM2 sealed key 或桌面 Secret Service。systemd credential 和外部受限 key file 都会在进程内存中短暂持有主密钥；拥有 root 权限或能够读取 provider 来源及进程内存的攻击者仍属于受信任边界之外的高权限威胁。

## 独占锁、原子写入与恢复

agent 和 controller 在恢复、读取或迁移前先锁定与状态路径对应的 `.lock` 侧边文件，并把锁持有到进程退出。这样 SYSTEM 自启动实例与管理员手动实例不能同时操作同一个状态文件；第二个实例会在任何状态写入前失败。

每次保存都会在同一目录创建唯一的 `.tmp-<UUID>` 文件，设置权限、写入完整内容并执行 `sync_all`，随后再替换正式状态：

- Windows 对既有文件使用 `ReplaceFileW` 和 write-through 标志，让新内容继承被替换文件的安全属性，并在 API 操作期间使用 `.bak`；首次创建使用 `MoveFileExW`。
- Unix 使用同文件系统的原子 `rename`，替换后同步父目录，并再次确认最终文件权限为 `0600`。

如果正式文件缺失而 `.bak` 仍存在，下次启动会在持有独占锁后恢复备份。正常成功写入会删除备份；若仅备份清理失败，已提交的新状态仍保留，并输出警告。

临时文件、锁文件和备份都必须位于访问受限的状态目录中。异常退出可能留下 `.bak` 或唯一临时文件；它们不得上传到 Issue、聊天或公开仓库。

## 备份与迁移边界

Windows DPAPI 正式状态仍然与当前计算机绑定，不能直接复制到另一台机器恢复。跨机器迁移必须使用独立的口令保护备份格式：

```powershell
# Agent：先停止正在持有状态锁的 meshlaked
meshlaked.exe --state-file C:\MeshLake\agent.json state backup D:\Backup\agent.mlb
meshlaked.exe --state-file C:\MeshLake\agent.json state restore D:\Backup\agent.mlb --force

# Controller：先停止正在持有状态锁的 controller
meshlake-controller.exe --state-file C:\MeshLake\controller.json state backup D:\Backup\controller.mlb
meshlake-controller.exe --state-file C:\MeshLake\controller.json state restore D:\Backup\controller.mlb --force
```

- 默认通过终端隐藏输入口令；导出时要求再次确认。`--password-stdin` 只从标准输入读取一行，适合受控自动化，不得把口令写入命令行参数、日志或仓库。
- 备份使用固定版本的 Argon2id 参数派生 32 字节密钥，再用 XChaCha20-Poly1305 加密完整状态。格式版本、agent/controller 类型、KDF 参数、随机 salt、nonce 均受 AEAD 认证。
- 错误口令、密文篡改、截断、未知版本、agent/controller 类型混用或解密后状态结构无效都会在覆盖正式状态前失败。
- 导出和恢复都使用现有 `StateFileLock`。默认拒绝覆盖现有备份或正式状态；只有显式 `--force` 才允许在完整验证后替换。
- 备份路径不能解析为正式状态、`.lock` 或 `.bak` 的任何 `.`、`..`、符号链接别名；实际读写使用安全解析后的绝对路径。
- Windows 恢复通过正式状态写入路径重新应用 DPAPI；Linux 恢复文件及备份文件保持 `0600`。

备份当前采用整文件内存处理。不要把来源不可信、异常巨大的文件交给恢复命令；Argon2 参数若未来调整，需要通过新的兼容格式版本演进。

## 当前验证状态

状态保护与可移植备份已通过 Windows 工作区测试和 Linux 容器测试。自动测试覆盖 DPAPI 信封、旧明文升级、用途隔离、错误口令、密文篡改、未知版本、类型混用、状态锁、默认拒绝覆盖、路径别名拒绝及 Linux `0600`。仍需在真实 systemd 服务账户、Windows SYSTEM 自启动身份和异常断电恢复场景中完成运行验收；DPAPI 正式状态本身仍不支持直接跨机器恢复。
