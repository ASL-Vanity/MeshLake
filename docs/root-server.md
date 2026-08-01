# MeshLake 根服务器（meshlake-root）

`meshlake-root` 是 Windows/Linux 通用的 UDP 节点发现与 NAT 协调服务。它不是控制器，也不是流量中继：

- 控制器负责创建网络、分配地址和签发成员证书；
- 根服务器验证成员证书，交换节点候选地址；
- 中继只在节点无法直连时转发端到端加密数据。

根服务器不会收到虚拟网络流量密钥。

## 端口

当前默认端口：

- `51819/UDP`：根发现和候选地址交换；
- `51820/UDP`：加密数据中继；
- `51822/TCP`：控制器 HTTPS API；可由控制器原生 Rustls 提供，也可仅监听回环并置于 HTTPS 反向代理之后。

## 生成根身份

先生成根服务器长期身份并读取公钥：

```powershell
meshlake-root.exe `
  --identity-file .\root-identity.json `
  --print-public-key
```

Linux 使用相同参数。`root-identity.json` 包含根私钥，不可公开、不可提交到源码仓库。Planet 中只填写输出的 Base64 公钥。

## 配置 Planet V2

控制器支持多个根和多个中继。参数顺序就是初始优先级：

```powershell
meshlake-controller.exe `
  --bind 127.0.0.1:51822 `
  --planet-controller-url https://planet.example.com `
  --planet-root "<根公钥Base64>@203.0.113.10:51819" `
  --planet-root "<第二根公钥Base64>@203.0.113.11:51819" `
  --planet-relay-endpoint 203.0.113.10:51820 `
  --planet-relay-endpoint 203.0.113.11:51820 `
  --planet-stun stun.example.com:3478
```

控制器通过 `/v1/planet` 返回签名 Planet V2，其中包含根节点公钥、根节点地址、中继顺序和 STUN 列表。

## 启动根服务器

读取控制器启动时输出的控制器公钥，然后启动根服务：

```powershell
meshlake-root.exe `
  --bind 0.0.0.0:51819 `
  --identity-file .\root-identity.json `
  --controller-public-key-base64 <控制器公钥Base64>
```

可以重复 `--controller-public-key-base64`，让同一根服务器服务多个可信控制器。

## 持久化配置与自动启动

先将命令行参数保存为 JSON。建议配置文件和根身份文件放在同一个仅管理员可读写的目录：

```powershell
meshlake-root.exe `
  --bind 0.0.0.0:51819 `
  --identity-file C:\ProgramData\MeshLake\root-identity.json `
  --controller-public-key-base64 <控制器公钥Base64> `
  --write-config C:\ProgramData\MeshLake\root.json
```

验证配置能够运行：

```powershell
meshlake-root.exe --config C:\ProgramData\MeshLake\root.json run
```

Windows 以管理员权限安装 SYSTEM 开机任务：

```powershell
meshlake-root.exe --config C:\ProgramData\MeshLake\root.json autostart install
meshlake-root.exe autostart status
meshlake-root.exe autostart uninstall
```

Linux 使用相同配置格式，并通过 systemd 安装：

```bash
sudo meshlake-root --config /etc/meshlake/root.json autostart install
meshlake-root autostart status
sudo meshlake-root autostart uninstall
```

Linux systemd 单元会限制文件系统写入范围，因此 `identity_file` 应放在配置文件所在目录内。

## 当前协议行为

1. 节点首次启动生成自己的 Ed25519 身份；
2. 控制器将设备 ID 和设备公钥同时写入成员证书；
3. 节点通过当前 UDP 映射向 Planet 中的所有根节点发送签名注册；
4. 根节点验证设备签名、设备公钥、控制器成员证书及覆盖该证书的当前签名授权清单；
5. 根节点返回同网络其他设备的公网、STUN、UPnP 等候选地址；
6. 节点并行发送 UDP 探测，成功后优先直连；
7. 无法直连时继续使用加密中继。

V1 根服务采用内存在线表，节点需要周期性刷新。根节点之间暂不复制数据库；客户端同时注册所有根节点，因此单个根节点离线不会阻止其他根节点发现成员。

客户端也会使用同一个 UDP socket 向 Planet 中所有同地址族中继注册。Root 和 Relay 都拒绝不带授权清单、清单过期、证书已吊销或网络密钥 epoch 落后的注册；中继只有在严格验证成功后才发送注册确认。客户端按 Planet 顺序选择仍在正常确认的最高优先级中继。首选中继停止确认后，会自动改用下一台中继，节点不需要重新加入网络。

## 兼容性说明

旧成员证书没有绑定设备公钥，不能使用新的认证根协议。测试旧网络时，需要让设备退出该网络并使用新邀请链接重新加入。
