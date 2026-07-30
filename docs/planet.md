# MeshLake 行星服务器（Planet）

Planet 是一个由控制器 Ed25519 私钥签名的公开引导清单，不是流量中继本身。它统一发布：

- 控制器 URL；
- MeshLake UDP 中继地址；
- 可选 STUN 服务器列表。

Planet V2 还会发布多个带固定公钥的根节点和按优先级排列的多个中继。客户端会同时向所有同地址族根节点注册，根节点响应必须通过 Planet 中固定的公钥验证。

根服务器部署方法见 `root-server.md`。

## 一条链接加入网络（无图形界面）

控制器启用 Planet 后，管理员不再需要分别发送控制器 URL、网络 ID、一次性令牌和公钥。先在管理员设备生成一次性邀请链接：

```powershell
meshlake-cli.exe controller invite `
  --controller https://planet.example.com `
  --network <网络ID> `
  --admin-token <管理员令牌>
```

命令只输出一条 `meshlake://join?...` 链接。它是一次性入网凭据，必须通过可信渠道发送。新设备只需：

```powershell
meshlake-cli.exe network join-link --link '<管理员发来的完整链接>'
```

客户端会先从链接固定的公钥验证 Planet 清单，自动保存控制器、UDP 中继和 STUN 配置，再向控制器兑换一次性成员资格。首次配置 Planet 后重启 `meshlaked.exe`，后台代理便会启动 UDP 直连与中继回退。

客户端必须同时提供该控制器的 Base64 公钥。代理会验证清单签名和公钥钉扎后才保存配置，网页返回的自称公钥不能作为信任依据。

## 控制器启动

```powershell
meshlake-controller.exe `
  --bind 0.0.0.0:51822 `
  --planet-controller-url https://planet.example.com `
  --planet-relay-endpoint planet.example.com:51820 `
  --planet-stun stun.example.com:3478
```

清单地址为：`https://planet.example.com/v1/planet`。生产环境应通过 HTTPS 反向代理转发到本机控制器，而不要将控制器的 HTTP 端口直接暴露到公网。

## Windows 客户端配置

GUI 的“行星服务器（推荐）”展开项填写清单 URL 和控制器公钥（Base64）后点击保存。无界面环境使用：

```powershell
meshlake-cli.exe planet set `
  --manifest https://planet.example.com/v1/planet `
  --controller-public-key-base64 <管理员可信渠道提供的公钥>
```

保存后重启 `meshlaked.exe`。这会自动应用 Planet 提供的中继与 STUN 配置；加入网络时仍使用管理员生成的一次性邀请链接。
