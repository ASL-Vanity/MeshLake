# MeshLake 签名 DNS 与自定义路由

阶段 2 引入控制器签名的 `NetworkPolicyManifest`。客户端只有在同时验证下列材料后，才会持久化并应用策略：

1. 策略网络 ID 与当前逻辑网络一致；
2. Ed25519 签名来自入网时钉扎的控制器公钥；
3. 策略未过期、未回滚且同 epoch 没有语义突变；
4. 当前 `NetworkAuthorizationManifest` 仍授权网关证书；
5. 网关证书属于同一网络，且其既有 `allowed_routes` 覆盖目标前缀。

策略更新不能隐式扩大成员证书权限。管理员必须先显式授权网关前缀，再创建引用该网关的策略。

## 管理 API

以下示例使用 PowerShell。生产控制器必须使用 HTTPS；示例中的回环 HTTP 仅用于本机试运行。

```powershell
$controller = 'http://127.0.0.1:51822'
$network = '<网络 UUID>'
$gateway = '<网关设备 UUID>'
$headers = @{ 'x-meshlake-admin-token' = '<管理员令牌>' }

# 1. 显式授权该成员转发非默认前缀；请求会保留网络自身 IPv4/IPv6 前缀。
$allowed = @{
  allowed_routes = @('10.20.0.0/16', '2001:db8:20::/48')
} | ConvertTo-Json -Depth 4
Invoke-RestMethod -Method Post `
  -Uri "$controller/v1/networks/$network/members/$gateway/allowed-routes" `
  -Headers $headers -ContentType 'application/json' -Body $allowed

# 2. 发布签名路由与 split-DNS 策略。
$policy = @{
  routes = @(
    @{ prefix = '10.20.0.0/16'; gateway_device_id = $gateway },
    @{ prefix = '2001:db8:20::/48'; gateway_device_id = $gateway }
  )
  dns = @{
    servers = @('10.20.0.53', '2001:db8:20::53')
    search_domains = @('corp.example')
  }
} | ConvertTo-Json -Depth 6
Invoke-RestMethod -Method Post `
  -Uri "$controller/v1/networks/$network/policy" `
  -Headers $headers -ContentType 'application/json' -Body $policy
```

`GET /v1/networks/{id}/policy` 返回公开但带签名的策略。`meshlaked` 约每 20 秒在刷新授权后获取策略，并拒绝网络不匹配、未授权网关、过期、回滚、重复同前缀、多网关歧义或非法 DNS 配置。

## 路由与数据面

- 本阶段拒绝 `0.0.0.0/0` 和 `::/0`；出口节点不在此功能内。
- 同一网络内使用最长前缀匹配；同优先级多网关歧义失败关闭。
- 自定义路由不能与该逻辑网络的虚拟地址前缀重叠。
- 发往自定义前缀的加密包只发送给策略指定的当前授权网关。
- 网关返回的 LAN 源地址只有在发送设备正是该前缀的当前签名网关时才被接收；非网关、前缀外、跨网络或授权过期流量会被丢弃。
- 网关主机仍需管理员自行启用 IP forwarding，并配置 LAN 防火墙；本阶段不自动配置 NAT。

## Windows/Linux 平台事务

- Windows 使用 MeshLake Wintun 接口的 ActiveStore 路由、DNS server 和一个 connection-specific search suffix。请求多个 search domain 会失败关闭。
- Linux 使用 `ip route` 与 `resolvectl`，不会直接修改 `/etc/resolv.conf`；系统必须运行兼容的 `systemd-resolved`。
- 多个逻辑网络不能同时混合各自 DNS 策略；这会被视为跨网络 DNS 歧义。
- 更新时先移除旧策略，再应用新策略；失败后尝试清理新策略并恢复旧策略。若无法确认恢复成功，适配器会被停用，可信 applied-policy 状态会被清空。
- 退网、成员吊销、策略过期、adapter stop 和 daemon shutdown 都会触发策略清理。

平台命令生成和失败注入已有纯单元测试；尚未在提权真实 Windows/Linux 主机上完成破坏性故障注入验收。
