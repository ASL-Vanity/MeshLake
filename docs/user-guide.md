# MeshLake 使用说明

适用于 **v0.1.0**。本文介绍 Windows 图形客户端、Windows/Linux 无界面客户端，以及自建网络的日常管理。

程序下载：[GitHub Releases](https://github.com/ASL-Vanity/MeshLake/releases/latest)。项目介绍见 [README](../README.md)。文中的域名、路径和 `<…>` 均为示例，执行前请替换成自己的配置。

## 1. 选择与准备程序

Windows 使用 `MeshLake-Windows-x64.zip`，解压到长期保留的目录，例如 `C:\MeshLake`。保留完整目录，不要只把 `MeshLake.exe` 拖到桌面；需要快捷入口时创建快捷方式。GUI 和 CLI 的本机维护功能会调用同目录的配套程序。

| Windows 文件 | 用途 | 普通成员是否需要启动 |
| --- | --- | --- |
| `MeshLake.exe` | 原生图形界面 | 使用 GUI 时打开 |
| `meshlake-cli.exe` | 无界面管理命令 | 按需执行 |
| `meshlaked.exe` | Agent，维护设备身份、虚拟网卡和网络连接 | 需要 |
| `meshlake-controller.exe` | Controller，管理网络、成员、邀请和签名策略 | 使用自建 Controller 时 |
| `meshlake-root.exe` | Root，发现节点、交换连接候选地址 | 按自建服务配置 |
| `meshlake-relay.exe` | Relay，转发加密流量 | 按自建服务配置 |
| `wintun.dll` | Windows 虚拟网卡组件 | 保留在程序目录 |

Windows 程序需要 x64 系统、VC++ x64/UCRT 运行库；GUI 还需要正常的图形驱动。MiSans 已嵌入 GUI，不用安装系统字体。分发程序时应保留包内 Wintun、MiSans 及项目许可证。

Linux 使用 `MeshLake-Linux-x64.tar.gz`，其中五个无界面程序的名称与上表相同，但没有 `.exe`，也不包含 Windows GUI 和 Wintun。Agent 需要 `/dev/net/tun`、`iproute2` 及 root 或等效网络管理权限；DNS 策略还需要可用的 `resolvectl`/`systemd-resolved`。部署细节见 [Linux 客户端](linux-client.md)。

收到管理员邀请的设备通常只需运行 Agent。Controller、Root、Relay 可以部署在其他 Windows/Linux 主机上，不需要在每台成员设备上各启动一套。

## 2. 第一次打开 Windows GUI

GUI 有六个页面：

| 页面 | 常用操作 |
| --- | --- |
| 概览 | 查看设备 ID、网络、分配地址、连接会话，离开网络，查看或导出状态 |
| 连接与网卡 | 启停网卡，配置 Relay、STUN、自动端口映射与 Planet |
| 加入网络 | 从邀请或手动参数入网 |
| 控制器管理 | 创建网络、生成邀请、管理成员、路由、DNS 和出口候选 |
| 出口与网关 | 为本机选择出口，或把本机配置为出口网关 |
| 维护工具 | 启停本机服务、诊断、备份恢复、状态修复和自启动 |

首次使用的顺序：

1. 打开 `MeshLake.exe`。GUI 不会自动启动后台，也不会自动申请管理员权限；未连接 Agent 时，概览中的未连接状态是正常的。
2. 如果这台电脑要实际参与组网，在“维护工具 → 客户端维护”点击“以管理员权限重启界面”，按 Windows 提示授权。若已有普通权限启动的 Agent，先正常停止它，再从提权后的界面启动；重启 GUI 不会提升已有后台进程的权限。
3. 在“维护工具 → 本机服务”选择 **Agent**。通常可保留默认启动参数；已有状态文件时填写它的实际路径。点击“启动服务”，查看进程状态和最近输出。
4. 点击界面上的“刷新”。概览应显示本机设备 ID。默认 Agent API 是 `http://127.0.0.1:51821/v1`。
5. 按下一节加入网络，然后在“连接与网卡”确认网卡正在运行；未启动时点击“启动网卡”。

已有 Agent 或开机启动任务在运行时，GUI 可直接连接，无需再启动第二个实例。已保存网络的 Agent 重启时会尝试重新激活网卡；失败时仍保留本机 API，便于查看错误和重试。

## 3. 加入网络与日常连接

### 使用邀请

1. 向网络管理员索取一次性邀请，或由管理员生成的邀请文件。
2. 打开“加入网络 → 使用邀请加入”。粘贴邀请；使用文件时展开“从文件导入邀请”，选择文件并点击“导入”。
3. 点击“通过邀请加入”。GUI 会读取当前 Agent 身份，再提交入网请求。
4. 成功后到“概览”检查网络名称、网络 ID 和“分配地址”，并确认网卡运行状态。其他设备使用各自的新邀请加入同一个网络。
5. 在应用中使用对方的 MeshLake 分配地址访问服务；例如远程桌面、文件服务或游戏服务还需在对方设备上实际运行，并允许相应入站连接。

邀请包含一次性凭据，过期或已使用后需要管理员重新签发。不要把完整邀请、管理员令牌或状态文件放进公开聊天、Issue、截图或日志。正常使用邀请不必手工填写 Controller、公钥和 Planet；邀请会携带相应入网信息，私有 CA 也可随邀请传递。

### 手动入网

管理员只提供独立令牌时，使用“手动入网”，填写：

- **控制器地址**：管理员提供的 HTTP(S) 基地址，例如 `https://controller.example.com`。
- **网络 ID**：目标网络的 UUID。
- **一次性入网令牌**：可粘贴，也可从受限文件导入。
- **控制器验证公钥（Base64）**：经可信渠道确认的控制器公钥。
- **私有 CA（高级）**：仅自建 CA 的 HTTPS Controller 需要，使用公开 CA 证书 PEM，不是服务器私钥。

点击“验证并加入网络”。管理员令牌用于管理 Controller，不是成员的入网令牌；不要混用。公钥和 TLS CA 也有不同用途：前者验证成员及策略签名，后者验证 HTTPS 服务器证书。

### 查看、断开与退出

“概览 → 连接会话”可刷新会话，查看当前会话状态与连接路径。没有会话不等于尚未入网；应结合分配地址、网卡状态和实际访问结果判断。状态和会话的 JSON 视图、复制与导出会进行敏感字段脱敏。

- 暂停虚拟网络收发：在“连接与网卡”停止网卡。
- 退出某个网络：在“概览”对应网络点击“离开网络”并确认。再次加入需要新的入网凭据。
- 停止整个 Agent：在“维护工具 → 本机服务”点击“正常停止本机 Agent”。

关闭、隐藏或退出 GUI 后，独立网络服务继续运行。关闭行为可在设置中调整，托盘可以重新显示界面。需要停止网络时应执行上面的网卡或 Agent 操作。

## 4. 自建 Controller 与创建网络

### 准备基础服务

已有 Controller 的管理员可以直接进入下一小节。首次自建时，先决定可供成员访问的 Controller HTTPS 域名、Root/Relay 地址和数据目录。

“维护工具 → 本机服务”可以分别配置并启动 Controller、Root 和 Relay。Controller 首次创建状态时，在“启动参数”里填写“首次管理员令牌保存到新文件”；父目录应已存在且访问受限，目标文件必须尚不存在。程序会把新管理员令牌保存到该文件，供“控制器管理”导入。已有状态的 Controller 应持续使用原状态文件，避免无意创建另一套身份和管理凭据。

公网或不可信局域网中的 Controller 使用 HTTPS：可填写 TLS 证书链与私钥文件，或让 Controller 只监听回环地址，由 HTTPS 反向代理转发。对成员公开的 URL 不能填写 `127.0.0.1`。私有 CA 部署还应填写供邀请携带的公开 CA 文件。

Root 负责发现，不转发业务流量；Relay 负责加密数据中继。按 [Root 服务器](root-server.md)、[Planet](planet.md) 配置服务身份和控制器公钥，再把公开端点和公开身份发布到 Planet。新部署采用 Planet V3 的 Root/Relay 身份配置；不要把长期身份文件当成公钥发布，也不要把 V1/V2 兼容地址参数与 V3 身份参数混用。HTTPS 和首次初始化细节见 [Controller TLS](controller-tls.md)。

### 连接并创建网络

1. 在“控制器管理 → 控制器连接”填写 Controller 地址，从文件导入管理员令牌；需要时填写私有 CA。
2. 点击“健康检查”，确认 HTTP(S) API 可达；“读取公钥”“读取 Planet”用于核对当前公开配置。
3. 在“网络管理 → 创建新网络”填写网络名称、IPv4 前缀、可选 IPv6 前缀。网段应避开现有 LAN、VPN 和其他虚拟网络；新网络 ID 可以留空自动生成。
4. 选择中继策略：“优先直连”“始终中继”或“禁用中继”，点击“创建控制器网络”。
5. 刷新网络列表，在目标网络点击“选择网络”。后续邀请、成员和策略操作都针对这个网络。

创建 Controller 网络不会自动把管理员这台设备加入网络。要使用它，也需生成邀请并在本机“加入网络”页入网。

“连接与网卡 → 创建本地开发网络”只创建没有 Controller 成员证书的本地开发记录；日常多设备组网应创建 Controller 网络并通过邀请入网。

### 邀请与独立令牌

选择网络后，在“邀请设备”设置有效期并点击“生成邀请链接”。有效期支持 **60–86400 秒**，默认 **900 秒**。可复制邀请或保存为新文件，再经可信渠道交付给一台设备。

没有配置 Planet 的 Controller 可以使用“独立入网令牌”：选择尚不存在的令牌文件路径，点击“签发并保存令牌”。同时把 Controller 地址、网络 ID、公钥和必要的 CA 交付给成员，供手动入网。若令牌已签发但保存失败，更换路径后用“保存现有令牌”，无需重复签发。

### 管理成员

“网络成员”提供“刷新成员”“读取授权清单”“读取策略清单”。按设备 ID 确认对象后，可移除成员或将它填入出口候选表单。移除成员会撤销成员资格并轮换网络密钥 epoch；其他设备需获取新的授权状态。

删除整个网络会影响全部成员。只想让本机退出时，使用概览中的“离开网络”；不要删除 Controller 网络。

## 5. 路由、DNS 与出口

### 发布非默认路由与 DNS

在 Controller 中选中网络后，展开“成员路由授权”，填入承担转发的成员设备 ID 和允许的路由前缀，每行一个。确认后点击“保存路由授权”。此操作替换该成员的全部额外路由授权；留空会撤销额外前缀，网络自身前缀由 Controller 保留。

然后展开“路由与 DNS 策略”：

1. 点击“读取完整策略”。
2. 添加需要的路由前缀及网关设备 ID。网关必须先获得覆盖这些前缀的成员路由授权。
3. DNS 服务器每行一个 IP，搜索域每行一个。Windows 当前只支持一个连接专用搜索域；含 Windows 成员的网络请按此填写。
4. 检查完整的路由、出口列表和 DNS，勾选“确认用以上内容替换完整策略”，点击“保存策略”。

保存是完整替换，空的部分也会覆盖原内容。先读取再修改，可以保留不打算变更的配置。策略文件导入只填入表单，检查后仍需确认保存；可导出可编辑 JSON 留存，目标需为新文件。

自定义路由不能与网络自身地址段重叠，默认路由由下面的出口功能管理。策略签名不能代替网关主机上的实际转发能力；子网路由还需网关系统的 IP forwarding、目标 LAN 和防火墙配置。Linux DNS 使用 `resolvectl`，不会直接改写 `/etc/resolv.conf`。细节见 [网络策略](network-policy.md)。

### 设置出口网关

出口使用涉及三个分别确认的步骤：

1. **管理员授权**：在“控制器管理 → 出口候选授权”填入已入网的网关设备 ID，选择 IPv4、IPv6 能力，点击“授权 / 更新”。
2. **网关本机启用**：在该设备的“出口与网关”选择网络，在“将本机作为网关”填入实际出口网卡名称，例如 Windows 的 `Ethernet` 或 Linux 的 `eth0`，选择协议并应用网关配置。
3. **使用者选择**：在需要通过网关访问外网的设备上，进入“出口与网关 → 流量出口”，填入 IPv4、IPv6 对应网关设备 ID，点击“应用出口选择”。只用一个地址族时，另一项可留空。

“启用故障关闭”用于在所选出口无法应用时阻止回落到物理网络，依赖 Agent 的平台保护成功应用。确认当前状态和实际业务访问结果后再依赖该配置；若平台拒绝应用，应处理错误，不能把勾选框本身当作保护已生效。

停止使用时，客户端执行“清除出口选择”；网关设备执行“停用网关”；管理员可“撤销出口授权”。这三个操作分别管理本机选择、本机转发和 Controller 候选资格。

修改出口候选会使已打开的完整策略草稿失效。GUI 会保留草稿但阻止旧内容保存或导入；先记录需要保留的编辑，再“读取完整策略”继续修改。

## 6. 连接与诊断

“连接与网卡 → 中继与连接发现”可设置 UDP 中继地址、逗号分隔的 STUN 服务器及 PCP/NAT-PMP/UPnP 自动端口映射。保存后 Agent 会重载配置；自动映射能否成功取决于路由器支持。

使用管理员提供的签名清单时，在“Planet 配置”填写清单 URL 和可信控制器公钥，必要时导入 CA，再点击“验证并保存 Planet”。程序会验证签名与清单约束；不要用任意下载地址或未经确认的公钥替换现有信任配置。

“维护工具 → 连接设置与诊断”包含：

- **本机 API 地址**：默认 `http://127.0.0.1:51821/v1`，保留 `/v1`。只接受回环地址，不能在这里填写远程 Controller。
- **请求超时**：1–3600 秒，默认 30 秒。修改后点击“应用连接设置”，设置仅本次 GUI 运行有效。
- **本机 HTTPS 私有 CA**：与 Controller CA 共用证书设置；修改后重新应用连接设置。
- **运行诊断**：读取本机状态与会话。可额外探测指定 `IP:端口`，IPv6 写成 `[地址]:端口`；只尝试 TCP 连接，不发送应用数据。

API 健康、已入网、会话建立和业务连通分别反映不同状态。一次 TCP 连接成功不证明 UDP、DNS、路由、出口或故障切换全部正常。遇到问题可先复制或导出脱敏状态，再附上具体错误和复现步骤。

## 7. 数据、备份、恢复与升级

### 默认位置

| 内容 | 默认位置 |
| --- | --- |
| Windows Agent 状态 | `%LOCALAPPDATA%\MeshLake\agent.json` |
| Windows Controller 状态 | `%LOCALAPPDATA%\MeshLake\controller.json` |
| Windows GUI 外观与关闭偏好 | `%LOCALAPPDATA%\MeshLake\gui-settings.json` |
| GUI 启动服务的日志 | `%LOCALAPPDATA%\MeshLake\gui-runs\` |
| Linux 手动运行的 Agent 状态 | `$XDG_STATE_HOME/meshlake/agent.json`，未设置时为 `~/.local/state/meshlake/agent.json` |
| Linux 默认自启动 Agent 状态 | `/var/lib/meshlake/agent.json` |
| Linux Controller 未指定路径时 | 当前工作目录下 `MeshLake/controller.json`；部署时建议显式指定 |

Agent 的 `--state-file` 优先于默认路径，`MESHLAKE_STATE_DIR` 也可改变 Agent 的默认目录。“维护工具 → 客户端维护 → 查看状态路径”可查询按所填运行参数解析出的路径；查询时应填入与实际 Agent 相同的状态参数。使用系统账户或自定义路径时，以真实运行参数为准。

状态包含设备身份和网络凭据，不能直接编辑、公开上传或复制给另一台在线设备共用身份。Windows 正式状态受本机 DPAPI 保护，跨机器移动请使用加密备份。Linux 的权限、外部状态密钥及 systemd credential 配置见 [状态保护](state-protection.md)。

### 加密备份

1. 正常停止持有目标状态的 Agent 或 Controller。备份和恢复都需要独占状态锁；退出 GUI 并不等于停止它们。
2. 在“维护工具 → 状态备份与恢复”选择“客户端状态”或“控制器状态”，填写与原服务一致的状态文件及必要的密钥参数。
3. 选择一个新的备份文件路径，例如 `D:\MeshLakeBackup\agent-20260912.mlb`；输入密码并再次确认。
4. 点击“加密备份”，检查执行结果。备份文件和密码分别妥善保存。

### 恢复与修复

停止对应服务，选择正确的状态类型、已有备份、目标状态路径，输入备份密码并“恢复状态”。默认拒绝覆盖已有目标；确需替换时勾选“允许覆盖现有目标文件”，核对确认信息后继续。Agent 备份不能当作 Controller 备份恢复。

恢复成功后，按同一状态路径重启对应服务并检查设备、网络和连接。不要让迁移前后的两台设备同时以恢复出的同一身份在线。

“客户端维护 → 修复无效网络记录”用于清理不能通过原生校验的本地网络记录。先备份并停止 Agent，再确认执行；它不是修改网段或强制入网的入口。遇到状态锁错误应查找仍在运行的进程，不要删除锁文件来强开第二个实例。

### 升级

1. 记录服务启动参数、程序目录和实际状态路径，停止需要替换的进程，备份 Agent/Controller 状态。
2. 下载新版本完整包，按发布的 SHA-256 清单校验；保留旧程序目录和加密备份。
3. 将同一版本的 GUI、CLI 和配套程序一起替换，保留状态、私有证书与秘密文件。
4. 若程序目录变化，更新自启动注册中的可执行程序路径；使用原状态路径启动，检查身份、网络与业务连接。

回退前先停止新版进程，使用旧程序和与它匹配的备份恢复。不要在服务运行时直接覆盖状态文件。

## 8. 自启动与后台服务

“维护工具 → 客户端维护”提供查看、安装和卸载 Agent 自启动；使用上方“状态文件与运行参数”中的设置。Windows 安装需要管理员权限，注册在启动时以 SYSTEM 运行的计划任务；Linux 使用 `meshlaked.service`。安装前先把程序放到稳定目录。

Linux 自启动默认使用 `/var/lib/meshlake/agent.json`，可能与交互终端的默认路径不同。从手动运行转为服务时，应显式指定原状态路径或按备份流程迁移，避免意外生成新设备身份。首次服务启动前不要保留另一个持有同一状态的前台实例。

“本机服务”中的 Agent、Controller、Root、Relay 启动参数相互独立；这里显示当前 GUI 发起的服务进程、日志路径和最近输出，不是系统全部服务的清单。Agent 优先用“正常停止本机 Agent”；“终止本次启动进程”仅作用于此界面记录的那次启动。重开 GUI 后，外部已运行的服务应按原进程或系统服务管理方式处理。

Agent 和 Root 在本机服务面板提供自启动操作。Controller、Relay 的长期后台托管按系统部署方式配置，不因关闭 GUI 而结束。Root 的持久化配置与自启动说明见 [Root 服务器](root-server.md)。

## 9. 外观与窗口

点击界面上的“设置”可选择简体中文或 English，调整以下外观并自动保存：

- 跟随系统、浅色、深色。
- 松石绿、湖蓝、靛紫、玫瑰、琥珀五种主题色。
- 减少动画。
- 80%、90%、100%、110%、125%、150% 六档界面缩放，选定后应用。
- 关闭窗口时默认最小化到托盘，以及关闭时是否询问。

界面使用内置 MiSans Regular/Medium；页面和图标按逻辑尺寸绘制，应用标志、窗口与托盘沿用 A「双岸」设计。窄窗口会调整导航布局，高缩放时可以滚动页面和设置窗口。使用可见的“刷新”“设置”按钮即可。

## 10. 常用 CLI

下面的 Windows 示例在解压目录的 PowerShell 中执行。Linux 使用同名无 `.exe` 程序。涉及网卡、状态或自启动的命令需使用相应权限；运行中的 Agent 决定实际网络操作权限。

### 启动、查询与入网

```powershell
# 在一个终端前台启动 Agent，关闭前用 Ctrl+C 正常停止
.\meshlake-cli.exe agent run

# 在另一个终端查询
.\meshlake-cli.exe status
.\meshlake-cli.exe --json sessions
.\meshlake-cli.exe agent state-path

# 邀请文件应来自管理员，并保持受限权限
.\meshlake-cli.exe network join-link --link-file 'C:\MeshLakeSecrets\member.invite'
.\meshlake-cli.exe adapter start

# 诊断默认只读取本机 API；可选 --tcp 仅用于明确的连接目标
.\meshlake-cli.exe diagnose
.\meshlake-cli.exe diagnose --tcp '100.64.20.2:3389'
```

如果不使用文件，`--link-prompt`、`--token-prompt` 和 `--admin-token-prompt` 会通过隐藏终端提示输入；相应 `--*-stdin` 可从受控标准输入读取。每项秘密只能选一种输入来源。不要使用旧的 `--link`、`--token` 或 `--admin-token` 明文参数。

### 创建网络并签发邀请

```powershell
$controllerUrl = 'https://controller.example.com'
$adminTokenFile = 'C:\MeshLakeSecrets\administrator.token'

.\meshlake-cli.exe controller network create `
  --controller $controllerUrl `
  --admin-token-file $adminTokenFile `
  --name '我的网络' `
  --ipv4-prefix '100.64.20.0/24' `
  --relay-policy preferred

# 从创建结果或 network list 获取实际网络 UUID
$networkId = '<网络 UUID>'
.\meshlake-cli.exe controller network list --controller $controllerUrl
.\meshlake-cli.exe controller invite `
  --controller $controllerUrl `
  --network $networkId `
  --admin-token-file $adminTokenFile `
  --invite-link-file 'C:\MeshLakeSecrets\new-member.invite'
```

私有 CA Controller 的命令应额外带上全局参数 `--tls-ca-certificate 'C:\MeshLakeTLS\root-ca.pem'`。没有 Planet 时，可用 `controller token` 将独立令牌写到 `--token-file`，成员使用 `network join --token-file` 并另外提供 Controller、公钥和网络 ID。

### 读取和保存策略

```powershell
# 输出可编辑的完整策略
.\meshlake-cli.exe controller policy get `
  --controller $controllerUrl --network $networkId --editable

# 将输出保存为 UTF-8 无 BOM 的 network-policy.json，编辑并检查
# routes、exit_nodes、dns 三个部分后，完整替换策略
.\meshlake-cli.exe controller policy set `
  --controller $controllerUrl --network $networkId `
  --admin-token-file $adminTokenFile --file '.\network-policy.json'
```

### 备份与自启动

```powershell
.\meshlake-cli.exe agent stop
.\meshlake-cli.exe state --state-file 'C:\MeshLakeData\agent.json' `
  backup 'D:\MeshLakeBackup\agent.mlb'

# 恢复默认不覆盖已有状态，确需替换才显式增加 --force
.\meshlake-cli.exe state --state-file 'C:\MeshLakeData\restored-agent.json' `
  restore 'D:\MeshLakeBackup\agent.mlb'

.\meshlake-cli.exe autostart --state-file 'C:\MeshLakeData\agent.json' install
.\meshlake-cli.exe autostart status
```

将示例状态路径替换成实际路径。备份密码默认在终端隐藏输入；备份时需要重复确认，不接受命令行明文密码。

查看完整参数用 `--help`，例如 `controller member --help`、`network exit --help`。`service controller -- --help` 可查看配套 Controller 的原生参数。GUI 的“高级命令控制台”每行代表一个参数，不执行 shell；路径无需引号，不要粘贴 PowerShell 的反引号、管道或整行脚本。

## 11. 常见问题

| 现象 | 处理 |
| --- | --- |
| GUI 提示无法联系本机后台 | 先确认 Agent 已启动；检查本机 API 地址及服务最近输出，避免重复启动 |
| 找不到配套程序或 Wintun | 恢复同一版本的完整解压目录，必要时在启动参数中指定 Wintun DLL |
| 缺少运行库或 GUI 无法创建图形上下文 | 补齐 VC++ x64/UCRT 运行库，检查系统图形驱动；无桌面主机使用 CLI/Agent |
| 入网成功但没有业务连接 | 检查分配地址、网卡状态、会话路径、对端服务监听与其防火墙，不只看 Controller 健康 |
| 邀请被拒绝 | 核对有效期、是否已使用、设备当前身份以及 Controller 地址；向管理员索取新邀请 |
| HTTPS 验证失败 | 核对域名、证书有效期与 CA 来源；导入正确 CA，不跳过证书校验 |
| 管理请求 401/403 | 核对 Controller 与管理员令牌是否匹配，确认没有误用成员入网令牌 |
| 策略保存按钮不可用 | 先读取完整策略并勾选替换确认；出口授权变更后重新读取策略 |
| 备份或启动报状态锁错误 | 停止仍持有该状态的实例后重试；不要删除锁文件绕过独占访问 |
| 导出提示文件已存在 | 换一个新的输出文件名；邀请、令牌和一般 JSON 导出默认拒绝覆盖 |
| 开机后出现了不同设备 ID | 检查服务账户、实际状态路径和手动启动时的路径是否一致，按备份流程恢复原身份 |
| 退出 GUI 后网络仍在线 | 独立后台的正常行为；使用“正常停止本机 Agent”或停止相应系统服务 |

反馈问题时提供版本、系统、操作步骤、完整错误和脱敏状态。真实跨主机连接、DNS、出口保护及干净系统安装效果需在自己的部署环境中确认；本版本的功能实现与构建结果不代表所有环境都已完成运行验收。
