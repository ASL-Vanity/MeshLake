# MeshLake Linux 无界面客户端

## 运行要求

- x86_64 Linux，glibc 2.17 或更高版本；
- 内核 TUN 支持，存在 `/dev/net/tun`；
- `iproute2`，命令 `ip` 必须可用；
- 创建 TUN 和配置地址需要 root 或等效的 `CAP_NET_ADMIN` 权限。

控制器、根节点和中继本身不创建 TUN；绑定 1024 以上端口时可使用权限更低的独立服务账户。客户端 `meshlaked` 当前建议通过 systemd 以 root 启动。

## 交叉构建

Windows 开发机安装 Zig 与 `cargo-zigbuild` 后，在项目根目录执行：

```powershell
cargo zigbuild --target x86_64-unknown-linux-gnu.2.17 --release `
  -p meshlaked -p meshlake-cli -p meshlake-controller `
  -p meshlake-relay -p meshlake-root
```

产物位于：

```text
target/x86_64-unknown-linux-gnu/release/
```

## 手动启动

将 `meshlaked` 与 `meshlake-cli` 复制到 Linux 设备并添加执行权限：

```bash
chmod 755 meshlaked meshlake-cli
sudo ./meshlaked run
```

另一个终端中可以查询和管理本机代理：

```bash
./meshlake-cli status
sudo ./meshlake-cli adapter start
./meshlake-cli network join-link --link 'meshlake://join?...'
```

邀请链接含一次性凭据，不要写入 shell 历史、日志或公开脚本。生产部署应通过受控的临时文件、标准输入或后续安全导入接口传递。

## systemd

把二进制放在长期不变的位置后执行：

```bash
sudo ./meshlaked autostart install
./meshlaked autostart status
```

未显式传入 `--state-file` 时，安装器创建 `/etc/systemd/system/meshlaked.service`，并将状态固定在 `/var/lib/meshlake/agent.json`（由 `StateDirectory=meshlake` 创建）；显式传入 `--state-file` 时则保留该绝对路径。服务异常退出后等待 3 秒重启。状态文件包含设备私钥和网络密钥，代理会在 Linux 上强制设置为 `0600`。

自动安装器会拒绝包含空白、控制字符、引号、反斜杠、`$`、`%`、`#` 或 `;` 的二进制、状态和密钥文件路径，避免这些内容被 systemd unit 重新解释。请把服务二进制、状态与密钥放在普通的绝对路径中，例如 `/opt/meshlake`、`/var/lib/meshlake` 与 `/etc/meshlake`。

卸载服务：

```bash
sudo ./meshlaked autostart uninstall
```

## 故障检查

```bash
test -c /dev/net/tun
command -v ip
systemctl status meshlaked.service
journalctl -u meshlaked.service -n 100 --no-pager
```

若 `/dev/net/tun` 不存在，可先检查内核是否启用了 TUN，或尝试 `sudo modprobe tun`。云主机、容器或受限虚拟机还可能需要宿主机显式开放 TUN 设备和 `CAP_NET_ADMIN`。
