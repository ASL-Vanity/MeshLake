# 第三方组件说明

## Wintun

MeshLake Windows 客户端包含 Wintun 预编译 DLL，以便创建三层虚拟网络适配器。

这些文件位于 `third_party/wintun/`，版权归 WireGuard LLC 所有，并适用该目录中的独立许可证：

- `third_party/wintun/LICENSE.txt`
- `third_party/wintun/package/wintun/LICENSE.txt`

Wintun 二进制文件不属于 MeshLake 的 Apache License 2.0 授权范围。分发 MeshLake Windows 构建时必须同时保留对应的 Wintun 许可证文本。

## MiSans

MeshLake Windows 图形界面内置未经修改的 MiSans Regular 和 Medium 字体。MiSans 字体版权归小米科技有限责任公司所有，适用《MiSans 字体知识产权许可协议》，不属于 MeshLake 源码的 Apache License 2.0 授权范围。

源码中的字体、来源说明与原始协议位于 `crates/meshlake-gui/assets/fonts/`。Windows 程序包保留 `licenses/MiSans/NOTICE.txt` 和 `licenses/MiSans/MiSans-License.pdf`；字体已内置于 GUI，无需安装到系统。Linux 无界面程序包不包含 MiSans 或 Wintun。

分发包含该字体的 MeshLake 图形界面时请保留原始声明与协议，不应把这些文件单独作为字体产品销售或分发。
