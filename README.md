# 神明之眼 1.0 · Windows

本机雷达 Windows 客户端：**无卡密**、单文件 exe、内置抓包驱动与本机引擎，
每局自动录制 `proxy-*.pcap`（Wireshark 可直接打开）。

## 使用
见 [`phoenix-windows/使用教程-小白版.md`](phoenix-windows/使用教程-小白版.md)（右键 exe → 以管理员身份运行）。

## 构建
GitHub Actions（`windows-latest`）：

```
RUSTFLAGS="-Ctarget-feature=+crt-static" cargo build -p phoenix-windows --release
```

产物：`target/release/Shenming-Eye.exe`，打包名 `神明之眼-1.0-Windows.zip`。

## 本版本改动
- 卡密验证链路移除（`authorization::activate_with_progress` 直接返回本机授权）。
- 名称/版本：神明之眼 1.0.0，二进制 `Shenming-Eye.exe`。
- 侧栏改为白色液态玻璃皮肤，新增「抓包（反馈/取证）」卡片：打开抓包目录 / 复制路径。
- `[record] proxy_pcap = true`：引擎启动后自动录制 PCAP 到
  `%LOCALAPPDATA%\Phoenix\local-engine\record\`。
