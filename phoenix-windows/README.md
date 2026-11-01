# Phoenix CodeV Windows 1.2.1 · 镜像修复版

当前交付：`win-1.2.1-fixes-20261006`，Windows 10/11 x64，Rust + tao/wry + WebView2。

## 本版模式与地址

- 当前交付以 `server-mode` 构建：本机采集 + 局域网 SOCKS5/热点入口，云端解析。
- 网关：`https://43.226.47.215:8443`；卡密验证由网关调用 103 验证服务，Windows 不直接持有服务器管理凭据。
- 手机节点显示本机 IPv4:2025。真实游戏流量从本机出口发送，同时复制给授权云端节点；不再把云端解析节点当成手机出口。
- 不嵌入 `codev-net.exe`、地图/解码器。旧的无 `server-mode` 本地引擎构建另有内嵌引擎，不能混称云端版。
- 当前 IP 测试站仍用自签证书；该包明确以 `PHOENIX_INSECURE_TLS=1` 构建。设为 `0` 确实开启正常证书校验，不再因为变量存在而误关校验。

## 构建与回归（绝对路径）

镜像目录：`/Users/Admin/Desktop/源码/Phoenix-副本本地/测试-镜像模式-20261002/客户端源码/rust/phoenix-windows`
主源码同步目录：`/Users/Admin/Desktop/源码/Phoenix-副本本地/Phoenix-CodeV-Source/rust/phoenix-windows`

```sh
cd '/Users/Admin/Desktop/源码/Phoenix-副本本地/测试-镜像模式-20261002/客户端源码/rust/phoenix-windows'
PHOENIX_BUILD_ID=win-1.2.1-fixes-20261006 bash build-cloud-exe.sh
```

需 cargo-xwin、x86_64-pc-windows-msvc target、clang-cl/lld-link。默认从 `$HOME/Library/Caches/cargo-xwin` 找工具；可设 `PHOENIX_XWIN_BIN`。请求签名密钥从权限 600 文件或环境读取，构建不会打印密钥。请求签名不是 Windows Authenticode 分发签名。

```sh
cd '/Users/Admin/Desktop/源码/Phoenix-副本本地/测试-镜像模式-20261002/客户端源码/rust'
BATTLE_SKIP_WEBUI_BUILD=1 cargo test -p phoenix-windows -p phoenix-cloud-relay --features phoenix-windows/server-mode
cargo xwin test -p phoenix-windows --features server-mode --target x86_64-pc-windows-msvc --no-run
node --test '/Users/Admin/Desktop/源码/Phoenix-副本本地/测试-镜像模式-20261002/客户端源码/rust/phoenix-windows/tools/test_sidebar.cjs'
python3 -m unittest discover -s '/Users/Admin/Desktop/源码/Phoenix-副本本地/测试-镜像模式-20261002/客户端源码/rust/phoenix-windows/tools' -p 'test_*.py'
```

## 验证边界

本机 macOS 上执行授权 HTTP 仿真、请求代次/取消、原子存储、局域网中继及侧栏状态回归；Windows 专属 DPAPI、WinDivert、窗口测试仅交叉编译，未冒充执行。实际双击需要 WebView2 Runtime 和管理员权限。真实卡密、WinDivert 加载、Windows 热点/ICS、端游及长时间运行仍需 Windows 实机验证。

## 修复要点

正确卡采用服务器判断，不做本地校验位限制；清除/换卡使旧请求和旧定时器失效；错误输入不会缓存到下一张正确卡；瞬时网络/503/截断或无效 JSON 自动重试；正常 /api/renew 不重启接收服务，房间消失和节点临期才重新激活；授权过真实有效期停止服务；加密存储失败明确提示但不误判卡密失败；私人房间地址同时验证房间号、origin、access；采集驱动错误不拖垮 SOCKS 接收；清除状态清空旧二维码、连接数和节点地址；PE 图标/版本资源可完整解析。

完整证据、回滚与未修复事项：`/Users/Admin/Desktop/源码/Phoenix-副本本地/Windows-EXE修复报告-20261006.md`。
