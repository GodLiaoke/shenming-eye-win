#!/bin/bash
set -euo pipefail

# Legacy local-engine build: use build-cloud-exe.sh for the current 43 cloud release.
export PATH="${PHOENIX_XWIN_BIN:-$HOME/Library/Caches/cargo-xwin}:$HOME/.cargo/bin:$PATH"
ROOT="$(cd "$(dirname "$0")" && pwd)"
RUST_ROOT="$(cd "$ROOT/.." && pwd)"
TARGET_DIR="$ROOT/build/target"
DIST="$ROOT/dist"

export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_DEBUG=false
# 验证服务器是自签证书：不开这个开关，reqwest 会在 TLS 阶段直接失败，
# 界面显示 "error sending request for url (https://…/api/activate)"。
# 地址默认不烘焙：运行时读 环境变量 PHOENIX_VERIFY_ORIGIN → verify-origin.txt。
# 需要固定进包时再显式给：PHOENIX_ORIGIN=https://… bash build-release-hardened.sh
export PHOENIX_GATEWAY_ORIGIN="${PHOENIX_ORIGIN:-}"
export PHOENIX_INSECURE_TLS="${PHOENIX_INSECURE_TLS:-1}"
export BATTLE_SKIP_WEBUI_BUILD=1
export RUSTFLAGS="-Ctarget-feature=+crt-static"

mkdir -p "$DIST"
cd "$RUST_ROOT"
cargo xwin build -p phoenix-windows --release --target x86_64-pc-windows-msvc

SOURCE="$TARGET_DIR/x86_64-pc-windows-msvc/release/Phoenix-Windows.exe"
OUTPUT="$DIST/Phoenix-Windows-local-$(date +%Y%m%d-%H%M).exe"
python3 "$ROOT/tools/pe_resource.py" "$SOURCE" --output "$OUTPUT" --version 1.2.1 --build "local-$(date +%Y%m%d-%H%M)" --icon "$ROOT/tools/app.ico"
shasum -a 256 "$OUTPUT"
