#!/usr/bin/env python3
"""把 index.html 编码成不可被 strings 直接读出的 .enc（XOR + hex）。

用法: encode-page.py <index.html> <index.html.enc>
解码在 Rust 侧: codev_web::index_html()（见 codev-web/src/lib.rs）
密钥算法与 Rust 侧逐字节一致，改一处必须同步另一处。
"""
import sys, hashlib

MAGIC = b"CVPAGE1\x00"

def key_for(n: int) -> bytes:
    # 与 Rust 侧 decode_page() 完全相同的派生方式
    seed = (n * 0x9E3779B97F4A7C15 ^ 0x0DDB1A5E5BAD5EED) & ((1 << 64) - 1)
    out = bytearray()
    x = seed
    while len(out) < 64:
        x ^= (x << 13) & ((1 << 64) - 1)
        x ^= x >> 7
        x ^= (x << 17) & ((1 << 64) - 1)
        out.append(x & 0xFF)
    return bytes(out)

def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__); return 2
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()
    packed = data   # 不压缩：避免引入新依赖，XOR 后 strings 已经看不到明文
    key = key_for(len(packed))
    enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(packed))
    blob = MAGIC + len(packed).to_bytes(8, "little") + enc
    open(dst, "wb").write(blob)
    print(f"  编码 {src} → {dst}  {len(data)} → {len(blob)} 字节")
    return 0

if __name__ == "__main__":
    sys.exit(main())
