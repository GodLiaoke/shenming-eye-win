#!/usr/bin/env python3
"""与 codev-obf::decode 完全一致的编码器（用于机械替换源码里的字面量）。"""
MASK = (1 << 64) - 1

def key_for(length: int):
    x = ((length * 0x9E3779B97F4A7C15) & MASK) ^ 0x0DDB1A5E5BAD5EED
    key = []
    for _ in range(8):
        x ^= (x << 13) & MASK
        x ^= x >> 7
        x ^= (x << 17) & MASK
        key.append(x & 0xFF)
    return key

def encode(plain: str) -> str:
    data = plain.encode('utf-8')
    k = key_for(len(data))
    return ''.join(f'{b ^ k[i % len(k)]:02x}' for i, b in enumerate(data))

if __name__ == '__main__':
    import sys
    for a in sys.argv[1:]:
        print(encode(a))
