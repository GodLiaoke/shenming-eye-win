#!/usr/bin/env python3
"""把含核心词表的字符串面量机械替换为 codev_obf 编码调用（不改变运行时文字）。"""
import re, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from importlib import import_module
enc = import_module('obf-encode'.replace('-', '_')) if False else None
# 直接内联编码器（避免 import 文件名问题）
MASK = (1 << 64) - 1
def key_for(n):
    x = ((n * 0x9E3779B97F4A7C15) & MASK) ^ 0x0DDB1A5E5BAD5EED
    k = []
    for _ in range(8):
        x ^= (x << 13) & MASK; x ^= x >> 7; x ^= (x << 17) & MASK
        k.append(x & 0xFF)
    return k
def encode(plain):
    d = plain.encode(); k = key_for(len(d))
    return ''.join(f'{b ^ k[i % len(k)]:02x}' for i, b in enumerate(d))

WORDS = ["BatchSync", "SGNet", "PacketHandler"]
LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')

def find_call(text, open_paren):
    depth = 0; i = open_paren; in_str = False; esc = False
    while i < len(text):
        c = text[i]
        if in_str:
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == '"': in_str = False
        else:
            if c == '"': in_str = True
            elif c in '([{': depth += 1
            elif c in ')]}':
                depth -= 1
                if depth == 0: return i
        i += 1
    return -1

def split_args(s):
    args, depth, in_str, esc, cur = [], 0, False, False, ''
    for c in s:
        if in_str:
            cur += c
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == '"': in_str = False
            continue
        if c == '"': in_str = True; cur += c; continue
        if c in '([{': depth += 1
        elif c in ')]}': depth -= 1
        if c == ',' and depth == 0:
            args.append(cur.strip()); cur = ''; continue
        cur += c
    if cur.strip(): args.append(cur.strip())
    return args

total_fmt = total_plain = 0
for path in sorted(pathlib.Path('.').glob('codev-*/src/**/*.rs')):
    src = path.read_text(encoding='utf-8')
    orig = src
    # ① format!("…", args) 形式
    for m in list(re.finditer(r'format!\s*\(', src))[::-1]:
        op = src.index('(', m.start())
        cl = find_call(src, op)
        if cl < 0: continue
        inner = src[op+1:cl]
        lm = re.match(r'\s*"((?:[^"\\]|\\.)*)"\s*(.*)$', inner, re.S)
        if not lm: continue
        lit, rest = lm.group(1), lm.group(2)
        if not any(w in lit for w in WORDS) or '\\' in lit: continue
        args = split_args(rest[1:]) if rest.strip().startswith(',') else []
        n = lit.count('{}')
        if n == 0:
            new = f'codev_obf::s("{encode(lit)}")'
        elif n == len(args) and 1 <= n <= 3:
            new = f'codev_obf::f{n}("{encode(lit)}"' + (''.join(', ' + a for a in args)) + ')'
        else:
            continue
        src = src[:m.start()] + new + src[cl+1:]
        total_fmt += 1
    # ② 其余独立字面量
    def repl(m):
        global total_plain
        lit = m.group(1)
        if '\\' not in lit and any(w in lit for w in WORDS) and len(lit) > 2:
            total_plain += 1
            return f'codev_obf::s("{encode(lit)}")'
        return m.group(0)
    src = LIT.sub(repl, src)
    if src != orig:
        path.write_text(src, encoding='utf-8')
        print(f'  {path}: 已处理')

print(f'  合计: format! 形式 {total_fmt} 处 / 独立字面量 {total_plain} 处')
