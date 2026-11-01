#!/usr/bin/env python3
"""把内嵌雷达页压缩（去注释 + 变量名混淆），**保留所有 id/属性/字符串面量**。

为什么：页面是成品包里最大的明文泄露面（300KB 中文注释 + 可读逻辑）。
只压内联 <script>（无 src/type 的），HTML 结构与所有 id 一个不动 —— 功能不受影响。
用法： minify-page.py <输入> <输出>     （需要 node/npx，用 terser 真解析，不用正则瞎删）
"""
import re, subprocess, sys, pathlib, tempfile

def minify_js(code: str) -> str:
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False, encoding='utf-8') as fh:
        fh.write(code); path = fh.name
    r = subprocess.run(['npx', '--yes', 'terser@5', path, '-c', '-m', '--comments', 'false'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f'terser failed: {r.stderr[-500:]}')
    return r.stdout

def main():
    src_path, out_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    html = src_path.read_text(encoding='utf-8')
    total_before = total_after = 0
    blocks = 0
    def repl(match):
        nonlocal total_before, total_after, blocks
        tag, body = match.group(1), match.group(2)
        # 只处理无 type / 无 src 的内联脚本
        if 'src=' in tag or ('type=' in tag and 'javascript' not in tag):
            return match.group(0)
        if len(body.strip()) < 40:
            return match.group(0)
        mini = minify_js(body)
        total_before += len(body); total_after += len(mini); blocks += 1
        return f'<script>{mini}</script>'
    out = re.sub(r'<script([^>]*)>(.*?)</script>', repl, html, flags=re.S)
    out_path.write_text(out, encoding='utf-8')
    print(f'  [minify] 压缩 {blocks} 个内联脚本: {total_before} → {total_after} 字符 '
          f'（省 {100*(1-total_after/max(total_before,1)):.1f}%）')
    print(f'  [minify] 整页 {len(html)} → {len(out)} 字符')
    ids_before = set(re.findall(r'id="([^"]+)"', html))
    ids_after = set(re.findall(r'id="([^"]+)"', out))
    missing = sorted(ids_before - ids_after)
    print(f'  [minify] HTML id: {len(ids_before)} → {len(ids_after)}，缺失 {missing if missing else "无 ✓"}')
    if missing:
        raise SystemExit('id 契约被破坏，拒绝输出')

main()
