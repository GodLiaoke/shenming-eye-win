#!/usr/bin/env python3
"""给 Windows exe 注入 VS_VERSION_INFO 与图标资源（cargo-xwin 不带 rc.exe，只能自己写）。

为什么需要：`phoenix-windows` 出来的 exe **资源表是空的** ——
  · 属性 → 详细信息里没有版本/公司/产品名（客户分不清哪一版，客服没法核对）
  · 资源管理器里没有文件图标（默认白图标）
  · 一些杀软/白名单工具对"无版本信息"的 exe 更敏感

用法：
  python3 pe_resource.py <exe> [--output <out>] --version 1.2.0 --build 20261004-0950 [--icon icon.ico]
"""
import argparse
import struct
import sys
from pathlib import Path

RT_ICON = 3
RT_GROUP_ICON = 14
RT_VERSION = 16
LANG = 0x0409  # en-US（内容里也有中文，Windows 照样显示）


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


# ---------------------------------------------------------------- PE 解析
class Pe:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[self.pe:self.pe + 4] != b"PE\0\0":
            raise SystemExit("不是有效的 PE 文件")
        self.coff = self.pe + 4
        self.machine, self.nsections = struct.unpack_from("<HH", self.data, self.coff)
        self.opt_size = struct.unpack_from("<H", self.data, self.coff + 16)[0]
        self.opt = self.coff + 20
        self.magic = struct.unpack_from("<H", self.data, self.opt)[0]
        self.dd = self.opt + (112 if self.magic == 0x20B else 96)
        self.section_align = struct.unpack_from("<I", self.data, self.opt + 32)[0]
        self.file_align = struct.unpack_from("<I", self.data, self.opt + 36)[0]
        self.section_table = self.opt + self.opt_size
        self.sections = []
        for i in range(self.nsections):
            off = self.section_table + i * 40
            name = bytes(self.data[off:off + 8]).rstrip(b"\0").decode("latin-1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", self.data, off + 8)
            self.sections.append(
                {"off": off, "name": name, "vsize": vsize, "vaddr": vaddr,
                 "rawsize": rawsize, "rawptr": rawptr}
            )

    @property
    def headers_end(self) -> int:
        """PE 头（含段表）结束的物理偏移 —— 新段头必须写在这里之前。"""
        return self.section_table + self.nsections * 40

    def set_directory(self, index: int, rva: int, size: int) -> None:
        struct.pack_into("<II", self.data, self.dd + index * 8, rva, size)


# ---------------------------------------------------------------- 版本资源
def _node(key: str, value: bytes, value_length: int, value_type: int, children: bytes = b"") -> bytes:
    body = bytearray(b"\0" * 6)
    body += (key + "\0").encode("utf-16-le")
    body += b"\0" * (align(len(body), 4) - len(body))
    body += value
    if children:
        body += b"\0" * (align(len(body), 4) - len(body))
        body += children
    length = len(body)
    struct.pack_into("<HHH", body, 0, length, value_length, value_type)
    body += b"\0" * (align(length, 4) - length)
    return bytes(body)


def version_resource(version: str, build: str, product: str, company: str) -> bytes:
    parts = []
    for chunk in (version.split(".") + ["0", "0", "0", "0"])[:4]:
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    ms, ls = parts[0] << 16 | parts[1], parts[2] << 16 | parts[3]

    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,   # dwSignature
        0x00010000,   # dwStrucVersion
        ms, ls,       # dwFileVersionMS/LS
        ms, ls,       # dwProductVersionMS/LS
        0x3F,         # dwFileFlagsMask
        0x0,          # dwFileFlags
        0x40004,      # dwFileOS = VOS_NT_WINDOWS32
        0x1,          # dwFileType = VFT_APP
        0x0,          # dwFileSubtype
        0x0,          # dwFileDateMS
        0x0,          # dwFileDateLS
    )

    strings = [
        ("CompanyName", company),
        ("FileDescription", "Phoenix CodeV 实时雷达"),
        ("FileVersion", f"{version} (build {build})"),
        ("InternalName", "Phoenix-Windows"),
        ("LegalCopyright", "Phoenix CodeV"),
        ("OriginalFilename", "Phoenix-Windows.exe"),
        ("ProductName", product),
        ("ProductVersion", version),
        ("Comments", f"build {build}"),
    ]
    table_children = b""
    for key, value in strings:
        encoded = (value + "\0").encode("utf-16-le")
        table_children += _node(key, encoded, len(encoded) // 2, 1)
    string_table = _node("040904B0", b"", 0, 1, table_children)
    string_file_info = _node("StringFileInfo", b"", 0, 1, string_table)
    translation = _node("Translation", struct.pack("<HH", LANG, 1200), 4, 0)
    var_file_info = _node("VarFileInfo", b"", 0, 1, translation)
    return _node("VS_VERSION_INFO", fixed, len(fixed), 0, string_file_info + var_file_info)


# ---------------------------------------------------------------- 图标
def parse_ico(path: Path):
    data = path.read_bytes()
    if data[:4] != b"\x00\x00\x01\x00":
        raise SystemExit("图标不是 .ico 格式")
    count = struct.unpack_from("<H", data, 4)[0]
    images = []
    offset = 6
    for _ in range(count):
        width, height, colors, _, planes, bits, size, image_offset = struct.unpack_from(
            "<BBBBHHII", data, offset
        )
        images.append({
            "width": width, "height": height, "colors": colors,
            "planes": planes, "bits": bits,
            "data": data[image_offset:image_offset + size],
        })
        offset += 16
    return images


def group_icon(images) -> bytes:
    blob = struct.pack("<HHH", 0, 1, len(images))
    for index, image in enumerate(images, start=1):
        blob += struct.pack(
            "<BBBBHHIH", image["width"], image["height"], image["colors"], 0,
            image["planes"], image["bits"], len(image["data"]), index,
        )
    return blob


# ---------------------------------------------------------------- 资源目录树
def build_directory(tree) -> bytes:
    """tree: {type_id: {name_id: {lang_id: payload}}} → 目录树 + 数据条目（RVA 先填 0）。"""
    types = sorted(tree)
    # 三段式布局：顶层目录 / 每类型一层 / 每种语言一层 / 数据条目
    level2 = {t: sorted(tree[t]) for t in types}
    cursor = 16 + 8 * len(types)
    level2_off = {}
    for t in types:
        level2_off[t] = cursor
        cursor += 16 + 8 * len(level2[t])
    level3_off = {}
    for t in types:
        for n in level2[t]:
            level3_off[(t, n)] = cursor
            cursor += 16 + 8 * len(tree[t][n])
    data_off = {}
    for t in types:
        for n in level2[t]:
            for lang in sorted(tree[t][n]):
                data_off[(t, n, lang)] = cursor
                cursor = align(cursor + 16 + len(tree[t][n][lang]), 4)
    blob = bytearray(cursor)
    struct.pack_into("<IIHHHH", blob, 0, 0, 0, 0, 0, 0, len(types))
    for i, t in enumerate(types):
        struct.pack_into("<II", blob, 16 + i * 8, t, 0x80000000 | level2_off[t])
        names = level2[t]; base = level2_off[t]
        struct.pack_into("<IIHHHH", blob, base, 0, 0, 0, 0, 0, len(names))
        for j, n in enumerate(names):
            struct.pack_into("<II", blob, base + 16 + j * 8, n, 0x80000000 | level3_off[(t, n)])
            langs = sorted(tree[t][n]); base3 = level3_off[(t, n)]
            struct.pack_into("<IIHHHH", blob, base3, 0, 0, 0, 0, 0, len(langs))
            for k, lang in enumerate(langs):
                d = data_off[(t, n, lang)]; payload = tree[t][n][lang]
                struct.pack_into("<II", blob, base3 + 16 + k * 8, lang, d)
                struct.pack_into("<IIII", blob, d, 0, len(payload), 0, 0)
                blob[d + 16:d + 16 + len(payload)] = payload
    return bytes(blob), data_off


def pe_checksum(data: bytearray, checksum_offset: int) -> int:
    total = 0
    length = len(data)
    for i in range(0, length - (length % 2), 2):
        if checksum_offset <= i < checksum_offset + 4:
            continue
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    if length % 2:
        total += data[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + length) & 0xFFFFFFFF


def inject(exe: Path, output: Path, version: str, build: str, icon: Path | None) -> None:
    pe = Pe(exe.read_bytes())
    if struct.unpack_from("<II", pe.data, pe.dd + 16) != (0, 0):
        raise SystemExit("输入已含资源：拒绝覆盖已有图标/manifest，请传入原始编译产物")
    if struct.unpack_from("<II", pe.data, pe.dd + 32) != (0, 0):
        raise SystemExit("输入已含 Authenticode 签名：请在资源注入后重新签名")
    tree = {RT_VERSION: {1: {LANG: version_resource(version, build, "Phoenix CodeV", "Phoenix CodeV")}}}
    if icon is not None:
        images = parse_ico(icon)
        for index, image in enumerate(images, start=1):
            tree.setdefault(RT_ICON, {})[index] = {LANG: image["data"]}
        tree[RT_GROUP_ICON] = {1: {LANG: group_icon(images)}}

    blob, data_offsets = build_directory(tree)
    rsrc_rva = align(
        max(s["vaddr"] + max(s["vsize"], s["rawsize"]) for s in pe.sections),
        pe.section_align,
    )
    blob = bytearray(blob)
    for key, d in data_offsets.items():
        struct.pack_into("<I", blob, d, rsrc_rva + d + 16)

    last = max(pe.sections, key=lambda s: s["rawptr"] + s["rawsize"])
    raw_ptr = align(max(len(pe.data), last["rawptr"] + last["rawsize"]), pe.file_align)
    raw_size = align(len(blob), pe.file_align)

    data = pe.data
    if len(data) < raw_ptr:
        data += b"\0" * (raw_ptr - len(data))
    data += blob + b"\0" * (raw_size - len(blob))

    if pe.headers_end + 40 > min(s["rawptr"] for s in pe.sections if s["rawptr"]):
        raise SystemExit("PE 头空间不够放新段头")
    off = pe.headers_end
    data[off:off + 40] = b"\0" * 40
    struct.pack_into(
        "<8sIIII", data, off, b".rsrc\0\0\0", len(blob), rsrc_rva, raw_size, raw_ptr
    )
    struct.pack_into("<I", data, off + 36, 0x40000040)
    initialized = struct.unpack_from("<I", data, pe.opt + 8)[0]
    struct.pack_into("<I", data, pe.opt + 8, initialized + raw_size)
    struct.pack_into("<H", data, pe.coff + 2, pe.nsections + 1)
    struct.pack_into(
        "<I", data, pe.opt + 56, align(rsrc_rva + len(blob), pe.section_align)
    )
    struct.pack_into("<I", data, pe.opt + 64, 0)
    pe.set_directory(2, rsrc_rva, len(blob))

    checksum = pe_checksum(data, pe.opt + 64)
    struct.pack_into("<I", data, pe.opt + 64, checksum)
    output.write_bytes(data)
    print(f"  资源已注入：版本 {version} (build {build})" + ("，含图标" if icon else "，无图标"))
    print(f"  .rsrc rva=0x{rsrc_rva:x} size={len(blob)} raw=0x{raw_ptr:x} checksum=0x{checksum:x}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--version", default="1.2.0")
    parser.add_argument("--build", default="dev")
    parser.add_argument("--icon", type=Path)
    args = parser.parse_args()
    inject(args.exe, args.output or args.exe, args.version, args.build, args.icon)
    return 0


if __name__ == "__main__":
    sys.exit(main())
