"""Stamp a VS_VERSIONINFO resource onto a Windows PE executable.

Same approach as seticon.py: windres cannot run in this environment (its
preprocessor fails), so the RT_VERSION block is assembled by hand and written
through the Win32 resource API. Existing resources (icons) are preserved
because BeginUpdateResourceW is called with bDeleteExistingResources = FALSE.

Run this *before* signing: modifying resources invalidates an Authenticode
signature that is already attached.
"""

from __future__ import annotations

import ctypes
import re
import struct
import sys
from ctypes import wintypes
from pathlib import Path

RT_VERSION = 16
LANG_EN_US = 0x0409
CODEPAGE_UNICODE = 1200

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
kernel32.BeginUpdateResourceW.restype = wintypes.HANDLE
kernel32.UpdateResourceW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.WORD,
    wintypes.LPVOID,
    wintypes.DWORD,
]
kernel32.UpdateResourceW.restype = wintypes.BOOL
kernel32.EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
kernel32.EndUpdateResourceW.restype = wintypes.BOOL


def align4(data: bytes) -> bytes:
    """Pad a *whole node* (header included) to a 32-bit boundary.

    The header is 6 bytes, so padding must be computed from 6 + len(data):
    aligning len(data) alone leaves everything 2 bytes out of place and Windows
    then reads the string table from the wrong offset.
    """
    return data + b"\x00" * ((-(6 + len(data))) % 4)


def node(key: str, value: bytes, wtype: int, wvalue: int, children: bytes = b"") -> bytes:
    """Assemble one VS_VERSIONINFO node.

    Layout is wLength / wValueLength / wType / szKey, then the value aligned to
    a 32-bit boundary, then the children aligned the same way. wLength covers
    header, key, padding, value and children.
    """
    key_bytes = key.encode("utf-16-le") + b"\x00\x00"
    body = align4(key_bytes)                       # align the value
    body += value
    body += b"\x00" * ((-(6 + len(body))) % 4)      # align whatever follows
    body += children
    return struct.pack("<HHH", 6 + len(body), wvalue, wtype) + body


def string_node(name: str, text: str) -> bytes:
    """A String node: wValueLength counts WCHARs including the terminator."""
    raw = (text + "\x00").encode("utf-16-le")
    return node(name, raw, wtype=1, wvalue=len(text) + 1)


def fixed_file_info(version: tuple[int, int, int, int]) -> bytes:
    major, minor, patch, build = version
    ms = (major << 16) | minor
    ls = (patch << 16) | build
    return struct.pack(
        "<13I",
        0xFEEF04BD,  # dwSignature
        0x00010000,  # dwStrucVersion
        ms,  # dwFileVersionMS
        ls,  # dwFileVersionLS
        ms,  # dwProductVersionMS
        ls,  # dwProductVersionLS
        0x3F,  # dwFileFlagsMask
        0x00,  # dwFileFlags
        0x40004,  # dwFileOS = VOS_NT_WINDOWS32
        0x01,  # dwFileType = VFT_APP
        0x00,  # dwFileSubtype
        0x00,  # dwFileDateMS
        0x00,  # dwFileDateLS
    )


def build_version_info(version: tuple[int, int, int, int], fields: dict[str, str]) -> bytes:
    text = f"{version[0]}.{version[1]}.{version[2]}.{version[3]}"

    ordered = [
        ("CompanyName", fields["company"]),
        ("FileDescription", fields["description"]),
        ("FileVersion", text),
        ("InternalName", fields["internal_name"]),
        ("LegalCopyright", fields["copyright"]),
        ("OriginalFilename", fields["original_filename"]),
        ("ProductName", fields["product_name"]),
        ("ProductVersion", text),
    ]

    strings = b"".join(string_node(name, value) for name, value in ordered)
    table = node(f"{LANG_EN_US:04X}{CODEPAGE_UNICODE:04X}", b"", wtype=1, wvalue=0, children=strings)
    string_file_info = node("StringFileInfo", b"", wtype=1, wvalue=0, children=table)

    translation = node(
        "Translation", struct.pack("<HH", LANG_EN_US, CODEPAGE_UNICODE), wtype=0, wvalue=4
    )
    var_file_info = node("VarFileInfo", b"", wtype=1, wvalue=0, children=translation)

    return node(
        "VS_VERSION_INFO",
        fixed_file_info(version),
        wtype=0,
        wvalue=52,
        children=string_file_info + var_file_info,
    )


def read_version(cargo_toml: Path) -> tuple[str, tuple[int, int, int, int]]:
    text = cargo_toml.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([0-9]+)\.([0-9]+)\.([0-9]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError(f"没在 {cargo_toml.name} 里找到 x.y.z 形式的 version")
    parts = [int(x) for x in match.groups()]
    return ".".join(str(x) for x in parts[:3]), (*parts, 0)


def inject(exe: Path, blob: bytes) -> None:
    handle = kernel32.BeginUpdateResourceW(str(exe), False)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    ok = True
    try:
        buf = ctypes.create_string_buffer(blob, len(blob))
        # Resource name 1 == VS_VERSION_INFO, the id every PE uses.
        ok = kernel32.UpdateResourceW(handle, RT_VERSION, 1, LANG_EN_US, buf, len(blob))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if not kernel32.EndUpdateResourceW(handle, not ok):
            raise ctypes.WinError(ctypes.get_last_error())


def main() -> int:
    if len(sys.argv) != 2:
        print("用法: version.py <exe>")
        return 2

    exe = Path(sys.argv[1])
    if not exe.exists():
        print(f"文件不存在: {exe}")
        return 2

    repo = Path(__file__).resolve().parent.parent
    text, version = read_version(repo / "Cargo.toml")
    blob = build_version_info(
        version,
        {
            "company": "aliex9527",
            "description": "PCAP IP 改写器",
            "internal_name": "pcap-rw",
            "copyright": f"Copyright (C) 2026 aliex9527",
            "original_filename": exe.name,
            "product_name": "PCAP IP 改写器",
        },
    )

    before = exe.stat().st_size
    inject(exe, blob)
    after = exe.stat().st_size
    print(f"版本资源已写入 {exe.name}：{text}（{before} -> {after} 字节，+{after - before}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
