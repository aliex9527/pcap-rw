"""Inject an .ico into a Windows PE executable using the Win32 resource API.

Used because the MinGW `windres` preprocessor cannot run in this environment.
Only writes RT_ICON / RT_GROUP_ICON resources; the rest of the PE is untouched.
"""

from __future__ import annotations

import ctypes
import struct
import sys
from ctypes import wintypes
from pathlib import Path

RT_ICON = 3
RT_GROUP_ICON = 14
LANG_NEUTRAL = 0

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


def parse_ico(data: bytes) -> list[tuple[bytes, tuple[int, ...]]]:
    """Return [(image_bytes, (w, h, colors, planes, bitcount))] for each icon image."""
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or kind != 1:
        raise ValueError("不是有效的 .ico 文件")
    images = []
    for i in range(count):
        (
            width,
            height,
            colors,
            _res,
            planes,
            bitcount,
            size,
            offset,
        ) = struct.unpack_from("<BBBBHHII", data, 6 + i * 16)
        images.append(
            (data[offset : offset + size], (width, height, colors, planes, bitcount))
        )
    return images


def build_group(images: list[tuple[bytes, tuple[int, ...]]]) -> bytes:
    header = struct.pack("<HHH", 0, 1, len(images))
    entries = b""
    for index, (blob, (width, height, colors, planes, bitcount)) in enumerate(images, 1):
        entries += struct.pack(
            "<BBBBHHIH",
            width,
            height,
            colors,
            0,
            planes,
            bitcount,
            len(blob),
            index,
        )
    return header + entries


def inject(exe: Path, ico: Path) -> None:
    images = parse_ico(ico.read_bytes())
    if not images:
        raise ValueError("图标文件里没有图像")

    handle = kernel32.BeginUpdateResourceW(str(exe), False)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    ok = True
    try:
        for index, (blob, _meta) in enumerate(images, 1):
            buf = ctypes.create_string_buffer(blob, len(blob))
            ok = ok and kernel32.UpdateResourceW(
                handle, RT_ICON, index, LANG_NEUTRAL, buf, len(blob)
            )
        group = build_group(images)
        gbuf = ctypes.create_string_buffer(group, len(group))
        ok = ok and kernel32.UpdateResourceW(
            handle, RT_GROUP_ICON, 1, LANG_NEUTRAL, gbuf, len(group)
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if not kernel32.EndUpdateResourceW(handle, not ok):
            raise ctypes.WinError(ctypes.get_last_error())


def main() -> int:
    if len(sys.argv) != 3:
        print("用法: seticon.py <exe> <ico>")
        return 2
    exe, ico = Path(sys.argv[1]), Path(sys.argv[2])
    if not exe.exists() or not ico.exists():
        print("文件不存在")
        return 2
    before = exe.stat().st_size
    inject(exe, ico)
    after = exe.stat().st_size
    print(f"图标已写入 {exe.name}：{before} -> {after} 字节")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
