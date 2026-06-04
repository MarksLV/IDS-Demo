from __future__ import annotations

import ctypes
import base64
import os
import platform
import zlib
from ctypes import wintypes
from pathlib import Path


BI_RGB = 0
DIB_RGB_COLORS = 0
DI_NORMAL = 0x0003
SHGFI_ICON = 0x000000100
SHGFI_SMALLICON = 0x000000001


class SHFILEINFOW(ctypes.Structure):
    _fields_ = [
        ("hIcon", ctypes.c_void_p),
        ("iIcon", ctypes.c_int),
        ("dwAttributes", wintypes.DWORD),
        ("szDisplayName", wintypes.WCHAR * 260),
        ("szTypeName", wintypes.WCHAR * 80),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


def executable_icon_data(path: str | Path, size: int = 16, background: tuple[int, int, int] = (255, 255, 255)) -> str | None:
    if platform.system().lower() != "windows":
        return None
    path_text = str(path)
    if not path_text or not os.path.exists(path_text):
        return None

    hicon = _small_icon_handle(path_text)
    if not hicon:
        return None
    try:
        pixels = _draw_icon_pixels(hicon, size, background)
        if pixels is None:
            return None
        return _png_base64_from_pixels(pixels, size, size)
    finally:
        ctypes.windll.user32.DestroyIcon(hicon)


def _small_icon_handle(path: str) -> int | None:
    info = SHFILEINFOW()
    result = ctypes.windll.shell32.SHGetFileInfoW(
        path,
        0,
        ctypes.byref(info),
        ctypes.sizeof(info),
        SHGFI_ICON | SHGFI_SMALLICON,
    )
    if not result or not info.hIcon:
        return None
    return int(info.hIcon)


def _draw_icon_pixels(
    hicon: int,
    size: int,
    background: tuple[int, int, int],
) -> list[tuple[int, int, int]] | None:
    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    screen_dc = user32.GetDC(None)
    if not screen_dc:
        return None
    memory_dc = gdi32.CreateCompatibleDC(screen_dc)
    if not memory_dc:
        user32.ReleaseDC(None, screen_dc)
        return None

    bits = ctypes.c_void_p()
    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = size
    bmi.bmiHeader.biHeight = -size
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = BI_RGB
    bitmap = gdi32.CreateDIBSection(
        memory_dc,
        ctypes.byref(bmi),
        DIB_RGB_COLORS,
        ctypes.byref(bits),
        None,
        0,
    )
    if not bitmap or not bits.value:
        gdi32.DeleteDC(memory_dc)
        user32.ReleaseDC(None, screen_dc)
        return None

    old_object = gdi32.SelectObject(memory_dc, bitmap)
    raw = (ctypes.c_ubyte * (size * size * 4)).from_address(bits.value)
    bg_r, bg_g, bg_b = background
    for index in range(size * size):
        offset = index * 4
        raw[offset] = bg_b
        raw[offset + 1] = bg_g
        raw[offset + 2] = bg_r
        raw[offset + 3] = 255

    user32.DrawIconEx(memory_dc, 0, 0, hicon, size, size, 0, None, DI_NORMAL)
    pixels = []
    for index in range(size * size):
        offset = index * 4
        pixels.append((int(raw[offset + 2]), int(raw[offset + 1]), int(raw[offset])))

    if old_object:
        gdi32.SelectObject(memory_dc, old_object)
    gdi32.DeleteObject(bitmap)
    gdi32.DeleteDC(memory_dc)
    user32.ReleaseDC(None, screen_dc)
    return pixels


def _png_base64_from_pixels(pixels: list[tuple[int, int, int]], width: int, height: int) -> str:
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        for red, green, blue in pixels[y * width : (y + 1) * width]:
            raw.extend((red, green, blue))
    png = bytearray(b"\x89PNG\r\n\x1a\n")
    png.extend(_png_chunk(b"IHDR", width.to_bytes(4, "big") + height.to_bytes(4, "big") + b"\x08\x02\x00\x00\x00"))
    png.extend(_png_chunk(b"IDAT", zlib.compress(bytes(raw))))
    png.extend(_png_chunk(b"IEND", b""))
    return base64.b64encode(png).decode("ascii")


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    payload = kind + data
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return len(data).to_bytes(4, "big") + payload + crc.to_bytes(4, "big")
