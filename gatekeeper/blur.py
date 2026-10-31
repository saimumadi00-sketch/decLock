"""Screenshot of the desktop, blurred and dimmed, for the unlock overlay (the Face ID look).

Uses plain GDI through ctypes plus OpenCV/NumPy (already dependencies for face unlock), so there is
no extra install. Any failure returns None and the overlay falls back to a plain dark backdrop.
"""

import base64
import ctypes
import logging
from ctypes import wintypes

log = logging.getLogger("gatekeeper.blur")

# GDI constants: plain copy; include layered (transparent) windows in the capture; smooth downscaling.
SRCCOPY, CAPTUREBLT, HALFTONE = 0x00CC0020, 0x40000000, 4


class _BitmapInfoHeader(ctypes.Structure):
    # BITMAPINFOHEADER from wingdi.h: describes the pixel format GetDIBits should return.
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD)]


def grab_small(x: int, y: int, w: int, h: int, scale: int):
    """The screen rectangle shrunk by `scale`, as an (h/scale, w/scale, 4) BGRA array."""
    import numpy as np
    user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
    sw, sh = max(1, w // scale), max(1, h // scale)  # size of the shrunken capture
    # Declare argument/return types: ctypes would otherwise truncate 64-bit handles to 32-bit ints.
    for fn, res in ((user32.GetDC, ctypes.c_void_p), (gdi32.CreateCompatibleDC, ctypes.c_void_p),
                    (gdi32.CreateCompatibleBitmap, ctypes.c_void_p), (gdi32.SelectObject, ctypes.c_void_p)):
        fn.restype = res
    user32.GetDC.argtypes = [ctypes.c_void_p]
    gdi32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]
    gdi32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    gdi32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    gdi32.StretchBlt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                 wintypes.DWORD]
    gdi32.SetStretchBltMode.argtypes = [ctypes.c_void_p, ctypes.c_int]
    gdi32.GetDIBits.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT, wintypes.UINT,
                                ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]
    gdi32.DeleteObject.argtypes = [ctypes.c_void_p]
    gdi32.DeleteDC.argtypes = [ctypes.c_void_p]
    user32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    screen = user32.GetDC(None)  # device context of the whole screen
    mem = gdi32.CreateCompatibleDC(screen)  # off-screen DC we draw the shrunken copy into
    bitmap = gdi32.CreateCompatibleBitmap(screen, sw, sh)
    old = gdi32.SelectObject(mem, bitmap)
    try:
        gdi32.SetStretchBltMode(mem, HALFTONE)
        # Copy AND shrink in one step (much cheaper than capturing full size and resizing).
        if not gdi32.StretchBlt(mem, 0, 0, sw, sh, screen, x, y, w, h, SRCCOPY | CAPTUREBLT):
            raise OSError("StretchBlt failed")
        # 32-bit BGRA; a NEGATIVE height means rows come top-down, matching NumPy/OpenCV order.
        info = _BitmapInfoHeader(ctypes.sizeof(_BitmapInfoHeader), sw, -sh, 1, 32, 0, 0, 0, 0, 0, 0)
        buffer = ctypes.create_string_buffer(sw * sh * 4)
        if not gdi32.GetDIBits(mem, bitmap, 0, sh, buffer, ctypes.byref(info), 0):
            raise OSError("GetDIBits failed")
        return np.frombuffer(buffer, dtype=np.uint8).reshape(sh, sw, 4).copy()
    finally:  # GDI handles are a limited resource: always free them
        gdi32.SelectObject(mem, old)
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(mem)
        user32.ReleaseDC(None, screen)


def blur_image(bgra, out_w: int, out_h: int, sigma: float = 4.5, dim: float = 0.42):
    """Blur and darken a small BGRA capture and scale it to out_w x out_h (BGR)."""
    import cv2
    bgr = cv2.cvtColor(bgra, cv2.COLOR_BGRA2BGR)
    bgr = cv2.GaussianBlur(bgr, (0, 0), sigma)
    bgr = cv2.convertScaleAbs(bgr, alpha=1 - dim, beta=4)  # darken: pixel * (1 - dim) + 4
    return cv2.resize(bgr, (out_w, out_h), interpolation=cv2.INTER_CUBIC)


def blurred_backdrop(x: int, y: int, w: int, h: int, scale: int = 4):
    """Base64 PNG for tk.PhotoImage of the blurred, dimmed screen at HALF size (zoom it x2), or None.

    The capture is blurred at 1/4 size (cheap, and a wide blur) and delivered at 1/2 size so the PNG
    stays small; Tk's integer zoom then doubles it, which is invisible on a blurred image.
    """
    try:
        import cv2
        small = grab_small(x, y, w, h, scale)
        image = blur_image(small, max(1, w // 2), max(1, h // 2))
        ok, png = cv2.imencode(".png", image, [cv2.IMWRITE_PNG_COMPRESSION, 1])
        return base64.b64encode(png.tobytes()).decode("ascii") if ok else None
    except Exception:
        log.exception("could not capture the screen for the blur backdrop")
        return None
