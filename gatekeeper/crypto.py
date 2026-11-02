"""Encryption at rest for face embeddings and snapshots (used from Phase 3 on).

A random Fernet key is generated once and stored in `key.bin`, wrapped with
Windows DPAPI so only the same Windows user on the same machine can unwrap it.
"""

import ctypes
from ctypes import POINTER, Structure, byref, c_char, c_void_p, cast, create_string_buffer, wintypes
from pathlib import Path

from cryptography.fernet import Fernet


class _Blob(Structure):
    # DATA_BLOB from wincrypt.h: a length and a pointer to bytes.
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", POINTER(c_char))]


CRYPTPROTECT_UI_FORBIDDEN = 0x1  # fail instead of ever showing a DPAPI prompt (no one may be there)
_DLLS = {}


def _dlls():
    """Private crypt32/kernel32 handles with the calls declared. Declaring them on the shared
    ctypes.windll objects (as before) changed LocalFree's prototype for every module in the process."""
    if not _DLLS:
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        for fn in (crypt32.CryptProtectData, crypt32.CryptUnprotectData):
            fn.argtypes = [POINTER(_Blob), c_void_p, c_void_p, c_void_p, c_void_p, wintypes.DWORD, POINTER(_Blob)]
            fn.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes, kernel32.LocalFree.restype = [c_void_p], c_void_p
        _DLLS.update(crypt32=crypt32, kernel32=kernel32)
    return _DLLS["crypt32"], _DLLS["kernel32"]


def _dpapi(data: bytes, protect: bool) -> bytes:
    """Encrypt (protect=True) or decrypt bytes with DPAPI, tied to the current Windows user."""
    crypt32, kernel32 = _dlls()
    buf = create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), cast(buf, POINTER(c_char)))
    blob_out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # (input, description, extra entropy, reserved, prompt struct, flags, output)
    if not fn(byref(blob_in), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blob_out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(cast(blob_out.pbData, c_void_p))  # DPAPI allocated the output buffer


class KeyStore:
    """Lazily loads (or creates on first use) the Fernet key used for face data."""
    def __init__(self, directory: Path):
        self.path = directory / "key.bin"
        self._fernet = None

    def _load(self) -> Fernet:
        if self._fernet is None:
            if self.path.exists():
                key = _dpapi(self.path.read_bytes(), protect=False)
            else:
                key = Fernet.generate_key()
                self.path.write_bytes(_dpapi(key, protect=True))
            self._fernet = Fernet(key)
        return self._fernet

    def encrypt(self, data: bytes) -> bytes:
        return self._load().encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self._load().decrypt(token)
