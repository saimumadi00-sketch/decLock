"""Encryption at rest for face embeddings and snapshots (used from Phase 3 on).

A random Fernet key is generated once and stored in `key.bin`, wrapped with
Windows DPAPI so only the same Windows user on the same machine can unwrap it.
"""

import ctypes
from ctypes import POINTER, Structure, byref, c_char, c_void_p, cast, create_string_buffer, wintypes
from pathlib import Path

from cryptography.fernet import Fernet


class _Blob(Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", POINTER(c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [c_void_p]
    kernel32.LocalFree.restype = c_void_p
    buf = create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), cast(buf, POINTER(c_char)))
    blob_out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    args = (byref(blob_in), None, None, None, None, 0, byref(blob_out))
    if not fn(*args):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(cast(blob_out.pbData, c_void_p))


class KeyStore:
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
