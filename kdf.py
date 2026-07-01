"""
Key derivation functions using only Python stdlib (hashlib, hmac).

Implements:
  - HKDF-Extract  (RFC 5869)
  - HKDF-Expand   (RFC 5869)
  - PBKDF2-SHA256 (RFC 2898 / hashlib built-in)
"""

import hashlib
import hmac
import math

# HMAC.new
# 1. Дополняет salt до размера блока SHA-256 (64 байта)
# 2. Вычисляет inner_hash = SHA256( (salt ⊕ ipad) + ikm )
# 3. Вычисляет final_hash = SHA256( (salt ⊕ opad) + inner_hash )
# 4. Возвращает final_hash

# HKDF (RFC 5869)

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand: derive *length* bytes from PRK using info context.
    SHA-256 hash length = 32, so max output = 255 * 32 = 8160 bytes.
    """
    hash_len = 32
    n = math.ceil(length / hash_len)
    if n > 255:
        raise ValueError("HKDF-Expand: requested length too large")

    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t

    return okm[:length]

# PBKDF2-SHA256

def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int,
                  key_length: int = 32) -> bytes:
    """PBKDF2-SHA256 via hashlib (C-accelerated on CPython)."""
    return hashlib.pbkdf2_hmac(
        "sha256", password, salt, iterations, dklen=key_length,
    )
