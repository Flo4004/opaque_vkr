"""
Pure-Python P-256 (secp256r1 / prime256v1) elliptic curve arithmetic.

Provides key generation, ECDH, and point encoding/decoding
without any third-party dependencies — only os and hashlib from stdlib.

Curve:  y² = x³ + ax + b  (mod p)
"""

import os

# ─────────────────── Curve parameters (NIST P-256) ────────────────────

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Точка на бесконечности
INF = (0, 0)


# ─────────────────── Modular arithmetic ───────────────────────────────

def _modinv(a: int, m: int) -> int:
    """Modular inverse via extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def _extended_gcd(a: int, b: int):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


# ─────────────── Affine point operations on P-256 ─────────────────────

def point_add(p1: tuple, p2: tuple) -> tuple:
    """Add two affine points on the curve."""
    if p1 == INF:
        return p2
    if p2 == INF:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2:
        if y1 != y2:
            return INF
        return point_double(p1)

    lam = ((y2 - y1) * _modinv(x2 - x1, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_double(pt: tuple) -> tuple:
    """Double an affine point."""
    if pt == INF:
        return INF

    x, y = pt
    if y == 0:
        return INF

    lam = ((3 * x * x + A) * _modinv(2 * y, P)) % P
    x3 = (lam * lam - 2 * x) % P
    y3 = (lam * (x - x3) - y) % P
    return (x3, y3)


def scalar_mult(k: int, pt: tuple) -> tuple:
    """Scalar multiplication using double-and-add (constant-time bit scan)."""
    if k < 0:
        k = k % N
    if k == 0 or pt == INF:
        return INF

    result = INF
    addend = pt

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result


def is_on_curve(pt: tuple) -> bool:
    """Check if a point lies on P-256."""
    if pt == INF:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


# ─────────────────── Generator point ──────────────────────────────────

G = (GX, GY)


# ─────────────────── Key generation / ECDH ────────────────────────────

def generate_private_key() -> int:
    """Generate a random private key scalar in [1, N-1]."""
    while True:
        raw = os.urandom(32)
        k = int.from_bytes(raw, "big")
        if 1 <= k < N:
            return k


def public_key_from_private(sk: int) -> tuple:
    """Compute the public key point Q = sk * G."""
    return scalar_mult(sk, G)


def ecdh(private_key: int, public_point: tuple) -> bytes:
    """
    ECDH: compute shared secret = x-coordinate of (sk * Q).
    Returns 32 bytes (big-endian x coordinate).
    """
    shared = scalar_mult(private_key, public_point)
    if shared == INF:
        raise ValueError("ECDH resulted in point at infinity")
    x, _ = shared
    return x.to_bytes(32, "big")


# ─────────────────── Encoding / decoding ──────────────────────────────

def encode_point(pt: tuple) -> bytes:
    """Encode a point as uncompressed SEC1:  04 || x(32) || y(32), 65 bytes."""
    if pt == INF:
        raise ValueError("Cannot encode point at infinity")
    x, y = pt
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def decode_point(data: bytes) -> tuple:
    """Decode an uncompressed SEC1 point (65 bytes starting with 0x04)."""
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("Invalid uncompressed point encoding")
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:65], "big")
    pt = (x, y)
    if not is_on_curve(pt):
        raise ValueError("Decoded point is not on P-256")
    return pt


def sk_to_bytes(sk: int) -> bytes:
    """Private key scalar → 32-byte big-endian."""
    return sk.to_bytes(32, "big")


def bytes_to_sk(data: bytes) -> int:
    """32 bytes → private key scalar (validates range)."""
    val = int.from_bytes(data, "big")
    if not (1 <= val < N):
        raise ValueError("Scalar out of range [1, N-1]")
    return val
