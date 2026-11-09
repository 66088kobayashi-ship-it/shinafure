"""Minimal NIST P-256 arithmetic in pure Python.

Needed because the two rooms must each compute s·H(x) on a point they hashed
*themselves*, and the client must *add* the two results. Libraries expose
ECDH (x-coordinate only), which cannot add points, so this file implements
the group directly. Correctness is cross-checked against `cryptography` in the
tests. Not constant-time: fine for a prototype, not for production rooms (use
an HSM or a vetted library with point arithmetic there).
"""
from __future__ import annotations

import hashlib
from typing import Optional, Tuple

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

Point = Optional[Tuple[int, int]]  # None is the point at infinity
G: Point = (GX, GY)


def is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


# ---------------------------------------------------------------- affine add
def add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def neg(pt: Point) -> Point:
    return None if pt is None else (pt[0], (-pt[1]) % P)


# ------------------------------------------------------- Jacobian internals
def _jdouble(X, Y, Z):
    if Y == 0 or Z == 0:
        return 0, 1, 0
    YY = Y * Y % P
    S = 4 * X * YY % P
    ZZ = Z * Z % P
    M = 3 * (X - ZZ) * (X + ZZ) % P  # a = -3
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * YY * YY) % P
    Z3 = 2 * Y * Z % P
    return X3, Y3, Z3


def _jadd(X1, Y1, Z1, X2, Y2, Z2):
    if Z1 == 0:
        return X2, Y2, Z2
    if Z2 == 0:
        return X1, Y1, Z1
    Z1Z1 = Z1 * Z1 % P
    Z2Z2 = Z2 * Z2 % P
    U1 = X1 * Z2Z2 % P
    U2 = X2 * Z1Z1 % P
    S1 = Y1 * Z2 * Z2Z2 % P
    S2 = Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        if S1 != S2:
            return 0, 1, 0
        return _jdouble(X1, Y1, Z1)
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    HH = H * H % P
    HHH = H * HH % P
    V = U1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    Y3 = (R * (V - X3) - S1 * HHH) % P
    Z3 = H * Z1 * Z2 % P
    return X3, Y3, Z3


def mul(k: int, pt: Point) -> Point:
    """k·pt with a 4-bit fixed window."""
    k %= N
    if k == 0 or pt is None:
        return None
    x, y = pt
    table = [(0, 1, 0), (x, y, 1)]
    for _ in range(14):
        table.append(_jadd(*table[-1], x, y, 1))
    X, Y, Z = 0, 1, 0
    for shift in range(252, -1, -4):
        for _ in range(4):
            X, Y, Z = _jdouble(X, Y, Z)
        w = (k >> shift) & 0xF
        if w:
            X, Y, Z = _jadd(X, Y, Z, *table[w])
    if Z == 0:
        return None
    zi = pow(Z, P - 2, P)
    zi2 = zi * zi % P
    return X * zi2 % P, Y * zi2 * zi % P


# ---------------------------------------------------------------- encoding
def encode(pt: Point) -> bytes:
    if pt is None:
        raise ValueError("cannot encode the point at infinity")
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def decode(data: bytes) -> Point:
    if len(data) != 65 or data[0] != 4:
        raise ValueError("expected an uncompressed P-256 point")
    pt = int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big")
    if not is_on_curve(pt):
        raise ValueError("point not on curve")
    return pt


# ------------------------------------------------------------ hash to curve
def hash_to_curve(domain: bytes, msg: bytes) -> Point:
    """Try-and-increment. Inputs here are record identifiers, not secrets, so
    the variable running time leaks nothing sensitive. P-256 has cofactor 1,
    so every curve point is in the prime-order group."""
    for ctr in range(256):
        h = hashlib.sha256(b"wariin-h2c|" + domain + b"|" + ctr.to_bytes(1, "big") + b"|" + msg).digest()
        x = int.from_bytes(h, "big") % P
        rhs = (x * x * x + A * x + B) % P
        y = pow(rhs, (P + 1) // 4, P)  # P ≡ 3 (mod 4)
        if y * y % P == rhs:
            if y & 1:
                y = P - y
            return x, y
    raise RuntimeError("hash_to_curve failed")  # probability ~2^-256
