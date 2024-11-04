from hashlib import *
import tinyec.ec as ec
import binascii
import math

"""
Given Elliptic Curve
"""
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
a, b = 0, 7
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
H = N // n
field = ec.SubGroup(p, (Gx, Gy), n, H)
curve = ec.Curve(a, b, field)
G = ec.Point(curve, Gx, Gy)


# get smallest non-negative integer s.t L <= Ax mod P <= R
# Constraint 1: 0 < A < P and 0 <= L <= R < P
# Constraint 2: L != 0 and (L - 1) // g < R // g, where g = gcd(A, P)
def get_smallest(P, A, L, R):
    if L == 0:
        return 0
    if 2 * A > P:
        L, R = R, L
        A = P - A
        L = P - L
        R = P - R
    t = (L + A - 1) // A
    if t * A <= R:
        return t
    y = get_smallest(A, A - P % A, L % A, R % A)
    return (L + P * y + A - 1) // A


def inv(x):
    return ec.mod_inv(x, n)


def split(x):
    high = x >> 128
    low = x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    return high, low


def hash(msg):
    return int(sha256(msg.encode()).hexdigest(), 16)


m = "helloecdsa"
r = 0xDA7866632109E77F0D3C5BDD49031E6D9A940FCB7D29EA2F858B991D1F17CEF8
s = 0xA4A700AC4F18634AC845739E0342CD8335BF6E0606CA9DC9D668ABF9ED812E6D
Q = ec.Point(
    curve,
    0xA51208ADFF894CDD79D4D7D967AA4D492256BA4D527661B10AE7CFD6E15F28A6,
    0x6FBFD9A270CD717AFB0949E1C40FD2754B46F4F8472AC5711DE0351FE81BBD80,
)

shift = 2**128
e = hash(m)
eH, eL = split(e)
print(f"{hex(eH)=}")
print(f"{hex(eL)=}")

t = (s - r * shift) % n
tinv = inv(t)
alpha = (tinv * r) % n
beta = tinv * (e - eH * shift * s) % n

print(f"{hex(alpha)=}")
print(f"{hex(beta)=}")

dL = get_smallest(n, alpha, -beta + n, -beta + n + shift)
dH = (alpha * dL + beta) % n
d = dH * shift + dL

print(f"{hex(dH)=}")
print(f"{hex(dL)=}")

print(f"Secret key d of Yeongsoo: {hex(d)}")
