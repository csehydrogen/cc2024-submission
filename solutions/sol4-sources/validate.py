from hashlib import *
import tinyec.ec as ec
import binascii
import math

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


def inv(x):
    return ec.mod_inv(x, n)


def split(x):
    high = x >> 128
    low = x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    return high, low


def hash(msg):
    return int(sha256(msg.encode()).hexdigest(), 16)


def sign(msg, d):
    e = hash(msg)
    ehigh, elow = split(e)
    dhigh, dlow = split(d)
    k = ehigh * (2**128) + dhigh
    r = (k * G).x % n
    s = (inv(k) * (e + d * r)) % n
    return r, s


m = "helloecdsa"
r = 0xDA7866632109E77F0D3C5BDD49031E6D9A940FCB7D29EA2F858B991D1F17CEF8
s = 0xA4A700AC4F18634AC845739E0342CD8335BF6E0606CA9DC9D668ABF9ED812E6D
Q = ec.Point(
    curve,
    0xA51208ADFF894CDD79D4D7D967AA4D492256BA4D527661B10AE7CFD6E15F28A6,
    0x6FBFD9A270CD717AFB0949E1C40FD2754B46F4F8472AC5711DE0351FE81BBD80,
)
d = 0x1d08a31305e240e0add3df2958063ad63160930d17c13af08f72038f13e02078

if sign(m, d) == (r, s):
    print(f"Correct secret key: {hex(d)}")
else:
    print(f"Wrong secret key")
