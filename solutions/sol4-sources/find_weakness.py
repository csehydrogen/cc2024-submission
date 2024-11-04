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


def inv(x):
    return ec.mod_inv(x, n)


def hash(msg):
    return int(sha256(msg.encode()).hexdigest(), 16)


m = "cryptoanalysiscontest"
r = 0xEB71F24CE44AA99D891BBA7623414355E63BF92A74D753F7CBAAB7831A357908
s = 0x8060D40BC3BF41F5D845E3EF6AE2270047A1E2A3E6C057BFC577D7D884089D47
d = 0xBDE07E98F0437A531C014A1FE6FD69C2CFB6C3657072696E7432303233383431
Q = d * G
e = hash(m)

k = inv(s) * (e + d * r) % n

print(f"ECDSA info of Cheolsoo")
print(f"{hex(d)=}")
print(f"{hex(e)=}")
print(f"{hex(k)=}")