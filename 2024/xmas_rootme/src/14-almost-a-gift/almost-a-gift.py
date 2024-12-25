from secrets import randbits
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, bytes_to_long

R, O, o, t, M, e = [getPrime(1337) for _ in "RootMe"]
gift = [
	R * O + randbits(666),
	R * o + randbits(666),
	R * t + randbits(666),
	R * M + randbits(666),
]

n = R * e
m = open("flag.txt", "rb").read()
c = bytes_to_long(PKCS1_OAEP.new(RSA.construct((n, 2 ** 16 + 1))).encrypt(m))
print(f"{n = }")
print(f"{c = }")
print(f"{gift = }")

# R divise gift[0]-gift[1]
