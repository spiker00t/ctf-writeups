from Crypto.Util.number import *
import os
from secret import flag

class LaSeine:
    def __init__(self, size):
        self.l = 20
        self.p = getStrongPrime(size)

        self.a = getRandomNBitInteger(size // 16)
        self.b = getRandomNBitInteger(size // 16)

    def split(self, f):
        if len(f) & 1:
            f += b"\x00"
        h = len(f) // 2
        return (bytes_to_long(f[:h]), bytes_to_long(f[h:]))

    def sign(self, m, b):
        xn, yn = self.split(m)
        k = (getRandomNBitInteger(self.l - 1) << 1) + b

        for _ in range(k):
            xnp1 = (self.a*xn + self.b*yn) % self.p
            ynp1 = (self.b*xn - self.a*yn) % self.p
            # ynp1 + xnp1 = (a+b)xn + (b-a)yn = b(xn+yn) + a(xn-yn) = aX + bY
            # ynp1 - xnp1 =                     b(xn-yn) - a(xn+yn) = bX - aY
            
            # (xnp1 + ynp1)^2 = b2(xn+yn)2 + 2ab(xn2-yn2) + a2(xn-yn)2
            # xn*xnp1 - yn*ynp1 = a*(xn2+yn2)
            # yn*xnp1 + xn*ynp1 = b*(yn2+xn2)
            # a = ((xn*xnp1) - (yn*ynp1))/(xn2+yn2)
            # b = ((yn*xnp1) + (xn*ynp1))/(xn2+yn2)
            # a2 + b2 = (((xn*xnp1) - (yn*ynp1))2 + ((yn*xnp1) + (xn*ynp1))2)/(xn2+yn2)2
            # a2 + b2 = ((xn2*xnp12 - 2*xn*yn*xnp1*ynp1 + yn2*ynp12) + (yn2*xnp12 + 2*xn*yn*xnp1*ynp1 + xn2*ynp12))/(xn2+yn2)2
            # a2 + b2 = ((xn2+yn2)*xnp12 + (xn2+yn2)*ynp12)/(xn2+yn2)2
            # a2 + b2 = (xnp1*xnp1 + ynp1*ynp1)/(xn2+yn2)
            #(xn2 + yn2) = (xnp12 + ynp12)/(a2 + b2)
            xn, yn = xnp1, ynp1
        return (k, xn, yn)

seine = LaSeine(1024)

_, xf, yf = seine.sign(flag, 1)
s2 = seine.sign(b"L'eau est vraiment froide par ici (et pas tres propre)", 0)

f = open("out.txt", "w")

f.write(str(seine.p) + "\n")
f.write(str((xf, yf)) + "\n")
f.write(str(s2))

f.close()
