from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long

sk = RSA.generate(2048)
pk = sk.public_key()
rebel = pk.n
santa = pow(sk.p + sk.q, 25_12, sk.n) # Y
alliance = pow(sk.p + 2024,  sk.q, sk.n) # X
grinch = bytes_to_long(PKCS1_OAEP.new(pk).encrypt(open("flag.txt", "rb").read()))
print(f"{rebel = }")
print(f"{santa = }")
print(f"{alliance = }")
print(f"{grinch = }")







# Y = (p+q)^2512 = p^2512 + q^2512 mod n

# (X-2024) = p + k*q

# (X-2024)^2512 = p^2512 + k^2512*q^2512 mod n
# ... = (Y - q^2512) + k^2512*q^2512 mod n
# ... - Y = (k^2512-1)*q^2512 mod n

# (X-2024)^2512 - Y     est un multiple de q^2512.

# (X-2024)^2512 = p^2512 + k^2512*(Y-p^2512) mod n
# (X-2024)^2512 - k^2512*Y = (1-k^2512)*p^2512 mod n



# Fermat : (p+2024)^q = (p+2024) mod q
# (p+2024)^q = 2024^q mod p
# mais mod pq on n'en sait rien...

# X = (p+2024)^q = (p+2024) mod q
# donc (p+2024)^q = (p+2024)+k*q = 2024^q + k'*p

# donc p*(p+2024)^q = p^2+2024*p mod n
# donc -p^2 + p*X - 2024*p = 0 mod n
# donc p(-p + (X-2024)) = 0 mod n
# donc p(-p + (X-2024)) = k'*n = k'*p*q
# donc (-p + (X-2024)) = k'*q (en boucle !)

# X = p + 2024 + k*q
# XY = (p + 2024 + k*q)(p^2512 + q^2512)
# XY = p^2513 + 2024(p^2512 + q^2512) + k*q^2513
# XY = p^2512(p + 2024) + q^2512(k*q + 2024)

# X^p = X mod p = X + k'*p
# X^p = k'*p + k*q + 2024

# qX = q*2024^q mod n

# qX = 2024q + kq^2 mod n
# kq^2 + q(2024-X) = 0 mod n

# p^2 + p(2024-X) = 0 mod n.

# X = 2024^q mod p = 2024^q + k''*p

# Y = (X-2024-k*q)^2512 + q^2512

# p = X-2024 mod q
# p^2 = p(X-2024) mod n
# p^2512 = p^1256*(X-2024)^1256
# Y-q^2512 = p^1256*(X-2024)^1256
