import hashlib
from pwn import *

seed = 0x7b118535

def rand():
    global seed
    w = (seed >> 24)
    x = w >> 1 ^ w
    y = x << 1 ^ x
    z = seed & 0xff
    seed <<= 8
    seed += ((z >> 3 ^ z ^ y) & 0xff)
    seed &= 0xffffffff
    return seed & 0xff

to_hash = b''

def rand_pos():
    x = rand() & 0xf8
    y = rand() & 0xf8
    
    if x == 0xf8:
        x = 0xf0
    elif x == 0:
        x = 8

    if y == 0:
        y = 0x10
    elif y <= 0xf:
        y = 0x18
    elif y > 0xdf:
        y = y & 0x7f
        
    return (x,y)

nb_enemies = 0x1e8480
chunks = []

for i in range(nb_enemies):
    if i % 100000 == 0:
        print(i)
    x,y = rand_pos()

    # to simulate the calls to rand() for the new remaining time
    rand()
    rand()

    # x, y, lost, remaining_enemies
    cur_to_hash = p8(x) + p8(y) + b'\x00' + p32(nb_enemies-i-1)
    chunks.append(cur_to_hash)
    
to_hash = b''.join(chunks)
    
h = hashlib.sha256()
h.update(to_hash)
print("FCSC{%s}" % h.hexdigest())
