# 404CTF 2024 - Write-Up for the challenge *La Seine* (Crypto)

**TL;DR:** Custom signature algorithm, based on 2x2-matrix
operations. Sum of two squares theorem.

![challenge](./img/chall.png)

**Description (in French):** La compétition d'apnée est sur le point
de commencer, l'eau est un peu trouble mais les épreuves précédentes
ont sculpté votre détermination. Au moment où vous vous apprêtez à
rentrer dans l'eau, votre entraineur vous ordonne d'un ton sevère :
"Lorsque tu mettras la tête sous l'eau, ne ressors pas avant d'avoir
réussi ce problème, bonne chance à toi". Vous prenez une grande
inspiration et plongez la tête baissée dans ce problème :

**Approximate translation:** The free diving competition is about to
start, the water is not very clean but previous challenges made you
full of determination. When you are about to enter in the water, your
coach order you severely: "When you will put your head under water, do
not get out until you solved this problem, good luck". You take a good
breath and dive, your head down, in this problem.

## Introduction

For this challenge, we are given

- the following Python script `LaSeine.py`
```python
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
```

- its output `out.txt`
```
179358513830906148619403250482250880334528756349120678091666297907253922185623290723862265402777434007178297319701286775733620488613530869850160450412929764046707392082705800333548316425165863556480623955587411083384086805686199851628022437853672200835000268893800610064747558825805271528526924659142504913631
(151683403543233106224623577311980037274441590153911847119566701699367001537936290730922138442040542620222943385810242081949211326676472369180020899628646165132503185978510932501521730827126356422842852151275382840062708701174847422687809816503983740455064453231285796998931373590630224653066573035583863902921, 76688287388975729010764722746414768266232185597001389966088556498895611351239273625106383329192109917896575986761053032041287081527278426860237114874927478625771306887851752909713110684616229318569024945188998933167888234990912716799093707141023542980852524005127986940863843004517549295449194995101172400759)
(929382, 118454610237220659897316062413105144789761952332893713333891996727204456010112572423850661749643268291339194773488138402728325770671625196790011560475297285424138262812704729573910897903628228179414627406601128765472041473647769084599481166191241495167773352105622894240398746332477947478817552973851804951566, 65891615565820497528921288257089595342791556688007325193257144738940922602117787746412089423500836495505254334866586155889060897532850381510520943387446058037766901712521471259853536310481267471645770625452422081411718151580380288380630522313377397166067417623947500542258985636659962524606869196898543973764)
```

The algorithm is a custom signature algorithm. Its parameters are
initialized as follows  (function `__init__`):
- $p$ is a random 1024-bit prime number
- $a$ and $b$ are random 64-bit numbers

To sign a given message (function `sign`), it performs the following operations:
- Split the message in two parts, convert the corresponding bytes to
  numbers $x$ and $y$
- Choose a random 20-bit number of iterations $k$
- At each iteration, $x$ and $y$ are updated respectively with the values $ax + by$ and $bx - ay$.
- Return the final values of $x$ and $y$, along with $k$.

For the challenge, we are given:
- the value of $p$,
- the signature of a known message "L'eau est vraiment froide par ici (et pas tres propre)" (in English: "The water is really cold there (and not very clean)") **with $k$ even**,
- part of the signature of the flag **with $k$ odd** (the final $x$ and $y$ are given but not $k$). 

## The Problem

