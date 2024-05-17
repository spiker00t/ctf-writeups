from Crypto.Util.number import bytes_to_long, long_to_bytes

p = 179358513830906148619403250482250880334528756349120678091666297907253922185623290723862265402777434007178297319701286775733620488613530869850160450412929764046707392082705800333548316425165863556480623955587411083384086805686199851628022437853672200835000268893800610064747558825805271528526924659142504913631

# Flag signature
(xsf, ysf) = (151683403543233106224623577311980037274441590153911847119566701699367001537936290730922138442040542620222943385810242081949211326676472369180020899628646165132503185978510932501521730827126356422842852151275382840062708701174847422687809816503983740455064453231285796998931373590630224653066573035583863902921, 76688287388975729010764722746414768266232185597001389966088556498895611351239273625106383329192109917896575986761053032041287081527278426860237114874927478625771306887851752909713110684616229318569024945188998933167888234990912716799093707141023542980852524005127986940863843004517549295449194995101172400759)

# Known signature
known = b"L'eau est vraiment froide par ici (et pas tres propre)"
(kk, xsk, ysk) = (929382, 118454610237220659897316062413105144789761952332893713333891996727204456010112572423850661749643268291339194773488138402728325770671625196790011560475297285424138262812704729573910897903628228179414627406601128765472041473647769084599481166191241495167773352105622894240398746332477947478817552973851804951566, 65891615565820497528921288257089595342791556688007325193257144738940922602117787746412089423500836495505254334866586155889060897532850381510520943387446058037766901712521471259853536310481267471645770625452422081411718151580380288380630522313377397166067417623947500542258985636659962524606869196898543973764)

def split(f):
    if len(f) & 1:
        f += b"\x00"
    h = len(f) // 2
    return (bytes_to_long(f[:h]), bytes_to_long(f[h:]))

F = GF(p)

# Step 1: Exploit the known signature to retrieve C

(k1, k2) = split(known)

C = (F(xsk)/F(k1)).nth_root(kk/2)

assert (F(xsk)/F(k1) == C**(kk/2))
assert (F(ysk)/F(k2) == C**(kk/2))

print("[+] C = a^2 + b^2 = %s" % C)

# Step 2: Recover k

S = F(xsf)**2 + F(ysf)**2

print("[+] xs^2 + ys^2 = %s" % S)
kf_cands = []

print("[*] Recovering k...")

for kf_cand in range(2**20):
    l = len(str(S/(C**kf_cand)))
    if l < 300:
        kf_cands.append(kf_cand)

kf = kf_cands[-1]
# kf = 691699

print("[+] Recovered k: %d" % kf)

# We can deduce x0² + y0², x1 and y1

S0 = S/(C**kf)
print("[+] x0^2 + y0^2 = %s" % S0)

(xfp1, yfp1) = F(xsf)/(C**(kf//2)), F(ysf)/(C**(kf//2))

assert ((F(xfp1)**2 + F(yfp1)**2) == C*S0)

print("[+] x1 = %s, y1 = %s" % (xfp1, yfp1))

# Step 3: List the candidates for a and b

factors = list(factor(int(C)))
print("[+] Factors of C: %s" % factors)

f1 = []
f3 = []

for (p,k) in factors:
    if p%4 == 3:
        f3.append((p,k))
    else:
        f1.append((p,k))

squares = []
        
for (p,k) in f1:
    squares.append((two_squares(p), k))

print("[+] Square decompositions: %s" % squares)

a_b_cands = []

for l in range(2**(len(squares)-1)):
    z = 3
    for j in range(len(squares)):
        ((x,y),k) = squares[j]
        if (l >> j) & 1 == 0:
            z *= (x+i*y)**k
        else:
            z *= (y+i*x)**k
    # we only keep positive candidates
    a_cand,b_cand = (abs(real(z)),abs(imag(z)))
    assert(F(a_cand)**2 + F(b_cand)**2 == C)
    a_b_cands.append((a_cand,b_cand))
    a_b_cands.append((b_cand,a_cand))

for (a,b) in a_b_cands:
    xf = (F(a)*xfp1 + F(b)*yfp1)/C
    yf = (F(b)*xfp1 - F(a)*yfp1)/C
    if xf**2 + yf**2 == S0 and len(str(xf)) < 300:
        print("[+] Recovered x0 = %s, y0 = %s" % (xf, yf))
        break

print("[+] FLAG: %s" % (bytes.fromhex(hex(xf)[2:]) + bytes.fromhex(hex(yf)[2:])))
