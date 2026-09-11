import random
q = 2**256 - 2**32 - 977; pc = 2**256 - q; M = 2**64
K = 2**256 + 2 - 3*pc; k0 = K % M
assert K >> 64 == 2**192 - 1  # limbs 1..3 = MAX
print("pc=%d=0x%X  pc-1=0x%X  q0=0x%X  k0=0x%X" % (pc, pc, pc-1, q % M, k0))
def modsub(a, b):            # 26-row block: t = a-b mod 2^256, beta, d = t - beta*pc (mod 2^256)
    t = (a - b) % 2**256; beta = int(a < b); d = (t - beta*pc) % 2**256; return d
def limbs(v): return [(v >> (64*i)) % M for i in range(4)]
def rc(v): l = limbs(v); return not (l[1] & l[2] & l[3] == M-1 and l[0] >= q % M)  # range check v<q
worst = [0,0,0]
for it in range(200000):
    mode = random.random()
    if mode < 0.3:   # adversarial-ish: values near q, tiny lambda
        x1, x2 = random.choice([q-1, q-2, q-pc, 1, 0, random.randrange(q)]), random.choice([q-1, q-3, q-2*pc, 2, random.randrange(q)])
        y1, y2 = random.choice([q-1, 0, 1, random.randrange(q)]), random.choice([q-1, 0, random.randrange(q)])
    else:
        x1, x2, y1, y2 = (random.randrange(q) for _ in range(4))
    if x1 == x2: continue
    d = modsub(x1, x2); assert d == (x1 - x2) % q and 0 < d < q
    lam = (y1 - y2) * pow(d, -1, q) % q
    x3 = (lam*lam - x1 - x2) % q; y3 = (lam*(x1 - x3) - y1) % q
    dp = modsub(x1, x3); assert dp == (x1 - x3) % q
    # identities
    W1, r = divmod(lam*d + y2 - y1, q); assert r == 0 and 0 <= W1 < 2**256
    nx1, nx2, ny1 = 2**256-1-x1, 2**256-1-x2, 2**256-1-y1
    W2, r = divmod(lam*lam + nx1 + nx2 + K - x3, q); assert r == 0 and 0 <= W2 < 2**256
    W3, r = divmod(lam*dp + ny1 - (y3 + pc - 1), q); assert r == 0 and 0 <= W3 < 2**256
    assert y3 + pc - 1 < 2**256
    # LHS totals must not wrap 2^512 (exactness argument)
    L1 = lam*d + y2 + W1*pc; L2 = lam*lam + nx1 + nx2 + K + W2*pc; L3 = lam*dp + ny1 + W3*pc
    assert L1 < 2**512 and L2 < 2**512 and L3 < 2**512
    assert L1 == 2**256*W1 + y1 and L2 == 2**256*W2 + x3 and L3 == 2**256*W3 + (y3 + pc - 1)
    assert rc(x3) and rc(y3)
    worst = [max(worst[0], W1.bit_length()), max(worst[1], W2.bit_length()), max(worst[2], W3.bit_length())]
    # uniqueness: any other lambda' != lam mod q fails (1)
    lam2 = (lam + random.randrange(1, q)) % q
    assert (lam2*d + y2 - y1) % q != 0
print("ok; max W bits", worst)
# lambda = 0 case: P + phi(P) shares y (beta x). verify with generator
beta = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A6855419 * 2**0
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
x1, y1, x2, y2 = Gx, Gy, beta*Gx % q, Gy
d = modsub(x1, x2); lam = (y1-y2)*pow(d,-1,q) % q; assert lam == 0
x3 = (-x1-x2) % q; y3 = (-y1) % q
W1 = (0*d + y2 - y1)//q; assert W1 == 0
print("lambda=0 case ok; W2 =", (lam*lam + (2**256-1-x1) + (2**256-1-x2) + K - x3)//q)
