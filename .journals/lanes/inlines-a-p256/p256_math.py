"""Minimal P-256 arithmetic for building forged/edge P256VERIFY inputs (test-vector generation only)."""
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

def on_curve(pt):
    if pt is None: return True
    x, y = pt
    return x < P and y < P and (y * y - (x * x * x + A * x + B)) % P == 0

def add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0: return None
        l = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (l * l - x1 - x2) % P
    return (x3, (l * (x1 - x3) - y1) % P)

def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r

def sign(d, z, k):
    """Raw ECDSA over the integer z (already reduced mod n); returns (r, s) with the given nonce k."""
    x, _ = mul(k, G)
    r = x % N
    s = pow(k, -1, N) * (z + r * d) % N
    assert r and s
    return r, s

def verify(z, r, s, q):
    """Software semantics of the p256/ecdsa crates: r,s in [1,n-1], q on curve and != O; z reduced mod n."""
    if not (0 < r < N and 0 < s < N) or q is None or not on_curve(q): return False
    z %= N
    w = pow(s, -1, N)
    pt = add(mul(z * w % N, G), mul(r * w % N, q))
    return pt is not None and pt[0] % N == r

def be(v, n=32): return v.to_bytes(n, 'big')
def inp(msg, r, s, q): return be(msg) + be(r) + be(s) + be(q[0]) + be(q[1])

if __name__ == '__main__':
    # self-check against the revm/daimo vector
    v = bytes.fromhex('4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e')
    z, r, s, x, y = (int.from_bytes(v[i:i+32], 'big') for i in range(0, 160, 32))
    assert verify(z, r, s, (x, y)) and not verify(z ^ 1, r, s, (x, y))
    d = 0x1234567; q = mul(d, G); z = 0xabcdef
    r, s = sign(d, z, 0x777)
    assert verify(z, r, s, q) and verify(z, r, N - s, q) and not verify(z + 1, r, s, q)
    print('p256_math ok')
