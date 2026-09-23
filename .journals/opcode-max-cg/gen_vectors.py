import json, hashlib
from py_ecc import bn128, bls12_381 as bls
from py_ecc.secp256k1 import secp256k1
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def be(x, n): return int(x).to_bytes(n, 'big')
V = {}
# --- bn254 (EIP-196/197) ---
G1, G2 = bn128.G1, bn128.G2
def bn_g1(p): return be(p[0], 32) + be(p[1], 32)
def bn_g2(p):  # EIP-197: imaginary coefficient first
    x, y = p
    return be(x.coeffs[1], 32) + be(x.coeffs[0], 32) + be(y.coeffs[1], 32) + be(y.coeffs[0], 32)
negG1 = bn128.neg(G1)
V['bn254_add'] = (bn_g1(G1) + bn_g1(bn128.multiply(G1, 7))).hex()
V['bn254_mul'] = (bn_g1(G1) + be(bn128.curve_order - 1, 32)).hex()  # full-size scalar
V['bn254_mul_small'] = (bn_g1(G1) + be(2, 32)).hex()
V['bn254_pair1'] = (bn_g1(G1) + bn_g2(G2)).hex()   # result false (0)
pair_ok = bn_g1(G1) + bn_g2(G2) + bn_g1(negG1) + bn_g2(G2)  # e(G1,G2)e(-G1,G2)=1 → true
V['bn254_pair2'] = pair_ok.hex()
V['bn254_pair4'] = (pair_ok * 2).hex()
V['bn254_pair8'] = (pair_ok * 4).hex()
# --- BLS12-381 (EIP-2537) ---
def fp(x): return be(0, 16) + be(x, 48)
def bls_g1(p): return fp(p[0]) + fp(p[1])
def bls_g2(p):
    x, y = p
    return fp(x.coeffs[0]) + fp(x.coeffs[1]) + fp(y.coeffs[0]) + fp(y.coeffs[1])
bG1, bG2 = bls.G1, bls.G2
V['bls_g1add'] = (bls_g1(bG1) + bls_g1(bls.multiply(bG1, 5))).hex()
V['bls_g2add'] = (bls_g2(bG2) + bls_g2(bls.multiply(bG2, 5))).hex()
sc = be(bls.curve_order - 1, 32)
def g1msm(k): return b''.join(bls_g1(bls.multiply(bG1, i + 2)) + sc for i in range(k))
def g2msm(k): return b''.join(bls_g2(bls.multiply(bG2, i + 2)) + sc for i in range(k))
for k in (1, 2, 8, 32, 128): V[f'bls_g1msm{k}'] = g1msm(k).hex()
for k in (1, 2, 8, 32): V[f'bls_g2msm{k}'] = g2msm(k).hex()
bpair_ok = bls_g1(bG1) + bls_g2(bG2) + bls_g1(bls.neg(bG1)) + bls_g2(bG2)
V['bls_pair1'] = (bls_g1(bG1) + bls_g2(bG2)).hex()
V['bls_pair2'] = bpair_ok.hex()
V['bls_pair4'] = (bpair_ok * 2).hex()
V['bls_pair8'] = (bpair_ok * 4).hex()
V['bls_mapg1'] = fp(123456789).hex()
V['bls_mapg2'] = (fp(123456789) + fp(987654321)).hex()
# --- ecrecover ---
priv = (7).to_bytes(32, 'big')
msg = hashlib.sha256(b'jeth').digest()
v, r, s = secp256k1.ecdsa_raw_sign(msg, priv)
pub = secp256k1.privtopub(priv)
addr = hashlib.new('sha3_256')  # placeholder; keccak below
def keccak(b):
    from Crypto.Hash import keccak as K
    return K.new(digest_bits=256, data=b).digest()
try:
    exp_addr = keccak(be(pub[0], 32) + be(pub[1], 32))[12:]
except Exception:
    exp_addr = None
V['ecrecover'] = (msg + be(v, 32) + be(r, 32) + be(s, 32)).hex()
V['ecrecover_expected'] = exp_addr.hex() if exp_addr else None
# --- modexp (Osaka EIP-7883) ---
def modexp(B, E, M):
    return (be(len(B), 32) + be(len(E), 32) + be(len(M), 32) + B + E + M).hex()
ones32 = b'\xff' * 32; odd1024 = b'\xff' * 1023 + b'\xfd'; even1024 = b'\xff' * 1023 + b'\xfe'
V['modexp_32_32_32'] = modexp(b'\x12' * 32, b'\x7f' + b'\xff' * 31, b'\xff' * 31 + b'\xfd')   # E 255 bits set
V['modexp_32_e1_32'] = modexp(b'\x12' * 32, be(1, 32), b'\xff' * 31 + b'\xfd')
V['modexp_32_e2_32'] = modexp(b'\x12' * 32, be(2, 32), b'\xff' * 31 + b'\xfd')
V['modexp_1024_32_1024'] = modexp(b'\x12' * 1024, ones32, odd1024)
V['modexp_1024_e1_1024'] = modexp(b'\x12' * 1024, be(1, 32), odd1024)
V['modexp_1024_32_1024even'] = modexp(b'\x12' * 1024, ones32, even1024)
V['modexp_32_1024_32'] = modexp(b'\x12' * 32, b'\xff' * 1024, b'\xff' * 31 + b'\xfd')
V['modexp_256_32_256'] = modexp(b'\x12' * 256, ones32, b'\xff' * 255 + b'\xfd')
V['modexp_64_32_64'] = modexp(b'\x12' * 64, ones32, b'\xff' * 63 + b'\xfd')
V['modexp_8_32_8'] = modexp(b'\x12' * 8, ones32, b'\xff' * 7 + b'\xfd')
V['modexp_1_1_1'] = modexp(b'\x02', b'\x03', b'\x05')
# --- blake2f ---
def blake2f(rounds):
    return (be(rounds, 4) + b'\x6a\x09\xe6\x67\xf3\xbc\xc9\x08' * 8 + b'\x00' * 128 + b'\x00' * 16 + b'\x01').hex()
V['blake2f_1'] = blake2f(1); V['blake2f_12'] = blake2f(12); V['blake2f_1000'] = blake2f(1000); V['blake2f_0'] = blake2f(0)
# --- KZG point evaluation: zero polynomial (commitment/proof = infinity) ---
comm = b'\xc0' + b'\x00' * 47
vh = b'\x01' + hashlib.sha256(comm).digest()[1:]
V['kzg'] = (vh + be(0, 32) + be(0, 32) + comm + comm).hex()
# --- P256VERIFY ---
key = ec.derive_private_key(12345, ec.SECP256R1())
h = hashlib.sha256(b'jeth p256').digest()
sig = key.sign(h, ec.ECDSA(hashes.SHA256()))  # signs sha256(h)
r_, s_ = decode_dss_signature(sig)
pn = key.public_key().public_numbers()
V['p256verify'] = (hashlib.sha256(h).digest() + be(r_, 32) + be(s_, 32) + be(pn.x, 32) + be(pn.y, 32)).hex()
json.dump(V, open('/tmp/opcg/vectors.json', 'w'), indent=0)
print({k: len(v) // 2 for k, v in V.items() if v})
