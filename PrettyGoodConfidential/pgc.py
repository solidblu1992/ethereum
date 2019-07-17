from random import SystemRandom
from py_ecc import bn128
from sha3 import keccak_256

H = (bn128.FQ(0x231c7944cd500565013d56c25cc8c77a6613cb6b2ccd0831240d1e8d3eea33e3),
     bn128.FQ(0x909c50f22cfb8da32dc5a2ad0380e1c0f5b0d9860dd49a566da7f77c600d03c))

def Gen():

    sk = SystemRandom().getrandbits(256)
    pk = bn128.multiply(bn128.G1, sk)

    return (sk, pk)

def Enc(pk, m, r):
    X = bn128.multiply(pk, r)
    Y = bn128.add(bn128.multiply(bn128.G1, r), bn128.multiply(H, m))
    return (X, Y)

def Dec(sk, X, Y):
    sk_inv = pow(sk, bn128.curve_order - 2, bn128.curve_order)
    denom = bn128.multiply(X, sk_inv)
    denom = (denom[0], -denom[1])

    Hm = bn128.add(Y, denom)
    P_test = H

    m = 1
    while not bn128.eq(Hm, P_test):
        m += 1
        P_test = bn128.add(P_test, H)
    
    return m

def Prove(pk1, X1, Y1, pk2, X2, Y2, r1, r2, v):
    sr = SystemRandom()
    
    #Prover Stage 1
    a1 = sr.getrandbits(256)
    a2 = sr.getrandbits(256)
    b = sr.getrandbits(256)

    A1 = bn128.multiply(pk1, a1)
    A2 = bn128.multiply(pk2, a2)
    B1 = bn128.add(bn128.multiply(bn128.G1, a1), bn128.multiply(H, b))
    B2 = bn128.add(bn128.multiply(bn128.G1, a2), bn128.multiply(H, b))

    #Fiat Shamir
    hasher = keccak_256()
    hasher.update(A1[0].n.to_bytes(32, 'big'))
    hasher.update(A1[1].n.to_bytes(32, 'big'))
    hasher.update(A2[0].n.to_bytes(32, 'big'))
    hasher.update(A2[1].n.to_bytes(32, 'big'))
    hasher.update(B1[0].n.to_bytes(32, 'big'))
    hasher.update(B1[1].n.to_bytes(32, 'big'))
    hasher.update(B2[0].n.to_bytes(32, 'big'))
    hasher.update(B2[1].n.to_bytes(32, 'big'))
    e = int.from_bytes(hasher.digest(), 'big')

    #Prover Stage 2
    z1 = (a1 + e*r1) % bn128.curve_order
    z2 = (a2 + e*r2) % bn128.curve_order
    z3 = (b + e*v) % bn128.curve_order

    return (z1, z2, z3)

def Verify(pk1, X1, Y1, pk2, X2, Y2, A1, A2, B1, B2, z1, z2, z3):
    #Fiat Shamir
    hasher = keccak_256()
    hasher.update(A1[0].n.to_bytes(32, 'big'))
    hasher.update(A1[1].n.to_bytes(32, 'big'))
    hasher.update(A2[0].n.to_bytes(32, 'big'))
    hasher.update(A2[1].n.to_bytes(32, 'big'))
    hasher.update(B1[0].n.to_bytes(32, 'big'))
    hasher.update(B1[1].n.to_bytes(32, 'big'))
    hasher.update(B2[0].n.to_bytes(32, 'big'))
    hasher.update(B2[1].n.to_bytes(32, 'big'))
    e = int.from_bytes(hasher.digest(), 'big')

    #Verifier checks
    left = bn128.add(A1, bn128.multiply(X1, e))
    right = bn128.multiply(pk1, z1)
    if not eq(left, right):
        return False

    left = bn128.add(A2, bn128.multiply(X2, e))
    right = bn128.multiply(pk2, z2)
    if not eq(left, right):
        return False

    left = bn128.add(B1, bn128.multiply(Y1, e))
    right = bn128.add(bn128.multiply(bn128.G1, z1), bn128.multiply(H, z3))
    if not eq(left, right):
        return False

    left = bn128.add(B2, bn128.multiply(Y2, e))
    right = bn128.add(bn128.multiply(bn128.G1, z2), bn128.multiply(H, z3))
    if not eq(left, right):
        return False

    return True
    
if __name__ == "__main__":
    #Examples
    sk, pk = Gen()

    m = 100
    r = SystemRandom().getrandbits(256)
    X, Y = Enc(pk, m, r)
    m_prime = Dec(sk, X, Y)
