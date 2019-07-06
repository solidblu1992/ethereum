from py_ecc import bn128
from sha3 import keccak_256
from random import SystemRandom

#"Private Keys"
sr = SystemRandom()
p = sr.getrandbits(256)
q = sr.getrandbits(256)

#"Random Numbers"
alpha = sr.getrandbits(256)
s0 = sr.getrandbits(256)

G1 = bn128.G1
P = bn128.multiply(G1, p)
Q = bn128.multiply(G1, q)

#Being Ring
A = bn128.multiply(G1, alpha)
c0 = int.from_bytes(keccak_256(A[0].n.to_bytes(32, 'big') + A[1].n.to_bytes(32, 'big')).digest(), 'big')

#Segment 0
A = bn128.multiply(P, c0)
B = bn128.multiply(G1, s0)
A = bn128.add(A, B)
c1 = int.from_bytes(keccak_256(A[0].n.to_bytes(32, 'big') + A[1].n.to_bytes(32, 'big')).digest(), 'big')

#Complete Ring
s1 = (alpha - c1*q) % bn128.curve_order

#Mix Ring
if sr.randrange(0,2)==0:
    P, Q, c0, s0, s1 = Q, P, c1, s1, s0

#Output
print(hex(P[0].n))
print(hex(P[1].n))
print(hex(Q[0].n))
print(hex(Q[1].n))
print(hex(c0))
print(hex(s0))
print(hex(s1))



