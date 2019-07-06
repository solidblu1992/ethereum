from py_ecc import bn128
from sha3 import keccak_256
from random import SystemRandom

#"Private Keys"
sr = SystemRandom()
asset_address = 0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359 #DAI
v = 1
bf = sr.getrandbits(256)

G1 = bn128.G1

#Get asset H
def H_from_address(address):
    x = bn128.FQ(int.from_bytes(keccak_256(address.to_bytes(20,'big')).digest(), 'big'))

    on_curve = False
    while not on_curve:
        y2 = x**3 + bn128.b
        y = y2**((bn128.field_modulus+1)//4)

        if (y**2 == y2):
            on_curve = True
        else:
            x += 1

    return (x, y)

if asset_address == 0:
    H = (   bn128.FQ(0x2854ddec56b97fb3a6d501b8a6ff07891ce7aeb22c1cc74cf0a18ebc3f15220b),
            bn128.FQ(0x23a967b0d240d4264fea929d6a02ba4b7c612c0a4ef611e92eb011aa854cdbf7)    )
else:
    H = H_from_address(asset_address)

#Calculate Ring
C = bn128.multiply(G1, bf)
if v==1:
    C = bn128.add(C, H)

    #"Random Numbers"
    alpha = sr.getrandbits(256)
    s0 = sr.getrandbits(256)

    #Being Ring
    A = bn128.multiply(G1, alpha)
    c0 = int.from_bytes(keccak_256(A[0].n.to_bytes(32, 'big') + A[1].n.to_bytes(32, 'big')).digest(), 'big')

    #Segment 0
    A = bn128.multiply(C, c0)
    B = bn128.multiply(G1, s0)
    A = bn128.add(A, B)
    c1 = int.from_bytes(keccak_256(A[0].n.to_bytes(32, 'big') + A[1].n.to_bytes(32, 'big')).digest(), 'big')

    #Complete Ring
    s1 = (alpha - c1*bf) % bn128.curve_order
    
else:
    #"Random Numbers"
    alpha = sr.getrandbits(256)
    s1 = sr.getrandbits(256)
    
    #Being Ring
    A = bn128.multiply(G1, alpha)
    c1 = int.from_bytes(keccak_256(A[0].n.to_bytes(32, 'big') + A[1].n.to_bytes(32, 'big')).digest(), 'big')

    #Segment 1
    Cp = bn128.add(C, (H[0], -H[1])) 
    A = bn128.multiply(Cp, c1)
    B = bn128.multiply(G1, s1)
    A = bn128.add(A, B)
    c0 = int.from_bytes(keccak_256(A[0].n.to_bytes(32, 'big') + A[1].n.to_bytes(32, 'big')).digest(), 'big')

    #Complete Ring
    s0 = (alpha - c0*bf) % bn128.curve_order

#Output
print(hex(C[0].n))
print(hex(C[1].n))
print(hex(H[0].n))
print(hex(H[1].n))
print(hex(c0))
print(hex(s0))
print(hex(s1))



