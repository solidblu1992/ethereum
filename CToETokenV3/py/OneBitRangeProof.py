from py_ecc import bn128
from sha3 import keccak_256
from random import SystemRandom

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

def GenerateOneBitRangeProofs(count=16, asset_address=0x0000000000000000000000000000000000000000, compress_proofs=False):
    sr = SystemRandom()

    #Pick values and blinding factors
    private_commitments = [(sr.randint(0, 1), sr.getrandbits(256)) for i in range(0, count)]

    #Get generator points
    G1 = bn128.G1
    H = H_from_address(asset_address)

    #Initialize proof memory
    proofs = asset_address.to_bytes(20, 'big')

    for x in private_commitments:
        #Calculate Ring
        C = bn128.multiply(G1, x[1])
        
        if x[0] == 1:            
            C = bn128.add(C, H)

            #Random Numbers
            alpha = sr.getrandbits(256)
            s0 = sr.getrandbits(256)

            #Begin Ring
            A = bn128.multiply(G1, alpha)
            c0 = int.from_bytes(keccak_256(A[0].n.to_bytes(32, 'big') + A[1].n.to_bytes(32, 'big')).digest(), 'big')

            #Segment 0
            A = bn128.multiply(C, c0)
            B = bn128.multiply(G1, s0)
            A = bn128.add(A, B)
            c1 = int.from_bytes(keccak_256(A[0].n.to_bytes(32, 'big') + A[1].n.to_bytes(32, 'big')).digest(), 'big')

            #Complete Ring
            s1 = (alpha - c1*x[1]) % bn128.curve_order
            
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
            s0 = (alpha - c0*x[1]) % bn128.curve_order

        #Store proof data
        if compress_proofs:
            c_compressed = C[0].n

            if (C[1].n & 1 == 1):
                c_compressed |= 0x8000000000000000000000000000000000000000000000000000000000000000

            proofs += c_compressed.to_bytes(32, 'big')       
        else:
            proofs += C[0].n.to_bytes(32, 'big')
            proofs += C[1].n.to_bytes(32, 'big')

        proofs += c0.to_bytes(32, 'big')
        proofs += s0.to_bytes(32, 'big')
        proofs += s1.to_bytes(32, 'big')

    print("Proof:")
    print("0x", proofs.hex())

    return private_commitments, proofs

if __name__ == "__main__":
    private_commitments, proofs = GenerateOneBitRangeProofs(count=3)
    #private_commitments, proofs = GenerateOneBitRangeProofs(asset_address=0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359)

