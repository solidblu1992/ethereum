from py_ecc import bn128
from sha3 import keccak_256
from random import SystemRandom

def IsPowerOf2(i):
    import math
    test = math.log(i, 2)
    return math.floor(test) == math.ceil(test)

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

def GetProofSizeAndCount(proof_bytes):
    #Only accept uncompressed proofs
    proof_size = 160
    proof_count = len(proof_bytes)-20
    assert(proof_count % proof_size == 0)
    proof_count = proof_count // proof_size
    return proof_size, proof_count

def GenerateOneBitRangeProofs(count=16, asset_address=0x0000000000000000000000000000000000000000, compress_proofs=False, print_proof=False):
    sr = SystemRandom()

    #Pick values and blinding factors
    #Pick equal number of each
    assert(IsPowerOf2(count))
    if count == 1:
        pc = [(sr.randint(0, 1), sr.getrandbits(256))]
        pcp = []
    else:
        pc = [(sr.randint(0, 1), sr.getrandbits(256)) for i in range(0, count // 2)]
        pcp = [(1 - pc[i][0], sr.getrandbits(256)) for i in range(0, count // 2)]
        
    private_commitments = pc + pcp

    if (count % 1 == 1):
        private_commitments += (sr.randint(0, 1), sr.getrandbits(256))

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

    if (print_proof):
        print("Proof:")
        print("0x" + proofs.hex())

    return private_commitments, proofs

def ExtractProof(proof_bytes, i):
    proof_size, proof_count = GetProofSizeAndCount(proof_bytes)
    assert(i < proof_count)

    #Store asset address
    out = proof_bytes[0:20]

    #Fetch proof
    out += proof_bytes[20+i*proof_size:20+(i+1)*proof_size]

    return out

def RecursiveMerkel(hashes):
    length = len(hashes)
    if length == 1:
        return hashes[0]
    elif length == 2:
        return keccak_256(hashes[0] + hashes[1]).digest()
    elif length == 3:
        return keccak_256(hashes[0] + hashes[1] + hashes[2]).digest()
    else:
        return keccak_256(RecursiveMerkel(hashes[0:length // 2]) + RecursiveMerkel(hashes[length // 2:])).digest()
    
def MerkelizeRangeProofs(proof_bytes):
    #Extract asset address
    asset_addr = proof_bytes[0:20]

    #Get size and count of proofs
    proof_size, proof_count = GetProofSizeAndCount(proof_bytes)
    assert(IsPowerOf2(proof_count))

    #Merkelize range proofs
    proof_hashes = [keccak_256(proof_bytes[20+i*proof_size:20+(i+1)*proof_size]).digest() for i in range(0, proof_count)]
    merkel_root = RecursiveMerkel(proof_hashes)

    #Hash in asset address
    final_hash = keccak_256(asset_addr + merkel_root).digest()
    return "0x" + final_hash.hex()

def GetMerkelProof(proof_bytes, index):
    #Extract asset address
    asset_addr = proof_bytes[0:20]

    #Get size and count of proofs
    proof_size, proof_count = GetProofSizeAndCount(proof_bytes)
    assert(IsPowerOf2(proof_count))
    assert(index < proof_count)

    #Merkelize range proofs
    merkel_row = [keccak_256(proof_bytes[20+i*proof_size:20+(i+1)*proof_size]).digest() for i in range(0, proof_count)]
    proof_hash = merkel_row[index]

    #Build merkel tree
    k = index
    hashes = []
    while len(merkel_row) > 1:
        #Index is on the left
        if k & 1 == 0:
            hashes += [merkel_row[k+1]]
        #Index is on the right
        else:
            hashes += [merkel_row[k-1]]

        #Advance k
        k >>= 1

        #Build new merkel row
        merkel_row = [keccak_256(merkel_row[2*i] + merkel_row[2*i+1]).digest() for i in range(0, len(merkel_row) // 2)]

    return (proof_hash, hashes, index, asset_addr)

def CheckMerkelProof(merkel_proof):
    proof_hash, hashes, index, asset_addr = merkel_proof[0], merkel_proof[1], merkel_proof[2], merkel_proof[3]
    #Check merkel tree
    k = index
    final_hash = proof_hash
    for h in hashes:
        #Index is on the left
        if k & 1 == 0:
            final_hash = keccak_256(final_hash + h).digest()
        #Index is on the right
        else:
            final_hash = keccak_256(h + final_hash).digest()

        #Advance k
        k >>= 1

    #Hash in asset address
    final_hash = keccak_256(asset_addr + final_hash).digest()
    return "0x" + final_hash.hex()

def PrintMerkelProof(range_proof, index):
    #Print out single merkel proof for solidity
    mp = GetMerkelProof(range_proof, index)
    rp = ExtractProof(range_proof, index)

    print("Merkel Proof")
    print("0x" + rp.hex() + ",", end="")

    print("[", end="")
    for i in range(0, len(mp[1])):
        print("\"0x" + mp[1][i].hex() + "\"", end="")
        if i < len(mp[1])-1:
            print(",", end="")

    print("]," + str(index))

def ExtractCommitmentsFromProof(proof_bytes):
    proof_size, proof_count = GetProofSizeAndCount(proof_bytes)

    #Do not store asset address
    out = bytes()

    #Fetch commitments
    for i in range(0, proof_count):
        out += proof_bytes[20+i*proof_size:20+i*proof_size+64]
        
    return out

def ExtractCommitments(commitment_bytes):
    #Get asset address, size, and commitment count
    asset_address = None
    commitment_size = 64
    commitment_count = len(commitment_bytes)
    
    #May or may not contain asset address
    if (commitment_count % commitment_size != 0):
        commitment_count -= 20
        asset_address = commitment_bytes[0:20]

    assert(commitment_count % commitment_size == 0)
    commitment_count = commitment_count // commitment_size

    commitments = [None]*commitment_count        
    if asset_address == None:
        for i in range(0, commitment_count):
            start = i*commitment_size
            x = int.from_bytes(commitment_bytes[start:start+32], 'big')
            y = int.from_bytes(commitment_bytes[start+32:start+64], 'big')
            commitments[i] = (x,y)
    else:
        for i in range(0, commitment_count):
            start = 20+i*commitment_size
            x = int.from_bytes(commitment_bytes[start:start+32], 'big')
            y = int.from_bytes(commitment_bytes[start+32:start+64], 'big')
            commitments[i] = (x,y)
            
    return asset_address, commitments

def MixCommitments(a_bytes, b_bytes):
    #Fetch individual commitments
    a_asset, a_commitments = ExtractCommitments(a_bytes)
    b_asset, b_commitments = ExtractCommitments(b_bytes)

    #Create Mixture
    c_bytes = bytes()
    for i in range(0, len(a_commitments)):
        A = (bn128.FQ(a_commitments[i][0]), bn128.FQ(a_commitments[i][1]))
            
        for j in range(0, len(b_commitments)):
            B = (bn128.FQ(b_commitments[j][0]), bn128.FQ(b_commitments[j][1]))

            C = bn128.add(A, B)
            c_bytes += C[0].n.to_bytes(32, 'big') + C[1].n.to_bytes(32, 'big')

    return c_bytes

def MerkelizeCommitments(c_bytes):
    a_asset, c_commitments = ExtractCommitments(c_bytes)
    assert(IsPowerOf2(len(c_commitments)))

    #Merkelize range proofs
    c_hashes = [keccak_256(c_commitments[i][0].to_bytes(32, 'big') + c_commitments[i][1].to_bytes(32, 'big')).digest() for i in range(0, len(c_commitments))]
    merkel_root = RecursiveMerkel(c_hashes)

    #Hash in asset address
    if a_asset != None:
        final_hash = keccak_256(a_asset + merkel_root).digest()
    else:
        final_hash = merkel_root
           
    return "0x" + final_hash.hex()

if __name__ == "__main__":
    #Create Proofs and test Merkel Proofs
    proof_count = 2
    private_commitments, proofs = GenerateOneBitRangeProofs(asset_address=0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359, count=proof_count)
    
    proof_hash = MerkelizeRangeProofs(proofs)
    print("proof_hash:\t" + proof_hash)

    for i in range(0, proof_count):
        merkel_proof = GetMerkelProof(proofs, i)
        test_hash = CheckMerkelProof(merkel_proof)
        print("test_hash[" + str(i) + "]:\t" + test_hash)



