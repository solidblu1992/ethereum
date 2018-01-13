from bn128_curve import *
from aes import *
import sha3
from ring_signatures import *

class StealthTransaction:
    dest_pub_key = 0
    dest_dhe_point = 0
    dest_encrypted_data = 0
    
    def __init__(self, pub_key, dhe_point, encrypted_data):
        self.dest_pub_key = pub_key
        self.dest_dhe_point = dhe_point
        self.dest_encrypted_data = encrypted_data

class PCRangeProof:
    pow10 = 0
    offset = 0
    total_commitment = 0
    range_proof = 0
    
    def __init__(self, pow10, offset, total_commitment, range_proof):
        self.pow10 = pow10
        self.offset = offset
        self.total_commitment = total_commitment
        self.range_proof = range_proof

    def Verify(self):
        L = len(self.range_proof.pub_keys)
        if (L % 4 != 0): return False
        L = L // 4
        
        #Check that bitwise commitments add up
        point = multiply(H, self.offset)
        for i in range(0, L):
            point = add(point, self.range_proof.pub_keys[i])

        if (not eq(point, self.total_commitment)): return False

        #Check that counter commitments are OK
        for i in range(0, L):
            point = self.range_proof.pub_keys[i]
            subtract = neg(multiply(H, (4**i)*(10**self.pow10)))

            for j in range(1, 4):
                point = add(point, subtract)
                if (not eq(point, self.range_proof.pub_keys[j*L + i])): return False
                        
        if(self.range_proof.Verify()): return True

    def Print(self):
        L = len(self.range_proof.pub_keys) // 4
        
        print("Committed Value = " + hex(CompressPoint(self.total_commitment)))
        print("Possible Range = " + str(self.offset) + " to " + str((4**L-1)*(10**self.pow10)+self.offset))
        print("Possible # of Values = " + str(4**L-1))
        print("Range Proof:")
        self.range_proof.Print()

        
        

class RingCTToken:
    MyPrivateViewKey = 0
    MyPublicViewKey = (FQ(0), FQ(0))
    
    MyPrivateSpendKey = 0
    MyPublicSpendKey = (FQ(0), FQ(0))

    MyPrivateKeys = []
    MyPublicKeys = []

    def GenerateNewStealthAddress(self):
        self.MyPrivateViewKey = getRandom()
        self.MyPrivateSpendKey = getRandom()

        self.MyPublicViewKey = multiply(G1, self.MyPrivateViewKey)
        self.MyPublicSpendKey = multiply(G1, self.MyPrivateSpendKey)

    def GenerateNewAddress(self):
        x = getRandom()
        self.MyPrivateKeys = self.MyPrivateKeys + [x]
        self.MyPublicKeys = self.MyPublicKeys + [multiply(G1, x)]

    def GenerateNewAddresses(self, n):
        for i in range(0, n):
            self.GenerateNewAddress()

    def GenerateCommitment(value, blinding_factor):
        point = multiply(G1, blinding_factor)
        temp = multiply(H, value)
        point = add(point, temp)
            
        return point

    def GenerateRangeProof(value, pow10, offset, bits_override, total_blinding_factor):
        #Figure out how many bits value is in base 4
        import math
        bits = math.floor(math.log(value,4))+1

        if (bits_override > bits):
            bits = bits_override

        c = []
        cp = []
        cpp = []
        cppp = []
        keys = []
        indices = []
        commitments = []
        bfTotal = 0
        for i in range(0, bits):
            v = (value & (3 << (2*i))) >> (2*i)

            if i < (bits-1):
                bf = getRandom()
                bfTotal = bfTotal + bf
            else:
                bf = (total_blinding_factor - bfTotal) % Ncurve

            keys = keys + [bf]
            indices = indices + [v]
                
                
            p1 = RingCTToken.GenerateCommitment(v * (4**i) * (10**pow10), bf)
            p2 = neg(multiply(H, (4**i)*(10**pow10)))
            
            c = c + [p1]            
            p1 = add(p1, p2)
            cp = cp + [p1]
            p1 = add(p1, p2)
            cpp = cpp + [p1]
            p1 = add(p1, p2)
            cppp = cppp + [p1]


        commitments = c + cp + cpp + cppp
        return PCRangeProof(pow10, offset, RingCTToken.GenerateCommitment(value*(10**pow10)+offset, total_blinding_factor), MSAG.Sign(bits, bytes(0), keys, indices, commitments))
            
    def GenerateStealthTx(self, pubViewKey, pubSpendKey, data):
        r = getRandom()
        R = multiply(G1, r)

        ss = hash_of_point(multiply(pubViewKey, r)) % Ncurve
        dest_pub_key = add(multiply(G1, ss), pubSpendKey)

        return StealthTransaction(dest_pub_key, R, data)
    
    def PrintStealthAddress(self):
        print("Public View Key:\t" + print_point(CompressPoint(self.MyPublicViewKey)))
        print("Public Spend Key:\t" + print_point(CompressPoint(self.MyPublicSpendKey)))

    def PrintAddresses(self):
        for i in range(0, len(self.MyPublicKeys)):
            print("Public Key " + str(i) + ":\t\t" + print_point(CompressPoint(self.MyPublicKeys[i])))
    
    def __init__(self):
        self.GenerateNewStealthAddress()

def SumPoints(points):
    s = points[0]
    for i in range(1,len(points)):
        s = add(points[i], s)

    return s

def RangeProofTest():
    value = 48
    pow10 = 18
    offset = 0
    bits = 4
    bf = 100
    
    print("Generating " + str(bits) + "-bit Range Proof for " + str(value) + "x(10**" + str(pow10) + ")+" + str(offset) + " = " + str(value*(10**pow10)+offset))
    print("Blinding factor = " + str(bf))
    rp = RingCTToken.GenerateRangeProof(45, 18, 0, 4, 100)
    rp.Print()

    print("\nVerifing Range proof...", end="")
    if(rp.Verify()):
        print("Success!")
    else:
        print("Failure!")

    return rp

def RingCTTest():
    rct = RingCTToken()
    rct.PrintStealthAddress()
    #rct.GenerateNewAddresses(5)

    rct.PrintAddresses()

    stx = rct.GenerateStealthTx(rct.MyPublicViewKey, rct.MyPublicSpendKey, 0)
    print("Stealth Tx Pub Key:\t" + print_point(CompressPoint(stx.dest_pub_key)))
    print("Stealth Tx DHE Point:\t" + print_point(CompressPoint(stx.dest_dhe_point)))
    return rp

#RingCTTest()
rp = RangeProofTest()
