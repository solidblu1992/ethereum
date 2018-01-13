from ring_signatures import *

class PCRangeProof:
    pow10 = 0
    offset = 0
    range_proof = 0
    
    def __init__(self, pow10, offset, range_proof):
        self.pow10 = pow10
        self.offset = offset
        self.range_proof = range_proof

    def GetTotalCommitment(self):
        return ExpandPoint(bytes_to_int(self.range_proof.msgHash))

    def Commit(value, blinding_factor):
        point = multiply(G1, blinding_factor)
        temp = multiply(H, value)
        point = add(point, temp)
            
        return point

    def Generate(value, pow10, offset, bits_override, total_blinding_factor):
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
                
                
            p1 = PCRangeProof.Commit(v * (4**i) * (10**pow10), bf)
            p2 = neg(multiply(H, (4**i)*(10**pow10)))
            
            c = c + [p1]            
            p1 = add(p1, p2)
            cp = cp + [p1]
            p1 = add(p1, p2)
            cpp = cpp + [p1]
            p1 = add(p1, p2)
            cppp = cppp + [p1]


        commitments = c + cp + cpp + cppp
        total_commitment = PCRangeProof.Commit(value*(10**pow10)+offset, total_blinding_factor)
        return PCRangeProof(pow10, offset, MSAG.Sign_GenRandom(bits, int_to_bytes32(CompressPoint(total_commitment)), keys, indices, commitments))
            

    def Verify(self):
        L = len(self.range_proof.pub_keys)
        if (L % 4 != 0): return False
        L = L // 4
        
        #Check that bitwise commitments add up
        point = multiply(H, self.offset)
        for i in range(0, L):
            point = add(point, self.range_proof.pub_keys[i])

        if (not eq(point, self.GetTotalCommitment())): return False

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
        
        print("Committed Value = " + hex(CompressPoint(self.GetTotalCommitment())))
        print("Possible Range = " + str(self.offset) + " to " + str((4**L-1)*(10**self.pow10)+self.offset))
        print("Possible # of Values = " + str(4**L-1))
        print("Range Proof:")
        self.range_proof.Print()

class PCAESMessage:
    message = b""
    iv = b""

    def __init__(self, message, iv):
        self.message = message
        self.iv = iv
        
    def Encrypt(value, blinding_factor, ss_point):
        from Crypto.Cipher import AES
        from Crypto import Random
        key = int_to_bytes32(hash_of_point(ss_point))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        message = cipher.encrypt(int_to_bytes32(value) + int_to_bytes32(blinding_factor))
        
        return PCAESMessage(message, iv)

    def Decrypt(self, ss_point):
        from Crypto.Cipher import AES
        from Crypto import Random
        key = int_to_bytes32(hash_of_point(ss_point))
        cipher = AES.new(key, AES.MODE_CFB, self.iv)
        msg = cipher.decrypt(self.message)

        value = bytes_to_int(msg[:32])
        bf = bytes_to_int(msg[32:])

        return (value, bf)

    def Print(self):
        print("Encrypted Message: " + hex(bytes_to_int(self.message)))
        print("iv: " + hex(bytes_to_int(self.iv)))

def RangeProofTest():
    value = 48
    pow10 = 18
    offset = 0
    bits = 4
    bf = getRandom()
    
    print("Generating " + str(bits) + "-bit Range Proof for " + str(value) + "x(10**" + str(pow10) + ")+" + str(offset) + " = " + str(value*(10**pow10)+offset))
    print("Blinding factor = " + hex(bf))
    rp = PCRangeProof.Generate(45, 18, 0, 4, 100)
    rp.Print()

    print("\nVerifing Range proof...", end="")
    if(rp.Verify()):
        print("Success!")
    else:
        print("Failure!")

def AESTest():
    value = 48
    pow10 = 18
    offset = 0
    bf = getRandom()

    v = value*(10**pow10)+offset
    print("Hiding " + str(v) + " and blinding factor " + hex(bf))
    ss_point = multiply(G1, getRandom())
    msg = PCAESMessage.Encrypt(v, bf, ss_point)
    msg.Print()

    (v2, bf2) = msg.Decrypt(ss_point)
    print("Recovered " + str(v2) + " and blinding factor " + hex(bf2))

    
    
