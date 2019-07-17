from sha3 import keccak_256

def getRandom(count=1):
    from random import SystemRandom
    sr = SystemRandom()

    if (count == 1):
        out = sr.getrandbits(256)
    else:
        out = []
        for i in range(0, count):
            out = out + [sr.getrandbits(256)]

    return out

class Lamport:
    PrivateKey = 0
    PublicKey = 0
    
    def __init__(self):
        from sha3 import keccak_256
        self.PrivateKey = [getRandom(512)]
        self.PublicKey = [keccak_256(int.to_bytes(self.PrivateKey[i], 256, 'big')).digest() for i in range(0, 512)]

    def Sign(self, msg_string):
        msg_hash = keccak_256(bytes(msg_string, 'utf')).digest()
        sig = bytes()
        for i in range(0, 32):
            test_bit = 0x80
            
            for j in range(0, 8):
                if byte & test_bit == 0:
                    sig += self.PublicKey[8*i + j]
