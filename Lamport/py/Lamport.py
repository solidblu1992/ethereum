def getRandom(count=1):
    import random

    if (count == 1):
        out = random.SystemRandom().getrandbits(255)
    else:
        out = []
        for i in range(0, count):
            out = out + [random.SystemRandom().getrandbits(255)]

    return out

def int_to_iterable(i):
    x = []
    bits = 0
    while i > 0:
        y = i & (0xFF << bits)
        x = [(y >> bits)] + x
        i = i - y
        bits = bits + 8

    return x

def int_to_bytes32(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))

    if (len(x) < 32):
        y = bytes(32 - len(x))
        x = y+x

    return x

def bytes_to_int(bytes):
    result = 0

    for b in bytes:
        result = result * 256 + int(b)

    return result

class Lamport:
    PrivateKey = 0
    PublicKey = 0
    
    def __init__(self):
        import sha3
        self.PrivateKey = getRandom(512)
        self.PublicKey = [0]*512

        for i in range(0, 512):
            self.PublicKey[i] = bytes_to_int(sha3.keccak_256(int_to_bytes32(self.PrivateKey[i])).digest())

    def Sign(self):
        print()


            
