from bn128_curve import *
import sha3

#alt_bn_128 curve parameters
Ncurve = curve_order
Pcurve = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000

def bytes_to_int(bytes):
    result = 0

    for b in bytes:
        result = result * 256 + int(b)

    return result

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

def print_point(p):
    if (type(p) == tuple):
        p = CompressPoint(p)
    
    s = hex(p)
    if (len(s) != 66):
        y = 66 - len(s)
        y = "0" * y
        s = "0x" + y + s[2:]
            
    print(s)
        

def hash_point(p):
    hasher = sha3.keccak_256()
    hasher.update(int_to_bytes32(p[0].n))
    hasher.update(int_to_bytes32(p[1].n))
    x = bytes_to_int(hasher.digest()) % Pcurve
    
    while(True):
        y_squared = (pow(x, 3, Pcurve) + 3) % Pcurve
        y = pow(y_squared, (Pcurve+1)//4, Pcurve)

        if(pow(y, 2, Pcurve) == y_squared):
            break
        else:
            x = x + 1

    return (FQ(x), FQ(y))

#Utility Functions
def CompressPoint(Pin):
    if (Pin[1].n > (Pcurve // 2)):
        Pout = Pin[0].n | (ECSignMask)
    else:
        Pout = Pin[0].n

    return Pout

def ExpandPoint(Pin):
    import math
    y_squared = (Pin**3 + 3) % Ncurve
    y = pow(y_squared, (Pcurve+1)//4, Pcurve)

    if (y > (Pcurve // 2)):
        if (Pin & ECSignMask == 0):
            y = Pcurve - y
    else:
        if (Pin & ECSignMask != 0):
            y = Pcurve - y

    Pout = (FQ(Pin & (~ECSignMask)), FQ(y))
    return Pout

def keccak256(msg):
    msgHash = 0 #Put keccak256 here
    return msgHash

def getRandom():
    import random
    out = (random.getrandbits(254) % Ncurve)
    return out

def point_to_hex(p):
    s = '0x4' + hex(p[0].n) + hex(p[1].n)
    return s

H = hash_point(G1)

class RingCTToken:
    MyPrivateViewKey = 0
    MyPublicViewKey = (FQ(0), FQ(0))
    
    MyPrivateSpendKey = 0
    MyPublicSpendKey = (FQ(0), FQ(0))

    def GenerateNewStealthAddress(self):
        self.MyPrivateViewKey = getRandom()
        self.MyPrivateSpendKey = getRandom()

        self.MyPublicViewKey = multiply(G1, self.MyPrivateViewKey)
        self.MyPublicSpendKey = multiply(G1, self.MyPrivateSpendKey)

    def PrintStealthAddress(self):
        print(hex(CompressPoint(self.MyPublicViewKey)))
        print(hex(CompressPoint(self.MyPublicSpendKey)))
    
    def __init__(self):
        self.GenerateNewStealthAddress()
        

#Stealth Address Functions


#Transaction Functions
