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

def hash_point(p):
    hasher = sha3.keccak_256()
    hasher.update(bytes(p[0].n))
    hasher.update(bytes(p[1].n))
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
    if (len(Pin) != 2):
        return 0

    if (Pin[1] > (Pcurve // 2)):
        Pout = Pin[0] | (ECSignMask)
    else:
        Pout = Pin[0]

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

    Pout = [Pin & (~ECSignMask), y]
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

MyPrivateViewKey = getRandom()
MyPublicViewKey = multiply(G1, MyPrivateViewKey)

MyPrivateSpendKey = getRandom()
MyPublicSpendKey = multiply(G1, MyPrivateSpendKey)

#Stealth Address Functions
def GenerateMyStealthAddress():
    MyPrivateViewKey = getRandom()
    MyPrivateSpendKey = getRandom()

    MyPublicViewKey = ecMul(G1, MyPrivateViewKey)
    MyPublicSpendKey = ecMul(G1, MyPublicSpendKey)
    (MyStealthAddress[0], MyStealthAddress[1]) = ecMul(G1, MyPrivateViewKey)

#Transaction Functions
