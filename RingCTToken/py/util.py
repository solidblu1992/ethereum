#from bn128_curve import *
from optimized_curve import *
import sha3

#alt_bn_128 curve parameters
Ncurve = curve_order
Pcurve = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000
NullPoint = (FQ(0), FQ(0), FQ(0))

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

def int_to_bytes64(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))

    if (len(x) < 64):
        y = bytes(64 - len(x))
        x = y+x

    return x

def int_to_bytes32(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))

    if (len(x) < 32):
        y = bytes(32 - len(x))
        x = y+x

    return x

def int_to_bytes20(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffffffffffff))

    if (len(x) < 20):
        y = bytes(20 - len(x))
        x = y+x

    return x

def int_to_bytes16(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffff))

    if (len(x) < 16):
        y = bytes(16 - len(x))
        x = y+x

    return x

def to_point(x, y):
    return (FQ(x), FQ(y), FQ(1))

def bytes32_to_str(b):
    s = hex(b)

    if (len(s) < 66):
        y = 66 - len(s)
        y = "0" * y
        s = "0x" + y + s[2:]

    return s

def bytes20_to_str(b):
    s = hex(b)

    if (len(s) < 42):
        y = 42 - len(s)
        y = "0" * y
        s = "0x" + y + s[2:]

    return s

def bytes16_to_str(b):
    s = hex(b)

    if (len(s) < 34):
        y = 34 - len(s)
        y = "0" * y
        s = "0x" + y + s[2:]

    return s

def point_to_str(p):
    if (type(p) != tuple):
        p = ExpandPoint(p)

    p = normalize(p)
    
    s = (bytes32_to_str(p[0].n) + ",\n" + bytes32_to_str(p[1].n))
    return s

def hash_of_int(i):
    hasher = sha3.keccak_256(int_to_bytes32(i))
    x = bytes_to_int(hasher.digest())
    return x

def hash_of_point(p):
    p = normalize(p)
    hasher = sha3.keccak_256()
    hasher.update(int_to_bytes32(p[0].n))
    hasher.update(int_to_bytes32(p[1].n))
    x = bytes_to_int(hasher.digest())
    return x

def hash_to_point(p):
    p = normalize(p)
    hasher = sha3.keccak_256()
    hasher.update(int_to_bytes32(p[0].n))
    hasher.update(int_to_bytes32(p[1].n))
    x = bytes_to_int(hasher.digest()) % Pcurve

    onCurve = False
    while(not onCurve):
        y_squared = (pow(x, 3, Pcurve) + 3) % Pcurve
        y = pow(y_squared, (Pcurve+1)//4, Pcurve)

        onCurve = (pow(y,2,Pcurve) == y_squared)

        if(not(onCurve)):
            x = x + 1

    return (FQ(x), FQ(y), FQ(1))

def add_point_to_hasher(hasher, point):
    point = normalize(point)
    hasher.update(int_to_bytes32(point[0].n))
    hasher.update(int_to_bytes32(point[1].n))
    return hasher

#Definition of H = hash_to_point(G1)
H = hash_to_point(G1)

def KeyImage(xk):
    return multiply(hash_to_point(multiply(G1,xk)), xk)

#Utility Functions
def CompressPoint(Pin):
    Pin = normalize(Pin)
    Pout = Pin[0].n
    if ( (Pin[1].n & 0x1) == 0x1):
        Pout = Pout | ECSignMask

    return Pout

def ExpandPoint(Pin):
    import math
    
    x = Pin & (~ECSignMask)
    y_squared = (pow(x,3,Pcurve) + 3) % Pcurve
    y = pow(y_squared, (Pcurve+1)//4, Pcurve)

    if ((Pin & ECSignMask) == 0):
        if ( (y & 0x1) == 0 ):
            Pout = (FQ(x), FQ(y), FQ(1))
        else:
            Pout = (FQ(x), FQ(Pcurve-y), FQ(1))
    else:
        if ( (y & 0x1) == 0 ):
            Pout = (FQ(x), FQ(Pcurve-y), FQ(1))
        else:
            Pout = (FQ(x), FQ(y), FQ(1))

    return Pout

def getRandom(count=1):
    import random

    if (count == 1):
        out = (random.SystemRandom().getrandbits(254) % Ncurve)
    else:
        out = []
        for i in range(0, count):
            out = out + [random.SystemRandom().getrandbits(254) % Ncurve]

    return out


def getRandomUnsafe(seed=None):
    import random
    if (seed != None):
        random.seed(seed)
        
    out = (random.getrandbits(254) % Ncurve)

    return out

def ExpandCompressTest():
    for i in range(0, 20):
        x = getRandom()
        point = multiply(G1, x)
        cpoint = CompressPoint(point)
        point2 = ExpandPoint(CompressPoint(point))
    
        print("Test[" + str(i) + "]...", end="")
        if (not eq(point, point2)):
            print("Failure! ", end="")

            if ((point[1].n & 0x1) == 0x1):
                print("point is odd")
            
            #print("point = " + hex(point[0].n))
            #print("cpoint = " + hex(cpoint))
        else:
            print("Success!")

        
        
        
