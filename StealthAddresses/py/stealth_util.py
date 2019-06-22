from py_ecc.fields import FQ
from py_ecc.secp256k1 import secp256k1 as curve

#Utility Functions
#secp256k1
def CompressPoint(Pin):
    if (type(Pin) != tuple):
        return Pin

    Pout = Pin[0]
    if ( (Pin[1] & 0x1) == 0x1):
        Pout = Pout | (0x3 << 256)
    else:
        Pout = Pout | (0x2 << 256) 

    return Pout.to_bytes(33, "big")

def ExpandPoint(Pin):
    import math

    raw_int = int.from_bytes(Pin, "big")
    sign = (raw_int & (3 << 256)) >> 256
    x = raw_int & (2**256 - 1)
    assert (sign == 2 or sign == 3)
    
    y_squared = (pow(x, 3, curve.P) + (curve.A*x) + (curve.B)) % curve.P
    y = pow(y_squared, (curve.P+1)//4, curve.P)

    assert (y_squared == pow(y, 2, curve.P))

    if (sign == 2):
        if ( (y & 0x1) == 0 ):
            Pout = (x, y)
        else:
            Pout = (x, curve.P-y)
    else:
        if ( (y & 0x1) == 0 ):
            Pout = (x, curve.P-y)
        else:
            Pout = (x, y)

    return Pout

#Stealth Read
def GetAddrFromPubKey(pub_key):
    from sha3 import keccak_256
    
    hasher = keccak_256()
    hasher.update(int.to_bytes(pub_key[0], 32, 'big') + int.to_bytes(pub_key[1], 32, 'big'))
    addr = hasher.digest()[-20:]   
    return addr

def GetStealthAddressFromKeys(scan_pub_key, spend_pub_key):
    scan_pub_bytes = CompressPoint(scan_pub_key)
    spend_pub_bytes = CompressPoint(spend_pub_key)

    sign = 1
    if scan_pub_bytes[0] == 0x3:
        sign += 2

    if spend_pub_bytes[0] == 0x3:
        sign += 4

    stealth_address = bytes([sign]) + scan_pub_bytes[1:] + spend_pub_bytes[1:]
    return stealth_address

def GetKeysFromStealthAddress(stealth_address):
    assert (len(stealth_address) == 65)
    assert (stealth_address[0] & 1 == 1)

    if stealth_address[0] & 2 == 0:
        scan_sign = 2
    else:
        scan_sign = 3

    if stealth_address[0] & 4 == 0:
        spend_sign = 2
    else:
        spend_sign = 3

    scan_comp = bytes([scan_sign]) + stealth_address[1:33]
    spend_comp = bytes([spend_sign]) + stealth_address[33:]
    return ExpandPoint(scan_comp), ExpandPoint(spend_comp)

def GetSharedSecret(R, scan_key):
    from hashlib import sha256

    if type(scan_key) == bytes:
        scan_key = int.from_bytes(scan_key, 'big')
        
    SS = curve.multiply(R, scan_key)

    hasher = sha256()
    hasher.update(int.to_bytes(SS[0], 32, 'big') + int.to_bytes(SS[1], 32, 'big'))
    ss = hasher.digest()

    return ss

def GetAddrFromSharedSecret(ss, pub_spend_key):
    P = curve.multiply(curve.G, int.from_bytes(ss, 'big'))
    P = curve.add(P, pub_spend_key)
    addr = GetAddrFromPubKey(P)
    return addr

def GetPrivKeyFromSharedSecret(ss, priv_spend_key):
    ss = int.from_bytes(ss, 'big')
    priv_spend_key = int.from_bytes(priv_spend_key, 'big')
    return (ss + priv_spend_key) % curve.N

#Stealth Write
def CreateStealthTx(pub_scan_key, pub_spend_key):
    from random import SystemRandom
    rnd = SystemRandom()
    r = rnd.getrandbits(256)
    R = CompressPoint(curve.multiply(curve.G, r))

    ss = GetSharedSecret(pub_scan_key, r)
    addr = GetAddrFromSharedSecret(ss, pub_spend_key)

    R = hex(int.from_bytes(R, 'big'))
    addr = hex(int.from_bytes(addr, 'big'))
    return R, addr
