from py_ecc.fields import FQ
from py_ecc.secp256k1 import secp256k1 as curve
from eth_keyfile import decode_keyfile_json
import json
from getpass import getpass

#Utility Functions
#general
def bytes_from_hex_string(s, desired_byte_length=0):
    #Extract Address
    b = s[2:]
    while len(b) < (desired_byte_length*2):
        b = "0" + b      
    b = bytes.fromhex(b)
    return b

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

    hasher = sha256()

    #XETH has certain oddities to how it calculates the shared secret
    using_XETH = True
    if using_XETH:
        #ss = sha256(compress(scan_key*G + R))
        SS = CompressPoint(curve.add(R, curve.multiply(curve.G, scan_key)))
        hasher.update(SS)
        
    else:
        #ss = sha256(expand(scan_key*R))
        SS = curve.multiply(R, scan_key)
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

    if type(priv_spend_key) == bytes:
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

#File Functions
def ReadAddressFromFile(filename):
    out = dict()
    with open(filename) as f:
        #Read File
        file_json = json.load(f)

        #Extract Address
        addr = bytes_from_hex_string(file_json['stealth_address'], 65)
        out['stealth_address'] = addr
        out['pub_scan_key'], out['pub_spend_key'] = GetKeysFromStealthAddress(addr)

    return out

def ReadKeysFromFile(filename, password=None):
    out = dict()
    with open(filename) as f:
        #Read File
        file_json = json.load(f)

        #Extract Address
        addr = bytes_from_hex_string(file_json['stealth_address'], 65)
        out['stealth_address'] = addr
        out['pub_scan_key'], out['pub_spend_key'] = GetKeysFromStealthAddress(addr)

        #Extract Scan Key
        if password==None:
            password = getpass()
            
        out['scan_key'] = decode_keyfile_json(file_json['scan_key'], bytes(password, 'utf'))
        out['spend_key'] = decode_keyfile_json(file_json['scan_key'], bytes(password, 'utf'))
        del password

    return out
