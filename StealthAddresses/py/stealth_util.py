from eth_keyfile import decode_keyfile_json
import json
from getpass import getpass

use_secp256k1 = False
use_altbn128 = True
if use_secp256k1:
    from py_ecc.secp256k1 import P, N, G, privtopub
    from py_ecc.secp256k1.secp256k1 import A, B, add as curve_add, multiply as curve_multiply, from_jacobian as curve_normalize

if use_altbn128:
    from py_ecc.optimized_bn128 import field_modulus as P, curve_order as N, G1 as G, b, add as curve_add, multiply as curve_multiply, normalize as curve_normalize, FQ
    A = 0
    B = b.n


#Utility Functions
#general
def add(P1, P2):
    if use_altbn128:
        if len(P1) == 3:
            P1 = (FQ(P1[0]), FQ(P1[1]), FQ(P1[2]))
        else:
            P1 = (FQ(P1[0]), FQ(P1[1]))

        if len(P2) == 3:
            P2 = (FQ(P2[0]), FQ(P2[1]), FQ(P2[2]))
        else:
            P2 = (FQ(P2[0]), FQ(P2[1]))
            
    return curve_add(P1, P2)

def multiply(P, k):
    if use_altbn128:
        if len(P) == 3:
            P = (FQ(P[0]), FQ(P[1]), FQ(P[2]))
        else:
            P = (FQ(P[0]), FQ(P[1]))
            
    if type(k) == bytes:
        k = int.from_bytes(k)
        
    return curve_multiply(P, k)

def normalize(P, ret_as_FQ=True):
    if len(P) == 3:
        if use_altbn128:
            P = (FQ(P[0]), FQ(P[1]), FQ(P[2]))
        
        P = curve_normalize(P)

    if use_altbn128:
        if ret_as_FQ:
            P = (FQ(P[0]), FQ(P[1]), FQ.one())
        else:
            P = (int(P[0]), int(P[1]), 1)
        
    return P

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

    Pin = normalize(Pin)

    if type(Pin[0]) != int:
        Pin = (Pin[0].n, Pin[1].n)

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
    
    y_squared = (pow(x, 3, P) + (A*x) + (B)) % P
    y = pow(y_squared, (P+1)//4, P)

    assert (y_squared == pow(y, 2, P))

    if (sign == 2):
        if ( (y & 0x1) == 0 ):
            Pout = (x, y)
        else:
            Pout = (x, P-y)
    else:
        if ( (y & 0x1) == 0 ):
            Pout = (x, P-y)
        else:
            Pout = (x, y)

    return Pout

def GetPubKeyFromPrivKey(priv_key):
    return normalize(multiply(G, priv_key))

#Stealth Read
def GetAddrFromPubKey(pub_key):
    from eth_hash.auto import keccak
    pub_key = normalize(pub_key, False)        
    digest = keccak(int.to_bytes(pub_key[0], 32, 'big') + int.to_bytes(pub_key[1], 32, 'big'))
    addr = digest[-20:]   
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

    if not use_secp256k1 and type(R[0]) == int:
        R = (FQ(R[0]), FQ(R[1]), FQ.one())

    hasher = sha256()

    #XETH has certain oddities to how it calculates the shared secret
    using_XETH = True
    if using_XETH:
        #ss = sha256(compress(scan_key*G + R))
        SS = CompressPoint(add(R, multiply(G, scan_key)))
        hasher.update(SS)
        
    else:
        #ss = sha256(expand(scan_key*R))
        SS = multiply(R, scan_key)
        hasher.update(int.to_bytes(SS[0], 32, 'big') + int.to_bytes(SS[1], 32, 'big'))

    ss = hasher.digest()

    return ss

def GetAddrFromSharedSecret(ss, pub_spend_key):
    #print(f"GetAddrFromSharedSecret: ss={ss.hex()}, pub_spend_key={pub_spend_key}")
    if not use_secp256k1 and type(pub_spend_key[0]) == int:
        pub_spend_key = (FQ(pub_spend_key[0]), FQ(pub_spend_key[1]), FQ.one())
        
    P = multiply(G, int.from_bytes(ss, 'big'))
    P = add(P, pub_spend_key)
    addr = GetAddrFromPubKey(P)
    return addr

def GetPrivKeyFromSharedSecret(ss, priv_spend_key):
    ss = int.from_bytes(ss, 'big')

    if type(priv_spend_key) == bytes:
        priv_spend_key = int.from_bytes(priv_spend_key, 'big')
        
    return (ss + priv_spend_key) % N

#Stealth Write
def CreateStealthTx(pub_scan_key, pub_spend_key):
    from random import SystemRandom
    rnd = SystemRandom()
    r = rnd.getrandbits(256)
    R = CompressPoint(multiply(G, r))

    ss = GetSharedSecret(pub_scan_key, r)
    addr = GetAddrFromSharedSecret(ss, pub_spend_key)

    R = hex(int.from_bytes(R, 'big'))
    addr = hex(int.from_bytes(addr, 'big'))
    return R, addr

#File Functions
def ReadStealthAddressFromFile(filename):
    out = dict()
    with open(filename) as f:
        #Read File
        file_json = json.load(f)

        #Extract Address
        addr = bytes_from_hex_string(file_json['stealth_address'], 65)
        out['stealth_address'] = addr
        out['pub_scan_key'], out['pub_spend_key'] = GetKeysFromStealthAddress(addr)

    return out

def ReadStealthKeysFromFile(filename, password=None):
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
        out['spend_key'] = decode_keyfile_json(file_json['spend_key'], bytes(password, 'utf'))
        del password

    return out

def ReadKeysFromFiles(filenames, password=None):
    out = dict()

    #Read Password
    if password==None:
        password = getpass()

    out['address'] = []
    out['priv_key'] = []
    
    for filename in filenames:
        with open(filename) as f:
            #Read File
            file_json = json.load(f)

            #Extract Address
            addr = bytes_from_hex_string(file_json['address'], 40)
            out['address'].append(addr)
            out['priv_key'].append(decode_keyfile_json(file_json, bytes(password, 'utf')))

    del password
    return out

#Schnorr Utilities
def SchnorrMultiSign(message, priv_keys):
    from os import urandom
    from hashlib import sha256

    if type(message) == str:
        message = bytes(message, 'utf')
    
    r = int.from_bytes(urandom(32)) % N
    R = normalize(multiply(G, r), False)
    x_sum = 0
    Y = []
    e = sha256(int.to_bytes(R[0], 32, 'big') + int.to_bytes(R[1], 32, 'big'))
    message_hash = sha256(message).digest()
    e.update(message_hash)
    for x in priv_keys:
        x_sum = x_sum + int.from_bytes(x)
        Y_x = normalize(multiply(G, x), False)
            
        Y.append(Y_x)
        e.update(int.to_bytes(Y_x[0], 32, 'big') + int.to_bytes(Y_x[1], 32, 'big'))
    e = int.from_bytes(e.digest()) % N
    
    s = (r - e*x_sum) % N
    sig = {
        "message": message,
        "message_hash": message_hash,
        "Y": Y,
        "e": e,
        "s": s
    }
    return sig

def SchnorrMultiVerify(sig: dict()):
    from hashlib import sha256
    S = multiply(G, sig["s"])

    Y = []
    Y_sum = None
    for Y_x in sig["Y"]:
        Y.append(normalize(Y_x, False))

        if Y_sum == None:
            Y_sum = Y_x
        else:
            Y_sum = add(Y_sum, Y_x)

    Rv = normalize(add(S, multiply(Y_sum, sig["e"])), False)
    
    e = sha256(int.to_bytes(Rv[0], 32, 'big') + int.to_bytes(Rv[1], 32, 'big'))
    message_hash = sha256(sig["message"]).digest()
    e.update(message_hash)
    for Y_x in Y:
        e.update(int.to_bytes(Y_x[0], 32, 'big') + int.to_bytes(Y_x[1], 32, 'big'))
    e = int.from_bytes(e.digest()) % N

    if sig["e"] == e:
        print("SIGNATURE VALID")
        return True
    else:
        print("SIGNATURE INVALID")
        return False
