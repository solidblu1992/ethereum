from random import SystemRandom
from py_ecc import optimized_bn128 as bn128
from sha3 import keccak_256

def norm_to_pt(P_norm):
    return (P_norm[0], P_norm[1], bn128.FQ.one())

class Schnorr:
    def Sign(x, msg, P=None, T=None):
        if P == None:
            P = bn128.multiply(bn128.G1, x)

        #Pick R, add adaptor
        r = SystemRandom().getrandbits(256)
        R = bn128.multiply(bn128.G1, r)
        if T != None:
            R = bn128.add(R, T)
        R = bn128.normalize(R)

        #Get challenge
        hasher = keccak_256(R[0].n.to_bytes(32, 'big'))
        hasher.update(R[1].n.to_bytes(32, 'big'))
        hasher.update(P[0].n.to_bytes(32, 'big'))
        hasher.update(P[1].n.to_bytes(32, 'big'))
        hasher.update(msg)
        e = int.from_bytes(hasher.digest(), 'big')

        #Create signature
        s = (r + e*x) % bn128.curve_order

        if T != None:
            sig_tuple = (R, P, s, T)
        else:
            sig_tuple = (R, P, s)

        return sig_tuple

    def Verify(msg, sig_tuple):
        #Only verify non-adapter signatures
        assert(len(sig_tuple) == 3)

        R, P, s = sig_tuple
        R = norm_to_pt(R)
        P = norm_to_pt(P)
        
        #Get challenge
        hasher = keccak_256(R[0].n.to_bytes(32, 'big'))
        hasher.update(R[1].n.to_bytes(32, 'big'))
        hasher.update(P[0].n.to_bytes(32, 'big'))
        hasher.update(P[1].n.to_bytes(32, 'big'))
        hasher.update(msg)
        e = int.from_bytes(hasher.digest(), 'big')

        #Check challenge
        #R = sG - eP
        S = bn128.multiply(bn128.G1, s)
        eP = bn128.multiply(P, e)
        R_check = bn128.add(S, bn128.neg(eP))

        return bn128.eq(R, R_check)

    def ConvAdaptor(sig_tuple, t):
        #Only convert adatpor signatures
        assert(len(sig_tuple) == 4)
        
        R, P, s, T = sig_tuple

        #Check for right adaptor
        assert(bn128.eq(T, bn128.multiply(bn128.G1, t)))

        #Convert
        s = (s + t) % bn128.curve_order

        sig_tuple = (R, P, s)
        return sig_tuple

    def Recover_t(asig_tuple, sig_tuple):
        _, _, s0, _ = asig_tuple
        _, _, s1 = sig_tuple

        t = (s1-s0) % bn128.curve_order
        return t
    
class Actor:
    def __init__(self):
        self.x = SystemRandom().getrandbits(256)
        self.P = norm_to_pt(bn128.normalize(bn128.multiply(bn128.G1, self.x)))
        self.r = []

    def Random(self):
        r = SystemRandom().getrandbits(256) % bn128.curve_order
        self.r += [r]
        return bn128.multiply(bn128.G1, r)

    def Sign(self, msg, T=None):
        return Schnorr.Sign(self.x, msg, P=self.P, T=T)

def schnorr_test():
    #Try regular schnorr
    msg = b'hello'
    A = Actor()
    sig = A.Sign(msg)
    print(Schnorr.Verify(msg, sig))

    #Try adaptor
    t = SystemRandom().getrandbits(256)
    T = bn128.multiply(bn128.G1, t)

    sig = A.Sign(msg, T)
    sig = Schnorr.ConvAdaptor(sig, t)
    print(Schnorr.Verify(msg, sig))

def lightning_test():
    #Lightning Tx Test
    #A --> B --> C --> D --> E --> F
    A = Actor()
    B = Actor()
    C = Actor()
    D = Actor()
    E = Actor()
    F = Actor()

    #Get adaptor from each actor
    T = F.Random()
    U = E.Random()
    V = D.Random()
    W = C.Random()
    X = B.Random()

    #A builds adaptors and sends them to each actor
    #Send T to E
    #Send TU to D
    #Send TUV to C
    #Send TUVW to B
    #Keep TUVWX for self (A)
    TU = bn128.add(T, U)
    TUV = bn128.add(TU, V)
    TUVW = bn128.add(TUV, W)
    TUVWX = bn128.add(TUVW, X)

    #Each actor creates an adaptor signature
    msg_AB = b'SendTokensFromAToB'
    asig_AB = A.Sign(msg_AB, TUVWX)

    msg_BC = b'SendTokensFromBToC'
    asig_BC = B.Sign(msg_BC, TUVW)

    msg_CD = b'SendTokensFromCToD'
    asig_CD = C.Sign(msg_CD, TUV)

    msg_DE = b'SendTokensFromDToE'
    asig_DE = C.Sign(msg_DE, TU)

    msg_EF = b'SendTokensFromEToF'
    asig_EF = C.Sign(msg_EF, T)

    #F spends first, revealing t
    sig_EF = Schnorr.ConvAdaptor(asig_EF, F.r[0])
    print(Schnorr.Verify(msg_EF, sig_EF))

    #With t revealed, E spends knowing u
    t = Schnorr.Recover_t(asig_EF, sig_EF)
    sig_DE = Schnorr.ConvAdaptor(asig_DE, (t + E.r[0]) % bn128.curve_order)
    print(Schnorr.Verify(msg_DE, sig_DE))

    #With t+u revealed, D spendsknowing v
    tu = Schnorr.Recover_t(asig_DE, sig_DE)
    sig_CD = Schnorr.ConvAdaptor(asig_CD, (tu + D.r[0]) % bn128.curve_order)
    print(Schnorr.Verify(msg_CD, sig_CD))

    #With t+u+v revealed, C spends knowing w
    tuv = Schnorr.Recover_t(asig_CD, sig_CD)
    sig_BC = Schnorr.ConvAdaptor(asig_BC, (tuv + C.r[0]) % bn128.curve_order)
    print(Schnorr.Verify(msg_BC, sig_BC))

    #With t+u+v+w revealed, B spends knowing x
    tuvw = Schnorr.Recover_t(asig_BC, sig_BC)
    sig_AB = Schnorr.ConvAdaptor(asig_AB, (tuvw + B.r[0]) % bn128.curve_order)
    print(Schnorr.Verify(msg_AB, sig_AB))
