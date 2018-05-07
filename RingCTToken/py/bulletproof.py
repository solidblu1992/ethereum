from util import *
from ring_signatures import *

Gi = []
Hi = []
def GenBasePoints(N):
    #Get curve Generator Points
    Gi = [None]*N
    Hi = [None]*N

    point = H
    for i in range(0, N):
        point = hash_to_point(point)
        Gi[i] = point
        point = hash_to_point(point)
        Hi[i] = point

    return (Gi, Hi)

print("Calculating Gi and Hi base points...", end="")
(Gi, Hi) = GenBasePoints(64)
print("Done!")

def sNeg(a):
    return (Ncurve - (a % Ncurve)) % Ncurve

def sAdd(a, b):
    return (a + b) % Ncurve

def sSub(a, b):
    return sAdd(a, sNeg(b))

def sMul(a, b):
    return (a * b) % Ncurve

def sSq(a):
    return sMul(a, a)

def sPow(a, p):
    out = a
    for i in range(1, p):
         out = sMul(out, a)
         
    return out

def sInv(a):
    a = a % Ncurve
    assert(a > 0)

    t1 = 0
    t2 = 1
    r1 = Ncurve
    r2 = a
    q = 0
    while (r2 != 0):
        q = r1 // r2
        (t1, t2, r1, r2) = (t2, t1 - q*t2, r2, r1 - q*r2)

    if (t1 < 0):
        t1 = t1 % Ncurve

    assert(sMul(a, t1) == 1)
    return t1

def vPowers(x, N):
    if (x == 0):
        return [0]*N
    elif (x == 1):
        return [1]*N

    out = [0]*N
    out[0] = 1
    for i in range(1, N):
        out[i] = sMul(out[i-1], x)

    return out

def vSum(x):
    out = x[0]
    for i in range(1, len(x)):
        out = sAdd(out, x[i])

    return out

def vAdd(a, b):
    assert(len(a) == len(b))

    out = [0]*len(a)
    for i in range(0, len(a)):
        out[i] = sAdd(a[i], b[i])

    return out

def vSub(a, b):
    assert(len(a) == len(b))

    out = [0]*len(a)
    for i in range(0, len(a)):
        out[i] = sSub(a[i], b[i])

    return out

def vMul(a, b):
    assert(len(a) == len(b))

    out = [0]*len(a)
    for i in range(0, len(a)):
        out[i] = sMul(a[i], b[i])

    return out

def vScale(a, s):
    out = [0]*len(a)
    for i in range(0, len(a)):
        out[i] = sMul(a[i], s)

    return out
    
def vDot(a, b):
    assert(len(a) == len(b))

    out = 0
    for i in range(0, len(a)):
        out = sAdd(out, sMul(a[i], b[i]))

    return out

def vSlice(a, start, stop):
    out = [0]*(stop-start)

    for i in range(start, stop):
        out[i-start] = a[i]

    return out

def pvExp(a, b):
    assert(len(a) == len(b))
    assert(len(Gi) >= len(a))
    assert(len(Hi) >= len(a))

    out = None
    for i in range(0, len(a)):
        out = add(out, multiply(Gi[i], a[i]))
        out = add(out, multiply(Hi[i], b[i]))

    return out

def pvExpCustom(A, B, a, b):
    assert(len(A) == len(B))
    assert(len(A) == len(a))
    assert(len(A) == len(b))

    out = None
    for i in range(0, len(a)):
        out = add(out, multiply(A[i], a[i]))
        out = add(out, multiply(B[i], b[i]))

    return out

def pvAdd(A, B):
    assert(len(A) == len(B))

    out = [None]*len(A)
    for i in range(0, len(A)):
        out[i] = add(A[i], B[i])

    return out

def pvScale(A, s):
    out = [None]*len(A)
    for i in range(0, len(A)):
        out[i] = multiply(A[i], s)

    return out

class BulletProof:
    V = []
    A = []
    S = []
    T1 = []
    T2 = []
    taux = 0
    mu = 0
    L = []
    R = []
    a = 0
    b = 0
    t = 0
    
    def __init__(self, V, A, S, T1, T2, taux, mu, L, R, a, b, t):
            self.V = V
            self.A = A
            self.S = S
            self.T1 = T1
            self.T2 = T2
            self.taux = taux
            self.mu = mu
            self.L = L
            self.R = R
            self.a = a
            self.b = b
            self.t = t
    
    def Prove(v, gamma, N=32):
        #Make sure N is a power of 2
        import math
        logN = math.floor(math.log(N, 2))
        N = 2**logN
        
        #Create commitment
        V = add(multiply(H, v), multiply(G1, gamma))

        #Create array of bits from v
        aL = [0]*N
        aR = [0]*N
        for i in range(0, N):
            if (v & (1 << i) != 0):
                aL[i] = 1
                
            aR[i] = sSub(aL[i], 1)

        #Create A
        alpha = getRandom()
        A = add(pvExp(aL, aR), multiply(G1, alpha))

        #Create S
        sL = getRandom(N)
        sR = getRandom(N)
        rho = getRandom()
        S = add(pvExp(sL, sR), multiply(G1, rho))

        #Start hasher for Fiat-Shamir
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(V[0].n))
        hasher.update(int_to_bytes32(V[1].n))
        hasher.update(int_to_bytes32(A[0].n))
        hasher.update(int_to_bytes32(A[1].n))
        hasher.update(int_to_bytes32(S[0].n))
        hasher.update(int_to_bytes32(S[1].n))
        y = bytes_to_int(hasher.digest()) % Ncurve
        hasher.update(int_to_bytes32(y))
        z = bytes_to_int(hasher.digest()) % Ncurve
        hasher.update(int_to_bytes32(z))

        #Calculate k
        vec_pow_2 = vPowers(2, N)
        vec_pow_y = vPowers(y, N)
        k = sAdd(sMul(sSq(z), vSum(vec_pow_y)), sMul(sPow(z,3), vSum(vec_pow_2)))
        k = sNeg(k)
        
        #Calculate t0, not used
        #t0 = sMul(z, vSum(vec_pow_y))
        #t0 = sAdd(t0, sMul(sSq(z), v))
        #t0 = sAdd(t0, k)

        #Calculate T1 and T2
        t1 = vDot(vSub(aL, [z]*N), vMul(vec_pow_y, sR))
        t1 = sAdd(t1, vDot(sL, vAdd(vMul(vec_pow_y, vAdd(aR, [z]*N)), vScale(vec_pow_2, sSq(z)))))
        t2 = vDot(sL, vMul(vec_pow_y, sR))

        tau1 = getRandom()
        tau2 = getRandom()
        T1 = add(multiply(H, t1), multiply(G1, tau1))
        T2 = add(multiply(H, t2), multiply(G1, tau2))

        #Continue hasher for Fiat-Shamir
        hasher.update(int_to_bytes32(T1[0].n))
        hasher.update(int_to_bytes32(T1[1].n))
        hasher.update(int_to_bytes32(T2[0].n))
        hasher.update(int_to_bytes32(T2[1].n))
        x = bytes_to_int(hasher.digest()) % Ncurve
        hasher.update(int_to_bytes32(x))

        #Calculate taux and mu
        taux = sMul(tau1, x)
        taux = sAdd(taux, sMul(tau2, sSq(x)))
        taux = sAdd(taux, sMul(gamma, sSq(z)))
        mu = sAdd(sMul(x, rho), alpha)

        #Calculate l, r, and t
        l = [0]*N
        r = [0]*N
        l = vAdd(vSub(aL, [z]*N), vScale(sL, x))
        r = vAdd(vMul(vec_pow_y, vAdd(aR, vAdd([z]*N, vScale(sR, x)))),
                       vScale(vec_pow_2, sSq(z)))
        t = vDot(l, r)

        #Continue hasher for Fiat-Shamir
        hasher.update(int_to_bytes32(taux))
        hasher.update(int_to_bytes32(mu))
        hasher.update(int_to_bytes32(t))
        x_ip = bytes_to_int(hasher.digest()) % Ncurve
        #hasher.update(int_to_bytes32(x_ip))

        #Intialize arrays
        Gprime = [None]*N
        Hprime = [None]*N
        aprime = [0]*N
        bprime = [0]*N
        for i in range(0, N):
            Gprime[i] = Gi[i]
            Hprime[i] = multiply(Hi[i], sPow(sInv(y), i))
            aprime[i] = l[i]
            bprime[i] = r[i]

        L = [None]*logN
        R = [None]*logN
        w = [0]*logN
        
        nprime = N
        rounds = 0
        while (nprime > 1):
            #Halve the vector sizes
            nprime = nprime // 2
            
            #Calculate L and R
            cL = vDot(vSlice(aprime, 0, nprime), vSlice(bprime, nprime, len(bprime)))
            cR = vDot(vSlice(bprime, 0, nprime), vSlice(aprime, nprime, len(aprime)))

            L[rounds] = pvExpCustom(vSlice(Gprime, nprime, len(Gprime)), vSlice(Hprime, 0, nprime),
                                    vSlice(aprime, 0, nprime),           vSlice(bprime, nprime, len(bprime)))
            
            R[rounds] = pvExpCustom(vSlice(Gprime, 0, nprime),           vSlice(Hprime, nprime, len(Hprime)),
                                    vSlice(aprime, nprime, len(aprime)), vSlice(bprime, 0, nprime))
									  
            L[rounds] = add(L[rounds], multiply(H, sMul(cL, x_ip)))
            R[rounds] = add(R[rounds], multiply(H, sMul(cR, x_ip)))

            #Update hasher for Fiat-Shamir
            hasher.update(int_to_bytes32(L[rounds][0].n))
            hasher.update(int_to_bytes32(L[rounds][1].n))
            hasher.update(int_to_bytes32(R[rounds][0].n))
            hasher.update(int_to_bytes32(R[rounds][1].n))
            w[rounds] = bytes_to_int(hasher.digest()) % Ncurve

            #Update Gprime, Hprime, aprime, and bprime
            Gprime = pvAdd(pvScale(vSlice(Gprime, 0, nprime), sInv(w[rounds])),   pvScale(vSlice(Gprime, nprime, len(Gprime)), w[rounds]))
            Hprime = pvAdd(pvScale(vSlice(Hprime, 0, nprime), w[rounds]),         pvScale(vSlice(Hprime, nprime, len(Hprime)), sInv(w[rounds])))

            aprime = vAdd(vScale(vSlice(aprime, 0, nprime), w[rounds]),         vScale(vSlice(aprime, nprime, len(aprime)), sInv(w[rounds])))
            bprime = vAdd(vScale(vSlice(bprime, 0, nprime), sInv(w[rounds])),   vScale(vSlice(bprime, nprime, len(bprime)), w[rounds]))

            rounds = rounds + 1

        #Debug Printing
        #print()
        #print("Bullet Proof Fiat-Shamir Challenges:")
        #print("y:    " + hex(y))
        #print("z:    " + hex(z))
        #print("k:    " + hex(k))
        #print("x:    " + hex(x))
        #print("x_ip: " + hex(x_ip))

        #for i in range(0, len(w)):
        #    print("w[" + str(i) + "]: " + hex(w[i]))
        
        return BulletProof(V, A, S, T1, T2, taux, mu, L, R, aprime[0], bprime[0], t)

    def Verify(self):
        #Get N and logN
        logN = len(self.L)
        N = 2**logN
        if(len(self.L) != logN): return False
        if(len(self.L) != len(self.R)): return False
        
        #Start hasher for Fiat-Shamir
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(self.V[0].n))
        hasher.update(int_to_bytes32(self.V[1].n))
        hasher.update(int_to_bytes32(self.A[0].n))
        hasher.update(int_to_bytes32(self.A[1].n))
        hasher.update(int_to_bytes32(self.S[0].n))
        hasher.update(int_to_bytes32(self.S[1].n))
        y = bytes_to_int(hasher.digest()) % Ncurve
        hasher.update(int_to_bytes32(y))
        z = bytes_to_int(hasher.digest()) % Ncurve
        hasher.update(int_to_bytes32(z))
        hasher.update(int_to_bytes32(self.T1[0].n))
        hasher.update(int_to_bytes32(self.T1[1].n))
        hasher.update(int_to_bytes32(self.T2[0].n))
        hasher.update(int_to_bytes32(self.T2[1].n))
        x = bytes_to_int(hasher.digest()) % Ncurve
        hasher.update(int_to_bytes32(x))
        hasher.update(int_to_bytes32(self.taux))
        hasher.update(int_to_bytes32(self.mu))
        hasher.update(int_to_bytes32(self.t))
        x_ip = bytes_to_int(hasher.digest()) % Ncurve

        #Calculate k
        vec_pow_2 = vPowers(2, N)
        vec_pow_y = vPowers(y, N)
        k = sAdd(sMul(sSq(z), vSum(vec_pow_y)), sMul(sPow(z,3), vSum(vec_pow_2)))
        k = sNeg(k)

        #Debug Printing
        #print()
        #print("Bullet Proof Fiat-Shamir Challenges:")
        #print("y:    " + hex(y))
        #print("z:    " + hex(z))
        #print("k:    " + hex(k))
        #print("x:    " + hex(x))
        #print("x_ip: " + hex(x_ip))

        #Check V, T1, T2
        L61Left = add(multiply(G1, self.taux), multiply(H, self.t))
        L61Right = multiply(H, sAdd(k, sMul(z, vSum(vec_pow_y))))
        L61Right = add(L61Right, multiply(self.V, sSq(z)))
        L61Right = add(L61Right, multiply(self.T1, x))
        L61Right = add(L61Right, multiply(self.T2, sSq(x)))

        if (not eq(L61Left, L61Right)):
            print("V, T1, T2, taux, t check failed!")
            return False

        #Update hasher for Fiat-Shamir
        rounds = len(self.L)
        w = [0]*rounds

        for i in range(0, rounds):
            hasher.update(int_to_bytes32(self.L[i][0].n))
            hasher.update(int_to_bytes32(self.L[i][1].n))
            hasher.update(int_to_bytes32(self.R[i][0].n))
            hasher.update(int_to_bytes32(self.R[i][1].n))
            w[i] = bytes_to_int(hasher.digest()) % Ncurve

            #Debug Printing
            #print("w[" + str(i) + "]: " + hex(w[i]))

        #Calculate Inner Products
        InnerProdG = None
        InnerProdH = None
        for i in range(0, N):
            gScalar = self.a
            hScalar = sMul(self.b, sPow(sInv(y), i))

            for J in range(0, rounds):
                j = rounds - J - 1

                if (i & (1 << j) == 0):
                    gScalar = sMul(gScalar, sInv(w[J]))
                    hScalar = sMul(hScalar, w[J])
                else:
                    gScalar = sMul(gScalar, w[J])
                    hScalar = sMul(hScalar, sInv(w[J]))

            gScalar = sAdd(gScalar, z)
            hScalar = sSub(hScalar, sMul(sAdd(sMul(z, sPow(y, i)), sMul(sSq(z), sPow(2, i))), sPow(sInv(y), i)))

            InnerProdG = add(InnerProdG, multiply(Gi[i], gScalar))
            InnerProdH = add(InnerProdH, multiply(Hi[i], hScalar))

        #Verify Pprime equality
        Pprime = add(self.A, multiply(self.S, x))
        Pprime = add(Pprime, multiply(G1, sNeg(self.mu)))
        
        for i in range(0, rounds):
            Pprime = add(Pprime, multiply(self.L[i], sSq(w[i])))
            Pprime = add(Pprime, multiply(self.R[i], sSq(sInv(w[i]))))

        Pprime = add(Pprime, multiply(H, sMul(self.t, x_ip)))

        Right = add(InnerProdG, InnerProdH)
        Right = add(Right, multiply(H, sMul(sMul(self.a, self.b), x_ip)))
        
        if (eq(Pprime, Right)):
            return True
        else:
            print("Pprime and Inner Product check failed!")
            return False
        
    def Print(self):
        print()
        print("Bulletproof:")
        print("V:    " + print_point(CompressPoint(self.V)))
        print("A:    " + print_point(CompressPoint(self.A)))
        print("S:    " + print_point(CompressPoint(self.S)))
        print("T1:   " + print_point(CompressPoint(self.T1)))
        print("T2:   " + print_point(CompressPoint(self.T2)))
        print("taux: " + hex(self.taux))
        print("mu:   " + hex(self.mu))

        print()
        for i in range(0, len(self.L)):
            print("L[" + str(i) + "]: " + print_point(CompressPoint(self.L[i])))

        print()
        for i in range(0, len(self.R)):
            print("R[" + str(i) + "]: " + print_point(CompressPoint(self.R[i])))

        print()
        print("a:    " + hex(self.a))
        print("b:    " + hex(self.b))
        print("t:    " + hex(self.t))
        print()


print("Creating Bulletproof")
bp = BulletProof.Prove(13, getRandom(), 4)
bp.Print()

print("Verifying Bulletproof")
print(bp.Verify())
