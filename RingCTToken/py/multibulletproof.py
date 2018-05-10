from bulletproofutil import *

class MultiBulletProof:
    V = [None]
    A = None
    S = None
    T1 = None
    T2 = None
    taux = 0
    mu = 0
    L = [None]
    R = [None]
    a = 0
    b = 0
    t = 0
    N = 0
    
    def __init__(self, V, A, S, T1, T2, taux, mu, L, R, a, b, t, N):
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
            self.N = N
    
    def Prove(v, gamma=None, N=32):
        assert(type(v) == list)

        if (gamma == None):
            gamma = getRandom(len(v))
            
        if(type(gamma) != list):
            gamma = [gamma]
            
        assert(len(v) == len(gamma))

        #Make sure M is a power of 2
        import math
        M = len(v)
        logM = math.ceil(math.log(len(v), 2))

        #Check for extra values of M, add random values
        diffM = (2**logM) - M
        if diffM > 0:
            print("warning... M(" + str(M) + ") is not a power of 2")
            print("generating " + str(diffM) + " extra values")
            M = M + diffM
            
        for i in range(0, diffM):
            v = v + [getRandom() % (2**N)]
            gamma = gamma + [getRandom()]

        #Make sure N is a power of 2
        logN = math.floor(math.log(N, 2))
        N = 2**logN

        logMN = logM + logN

        #Make sure enough base points have been generated
        assert(len(Gi) >= (M*N))
        assert(len(Hi) >= (M*N))

        #Create V[]
        V = [None]*M
        for i in range(0, M):
            V[i] = add(multiply(H, v[i]), multiply(G1, gamma[i]))

        #Create A
        aL = [0]*(M*N)
        aR = [0]*(M*N)
        for j in range(0, M):
            for i in range(0, N):
                if (v[j] & (1 << i) != 0):
                    aL[j*N+i] = 1

                aR[j*N+i] = sSub(aL[j*N+i], 1)

        alpha = getRandom()
        A = add(pvExp(aL, aR), multiply(G1, alpha))

        #Create S
        sL = getRandom(M*N)
        sR = getRandom(M*N)
        rho = getRandom()
        S = add(pvExp(sL, sR), multiply(G1, rho))

        #Start hasher for Fiat-Shamir
	#Hash V[], including array length
        hasher = sha3.keccak_256(int_to_bytes32(M*2))
        for j in range(0, M):
            hasher.update(int_to_bytes32(V[j][0].n))
            hasher.update(int_to_bytes32(V[j][1].n))

        hasher = sha3.keccak_256(hasher.digest())
        hasher.update(int_to_bytes32(A[0].n))
        hasher.update(int_to_bytes32(A[1].n))
        hasher.update(int_to_bytes32(S[0].n))
        hasher.update(int_to_bytes32(S[1].n))
	
        y = bytes_to_int(hasher.digest()) % Ncurve
        hasher = sha3.keccak_256(int_to_bytes32(y))
        
        z = bytes_to_int(hasher.digest()) % Ncurve
        hasher = sha3.keccak_256(int_to_bytes32(z))

        #Calculate l0, l1, r0, and r1
        vp2 = vPow(2, N)
        vpy = vPow(y, M*N)
        vpyi = vPow(sInv(y), M*N)
        
        l0 = vSub(aL, [z]*(M*N))
        l1 = sL

        zerosTwos = [0]*(M*N)
        for i in range(0, M*N):
            for j in range(1, M+1):
                temp = 0
                if (i >= ((j-1)*N)) and (i < (j*N)):
                    temp = vp2[i-(j-1)*N]
                zerosTwos[i] = sAdd(zerosTwos[i], sMul(sPow(z, j+1), temp))

        r0 = vAdd(aR, [z]*(M*N))
        r0 = vMul(r0, vpy)
        r0 = vAdd(r0, zerosTwos)
        r1 = vMul(vpy, sR)

        #Calculate t0, t1, and t2 => create T1, T2
        t0 = vDot(l0, r0)
        t1 = sAdd(vDot(l0, r1), vDot(l1, r0))
        t2 = vDot(l1, r1)

        tau1 = getRandom()
        tau2 = getRandom()
        T1 = add(multiply(H, t1), multiply(G1, tau1))
        T2 = add(multiply(H, t2), multiply(G1, tau2))

        #Continue Fiat-Shamir
        hasher.update(int_to_bytes32(T1[0].n))
        hasher.update(int_to_bytes32(T1[1].n))
        hasher.update(int_to_bytes32(T2[0].n))
        hasher.update(int_to_bytes32(T2[1].n))
        x = bytes_to_int(hasher.digest()) % Ncurve
        hasher = sha3.keccak_256(int_to_bytes32(x))
      
        #Calculate taux and mu
        taux = sAdd(sMul(tau1, x), sMul(tau2, sSq(x)))
        for j in range(1, M+1):
            taux = sAdd(taux, sMul(sPow(z, j+1), gamma[j-1]))
        mu = sAdd(sMul(x, rho), alpha)

        #Calculate l, r, and t
        l = vAdd(l0, vScale(l1, x))
        r = vAdd(r0, vScale(r1, x))
        t = vDot(l, r)

        #Continue Fiat-Shamir
        hasher.update(int_to_bytes32(taux))
        hasher.update(int_to_bytes32(mu))
        hasher.update(int_to_bytes32(t))
        x_ip = bytes_to_int(hasher.digest()) % Ncurve
        hasher = sha3.keccak_256(int_to_bytes32(x_ip))

        #Prepare Gprime, Hprime, aprime, and bprime
        Gprime = Gi[:(M*N)]
        Hprime = pvMul(Hi[:(M*N)], vpyi)
        aprime = l
        bprime = r

        #Calculate L and R
        L = [None]*logMN
        R = [None]*logMN
        w = [0]*logMN
        
        nprime = M*N
        rounds = 0
        while (nprime > 1):
            #Halve the vector sizes
            nprime = nprime // 2

            ap1 = vSlice(aprime, 0, nprime)
            ap2 = vSlice(aprime, nprime, len(aprime))
            bp1 = vSlice(bprime, 0, nprime)
            bp2 = vSlice(bprime, nprime, len(bprime))
            gp1 = vSlice(Gprime, 0, nprime)
            gp2 = vSlice(Gprime, nprime, len(Gprime))
            hp1 = vSlice(Hprime, 0, nprime)
            hp2 = vSlice(Hprime, nprime, len(Hprime))
			
            #Calculate L and R
            cL = vDot(ap1, bp2)
            cR = vDot(bp1, ap2)

            L[rounds] = add(pvExpCustom(gp2, hp1, ap1, bp2), multiply(H, sMul(cL, x_ip)))
            R[rounds] = add(pvExpCustom(gp1, hp2, ap2, bp1), multiply(H, sMul(cR, x_ip)))

            #Update hasher for Fiat-Shamir
            hasher.update(int_to_bytes32(L[rounds][0].n))
            hasher.update(int_to_bytes32(L[rounds][1].n))
            hasher.update(int_to_bytes32(R[rounds][0].n))
            hasher.update(int_to_bytes32(R[rounds][1].n))
            w[rounds] = bytes_to_int(hasher.digest()) % Ncurve
            hasher = sha3.keccak_256(int_to_bytes32(w[rounds]))

            #Update Gprime, Hprime, aprime, and bprime
            Gprime = pvAdd(pvScale(gp1, sInv(w[rounds])), pvScale(gp2, w[rounds]))
            Hprime = pvAdd(pvScale(hp1, w[rounds]), pvScale(hp2, sInv(w[rounds])))

            aprime = vAdd(vScale(ap1, w[rounds]), vScale(ap2, sInv(w[rounds])))
            bprime = vAdd(vScale(bp1, sInv(w[rounds])), vScale(bp2, w[rounds]))

            rounds = rounds + 1

        #Debug Printing
        #print()
        #print("Bullet Proof Fiat-Shamir Challenges:")
        #print("y:    " + hex(y))
        #print("z:    " + hex(z))
        #print("x:    " + hex(x))
        #print("x_ip: " + hex(x_ip))
        #for i in range(0, len(w)):
        #    print("w[" + str(i) + "]: " + hex(w[i]))
        
        return MultiBulletProof(V, A, S, T1, T2, taux, mu, L, R, aprime[0], bprime[0], t, N)

    #Verify batch of proofs
    def VerifyMulti(proofs):
        assert (type(proofs) == list)
        assert (type(proofs[0]) == MultiBulletProof)

        #Find longest proof
        maxLength = 0
        for p in range(0, len(proofs)):
            if (len(proofs[p].L) > maxLength):
                maxLength = len(proofs[p].L)

        maxMN = 2**maxLength

        #Initialize variables for checks
        y0 = 0              #taux
        y1 = 0              #t-(k+z+Sum(y^i))
        Y2 = None           #z-V sum
        Y3 = None           #x*T1
        Y4 = None           #x^2*T2
        Z0 = None           #A + xS
        z1 = 0              #mu
        Z2 = None           #Li / Ri sum
        z3 = 0              #(t-ab)*x_ip
        z4 = [0]*maxMN      #g scalar sum
        z5 = [0]*maxMN      #h scalar sum

        #Verify proofs
        for p in range(0, len(proofs)):
            proof = proofs[p]
            logMN = len(proof.L)
            M = 2**(logMN) // proof.N

            #Pick weight for this proof
            #weight = getRandom()
            weight = 1

            #Reconstruct Challenges
			#Hash V[], including array length
            hasher = sha3.keccak_256(int_to_bytes32(M*2))
            for j in range(0, M):
                hasher.update(int_to_bytes32(proof.V[j][0].n))
                hasher.update(int_to_bytes32(proof.V[j][1].n))

	    #Continue Hasher
            hasher = sha3.keccak_256(hasher.digest())
            hasher.update(int_to_bytes32(proof.A[0].n))
            hasher.update(int_to_bytes32(proof.A[1].n))
            hasher.update(int_to_bytes32(proof.S[0].n))
            hasher.update(int_to_bytes32(proof.S[1].n))
            y = bytes_to_int(hasher.digest()) % Ncurve
            
            hasher = sha3.keccak_256(int_to_bytes32(y))
            z = bytes_to_int(hasher.digest()) % Ncurve
            
            hasher = sha3.keccak_256(int_to_bytes32(z))
            hasher.update(int_to_bytes32(proof.T1[0].n))
            hasher.update(int_to_bytes32(proof.T1[1].n))
            hasher.update(int_to_bytes32(proof.T2[0].n))
            hasher.update(int_to_bytes32(proof.T2[1].n))
            x = bytes_to_int(hasher.digest()) % Ncurve
            
            hasher = sha3.keccak_256(int_to_bytes32(x))
            hasher.update(int_to_bytes32(proof.taux))
            hasher.update(int_to_bytes32(proof.mu))
            hasher.update(int_to_bytes32(proof.t))
            x_ip = bytes_to_int(hasher.digest()) % Ncurve
            hasher = sha3.keccak_256(int_to_bytes32(x_ip))

            #Calculate k
            vp2 = vPow(2, proof.N)
            vpy = vPow(y, M*proof.N)
            vpyi = vPow(sInv(y), M*proof.N)
            
            k = sMul(sSq(z), vSum(vpy))
            for j in range(1, M+1):
                k = sAdd(k, sMul(sPow(z, j+2), vSum(vp2)))
            k = sNeg(k)

            #Compute inner product challenges
            w = [0]*logMN
            for i in range(0, logMN):
                hasher.update(int_to_bytes32(proof.L[i][0].n))
                hasher.update(int_to_bytes32(proof.L[i][1].n))
                hasher.update(int_to_bytes32(proof.R[i][0].n))
                hasher.update(int_to_bytes32(proof.R[i][1].n))
                w[i] = bytes_to_int(hasher.digest()) % Ncurve
                hasher = sha3.keccak_256(int_to_bytes32(w[i]))

            #Debug Printing
            #print()
            #print("Bullet Proof Fiat-Shamir Challenges:")
            #print("y:    " + hex(y))
            #print("z:    " + hex(z))
            #print("x:    " + hex(x))
            #print("x_ip: " + hex(x_ip))
            #for i in range(0, len(w)):
            #    print("w[" + str(i) + "]: " + hex(w[i]))
            #print("k:    " + hex(k))

            #Compute base point scalars
            for i in range(0, M*proof.N):
                gScalar = proof.a
                hScalar = sMul(proof.b, vpyi[i])

                for J in range(0, logMN):
                    j = logMN - J - 1
                    if (i & (1 << j) == 0):
                        gScalar = sMul(gScalar, sInv(w[J]))
                        hScalar = sMul(hScalar, w[J])
                    else:
                        gScalar = sMul(gScalar, w[J])
                        hScalar = sMul(hScalar, sInv(w[J]))

                gScalar = sAdd(gScalar, z)
                hScalar = sSub(hScalar, sMul(sAdd(sMul(z, vpy[i]), sMul(sPow(z, 2+(i//proof.N)), vp2[i%proof.N])), vpyi[i]))

                #Update z4 and z5 checks for Stage 2
                z4[i] = sAdd(z4[i], sMul(gScalar, weight))
                z5[i] = sAdd(z5[i], sMul(hScalar, weight))

            #Apply weight to remaining checks (everything but z4 and z5)
            #Stage 1 Checks
            y0 = sAdd(y0, sMul(proof.taux, weight))
            y1 = sAdd(y1, sMul(sSub(proof.t, sAdd(k, sMul(z, vSum(vpy)))), weight))

            temp = None
            for j in range(0, M):
                temp = add(temp, multiply(proof.V[j], sPow(z, j+2)))
                
            Y2 = add(Y2, multiply(temp, weight))
            Y3 = add(Y3, multiply(proof.T1, sMul(x, weight)))
            Y4 = add(Y4, multiply(proof.T2, sMul(sSq(x), weight)))

            #Stage 2 Checks
            Z0 = add(Z0, multiply(add(proof.A, multiply(proof.S, x)), weight))
            z1 = sAdd(z1, sMul(proof.mu, weight))

            temp = None
            for i in range(0, logMN):
                temp = add(temp, multiply(proof.L[i], sSq(w[i])))
                temp = add(temp, multiply(proof.R[i], sSq(sInv(w[i]))))
            Z2 = add(Z2, multiply(temp, weight))
            z3 = sAdd(z3, sMul(sMul(sSub(proof.t, sMul(proof.a, proof.b)), x_ip), weight))

        #Perform all Checks
        Check1 = add(multiply(G1, y0), multiply(H, y1))
        Check1 = add(Check1, neg(Y2))
        Check1 = add(Check1, neg(Y3))
        if (not eq(Check1, Y4)):
            print("Stage 1 Check Failed!")
            return False

        Check2 = add(Z0, multiply(G1, sNeg(z1)))
        Check2 = add(Check2, multiply(H, z3))
        for i in range(0, maxMN):
            Check2 = add(Check2, multiply(Gi[i], sNeg(z4[i])))
            Check2 = add(Check2, multiply(Hi[i], sNeg(z5[i])))

        #More Debug Printing
        #print("y0: " + hex(y0))
        #print("y1: " + hex(y1))
        #print("Y2: " + hex(CompressPoint(Y2)))
        #print("Y3: " + hex(CompressPoint(Y3)))
        #print("Y4: " + hex(CompressPoint(Y4)))
        #print()
        #print("Z0: " + hex(CompressPoint(Z0)))
        #print("z1: " + hex(z1))
        #print("Z2: " + hex(CompressPoint(Z2)))
        #print("z3: " + hex(z3))
        #for i in range(0, len(z4)):
        #    print("z4[" + str(i) + "]: " + hex(z4[i]))
        #for i in range(0, len(z5)):
        #    print("z5[" + str(i) + "]: " + hex(z5[i]))            

        if (Check2 != neg(Z2)):
            print("Stage 2 Check Failed!")
            return False
        else:
            return True
        
    #On verify self, this is the only proof
    def Verify(self):
        return MultiBulletProof.VerifyMulti([self])

    def Print(self):
        print()
        print("Multi Bulletproof:")
        
        for i in range(0, len(self.V)):
            print("V[" + str(i) + "]: " + print_point(CompressPoint(self.V[i])))
            
        print("A:    " + print_point(CompressPoint(self.A)))
        print("S:    " + print_point(CompressPoint(self.S)))
        print("T1:   " + print_point(CompressPoint(self.T1)))
        print("T2:   " + print_point(CompressPoint(self.T2)))
        print("taux: " + hex(self.taux))
        print("mu:   " + hex(self.mu))

        for i in range(0, len(self.L)):
            print("L[" + str(i) + "]: " + print_point(CompressPoint(self.L[i])))

        for i in range(0, len(self.R)):
            print("R[" + str(i) + "]: " + print_point(CompressPoint(self.R[i])))

        print("a:    " + hex(self.a))
        print("b:    " + hex(self.b))
        print("t:    " + hex(self.t))
        print("N:    " + str(self.N))
        print()

    def Print_Serialized(self):
        print("Multi Bullet Proof:")
        print("[" + str(1) + "," + str(len(self.V*2)) + ",")
        print(str(len(self.L*2)) + "," + str(len(self.R*2)) + ",")
        for i in range(0, len(self.V)):
            print(hex(self.V[i][0].n) + ",")
            print(hex(self.V[i][1].n) + ",")
        print(hex(self.A[0].n) + ",")
        print(hex(self.A[1].n) + ",")
        print(hex(self.S[0].n) + ",")
        print(hex(self.S[1].n) + ",")
        print(hex(self.T1[0].n) + ",")
        print(hex(self.T1[1].n) + ",")
        print(hex(self.T2[0].n) + ",")
        print(hex(self.T2[1].n) + ",")
        print(hex(self.taux) + ",")
        print(hex(self.mu) + ",")

        for i in range(0, len(self.L)):
            print(hex(self.L[i][0].n) + ",")
            print(hex(self.L[i][1].n) + ",")

        for i in range(0, len(self.R)):
            print(hex(self.R[i][0].n) + ",")
            print(hex(self.R[i][1].n) + ",")

        print(hex(self.a) + ",")
        print(hex(self.b) + ",")
        print(hex(self.t) + ",")
        print(str(self.N) + "]")

    def Print_Multi_Serialized(proofs):
        print("Multi Bullet Proof:")
        print("[" + str(len(proofs)) + ",")
        for i in range(0, len(proofs)):
            if (i > 0):
                print(",")
                
            print(str(len(proofs[i].V*2)) + ",")
            print(str(len(proofs[i].L*2)) + "," + str(len(proofs[i].R*2)) + ",")
            for i in range(0, len(proofs[i].V)):
                print(hex(proofs[i].V[i][0].n) + ",")
                print(hex(proofs[i].V[i][1].n) + ",")
            print(hex(proofs[i].A[0].n) + ",")
            print(hex(proofs[i].A[1].n) + ",")
            print(hex(proofs[i].S[0].n) + ",")
            print(hex(proofs[i].S[1].n) + ",")
            print(hex(proofs[i].T1[0].n) + ",")
            print(hex(proofs[i].T1[1].n) + ",")
            print(hex(proofs[i].T2[0].n) + ",")
            print(hex(proofs[i].T2[1].n) + ",")
            print(hex(proofs[i].taux) + ",")
            print(hex(proofs[i].mu) + ",")

            for j in range(0, len(proofs[i].L)):
                print(hex(proofs[i].L[j][0].n) + ",")
                print(hex(proofs[i].L[j][1].n) + ",")

            for j in range(0, len(proofs[i].R)):
                print(hex(proofs[i].R[j][0].n) + ",")
                print(hex(proofs[i].R[j][1].n) + ",")

            print(hex(proofs[i].a) + ",")
            print(hex(proofs[i].b) + ",")
            print(hex(proofs[i].t) + ",")
            print(str(proofs[i].N), end="")

        print ("]")


def MultiBulletProofTest1():
    #Test verifying two bullet proofs with same number of commtiments and values of N
    print()
    print("Creating Multi Bulletproof 1")
    bp1 = MultiBulletProof.Prove([13], N=8)
    bp1.Print()

    print("Verifying Multi Bulletproof 1")
    print(bp1.Verify())

    print()
    print("Creating Multi Bulletproof 2")
    bp2 = MultiBulletProof.Prove([27], N=8)
    bp2.Print()

    print("Verifying Multi Bulletproof 2")
    print(bp2.Verify())

    print()
    print("Verifying Both Multi Bulletproofs at Once")
    bp = [bp1, bp2]
    print(MultiBulletProof.VerifyMulti(bp))
    return bp

def MultiBulletProofTest2():
    #Test verifying two bullet proofs at once with different values of N
    print()
    print("Creating Multi Bulletproof 1")
    bp1 = MultiBulletProof.Prove([13, 4], N=8)
    bp1.Print()

    print("Verifying Multi Bulletproof 1")
    print(bp1.Verify())

    print()
    print("Creating Multi Bulletproof 2")
    bp2 = MultiBulletProof.Prove([27, 1], N=16)
    bp2.Print()

    print("Verifying Multi Bulletproof 2")
    print(bp2.Verify())

    print()
    print("Verifying Both Multi Bulletproofs at Once")
    bp = [bp1, bp2]
    print(MultiBulletProof.VerifyMulti(bp))
    return bp

def MultiBulletProofTest3():
    #Test verifying two bullet proofs with different numbers of commitments
    print()
    print("Creating Multi Bulletproof 1")
    bp1 = MultiBulletProof.Prove([13, 4, 8, 12], N=8)
    bp1.Print()

    print("Verifying Multi Bulletproof 1")
    print(bp1.Verify())

    print()
    print("Creating Multi Bulletproof 2")
    bp2 = MultiBulletProof.Prove([27, 1], N=8)
    bp2.Print()

    print("Verifying Multi Bulletproof 2")
    print(bp2.Verify())

    print()
    print("Verifying Both Multi Bulletproofs at Once")
    bp = [bp1, bp2]
    print(MultiBulletProof.VerifyMulti(bp))
    return bp

def MultiBulletProofTest4():
    #Test verifying two bullet proofs with different numbers of commitments and different values of N
    print()
    print("Creating Multi Bulletproof 1")
    bp1 = MultiBulletProof.Prove([13, 4, 8, 12], N=8)
    bp1.Print()

    print("Verifying Multi Bulletproof 1")
    print(bp1.Verify())

    print()
    print("Creating Multi Bulletproof 2")
    bp2 = MultiBulletProof.Prove([27, 1], N=16)
    bp2.Print()

    print("Verifying Multi Bulletproof 2")
    print(bp2.Verify())

    print()
    print("Verifying Both Multi Bulletproofs at Once")
    bp = [bp1, bp2]
    print(MultiBulletProof.VerifyMulti(bp))
    return bp

bp = MultiBulletProof.Prove([13, 4], N=16)
