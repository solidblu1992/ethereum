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
	
def SerializeBasePoints():
	print("Gi:")
	for i in range(0, len(Gi)):
		print(point_to_str(Gi[i]) + ",")
	
	print()
	print("Hi:")
	for i in range(0, len(Hi)):
		print(point_to_str(Hi[i]) + ",")

def CheckBasePoints():
    for i in range(0, len(Gi)):
        if (is_on_curve(Gi[i], 3)):
            print("Gi[" + str(i) + "] passes!")
        else:
            print("Gi[" + str(i) + "] fails!")

    for i in range(0, len(Hi)):
        if (is_on_curve(Hi[i], 3)):
            print("Hi[" + str(i) + "] passes!")
        else:
            print("Hi[" + str(i) + "] fails!")		

(Gi, Hi) = GenBasePoints(32*4)

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

def vPow(x, N):
    if (x == 0):
        return [0]*N
    elif (x == 1):
        return [1]*N

    out = [0]*N
    out[0] = 1
    for i in range(1, N):
        out[i] = sMul(out[i-1], x)

    return out

def vSum(a):
    out = a[0]
    for i in range(1, len(a)):
        out = sAdd(out, a[i])

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

def pvMul(A, a):
    assert(len(A) == len(a))

    out = [None]*len(A)
    for i in range(0, len(A)):
        out[i] = multiply(A[i], a[i])

    return out
