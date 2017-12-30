N = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
 
def rand():
    import random
    return (random.getrandbits(254) % N)
 
def randmul(count):
    for i in range(0,count-1):
        print("\"" + hex(rand()) + "\",")
 
    return("\"" + hex(rand()) + "\"")
 
def hexArray(arr):
    print ("[", end = "")
    for i in range(0, len(arr)-1):
        print("\"" + hex(arr[i]) + "\",")
 
    print("\"" + hex(arr[len(arr)-1]) + "\"]")
 
def createTx(v1, p1, o1):
    import math
    b1 = math.floor(math.log(v1, 4)) + 1
    bf = rand()
 
    print("Call CTGenerateTx(")
    print("[" + str(v1) + ", " + str(p1) + ", " + str(o1) + ",")
    print("\"" + hex(bf) + "\",")
    print(randmul(5*b1-1) + "]")
    print(")")
    print("Blinding Factor = \"" + hex(bf) + "\"")
   
def createTx2(v1, p1, o1, extrabits1, v2, p2, o2, extrabits2, target_bf):
    import math
    b1 = math.floor(math.log(v1, 4)) + 1 + extrabits1
    b2 = math.floor(math.log(v2, 4)) + 1 + extrabits2
    bf1 = rand()
    bf2 = (target_bf + (N - bf1)) % N
   
    print("Call CTGenerateTx(")
    print("[" + str(v1) + ", " + str(p1) + ", " + str(o1) + ",")
    print("\"" + hex(bf1) + "\",")
    print(randmul(5*b1-1) + "]")
    print(")")
    print("Blinding Factor TXa = \"" + hex(bf1) + "\"")
 
    print("Call CTGenerateTx(")
    print("[" + str(v2) + ", " + str(p2) + ", " + str(o2) + ",")
    print("\"" + hex(bf2) + "\",")
    print(randmul(5*b2-1) + "]")
    print(")")
    print("Blinding Factor TXb = \"" + hex(bf2) + "\"")
