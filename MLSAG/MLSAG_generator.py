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

PubKeys = [0xa193a5a2223974dddbdae7e5be82ac8c5cedb51c749d7746c6914044a62512e2,
           0x4cd98d67b36e71a76cdd64574f1b73665fe24600f3d7820a843c1aecb883b3f,
           0x95f3554385d92e4a88abb52b8f34c01b76203821eea63a8ae8a3d3e91323773e,
           0x27d98aed737539c341d947fb8fe9d9d875ec7523dcb73bb556c1b888c163668c,
           0x27cc5c8fdd2034e5b3c5a45eeb6e4b99bbf3a41d94c167d28c073089d544cd4,
           0x2f035bdffa4df30bb40848ef6c9f99bad7eb7d5e692ead4619e292dd21429c84,
           0xaabe274e9832ced5e387b928d59d3ecf6a3e979e76420e486d171da39e8dcec0,
           0x184c9d4d2ea09a4f31bfca484dce7b066a6383a3f5bf751f1cfdcafe053c7ffc,
           0x1c133285336e739b061bb3f4813f391b24f03d91c5d9df5a3e89848bbd46ba62,
           0xd08ef01cfc3fcc91bd96d41fef4af1f276bd3e4d006b3f09af8124c85427cd0,
           0x22397a5c0650e5ba8102742b2b1319c2588084aa9aaa0c9f6eb7b7a26da529b4,
           0x5c4b667c97519827ec840555d00ade49c5879b2b0d950250a0e28f250473316,
           0x1fbb6796c7b26e5f477d7b8af3aa4c8667c25b62a941c2f6c6cad219294964d8,
           0x847f050d3d14216c229f2a660d80f54f23c96e69c0885fb1de076bce78574885,
           0x9ecbc2067e99fea8c5999bf4fb9c8a6542ffa5f54bcb57e4f7e8482057bc836c,
           0xaf78937e50d9288e665b09c874435b4cf013a559935ab63d4af54d23011aad0c]
           
PrivKeys = [0x73c07c62b6cb96a3498aaa2ddc2436c8e63a86a53988731c6e302b811a919e7,
            0x27a006567c875262d36272a6e91853d2f31a8d2458cab7295573d76ac315ee2d,
            0x9289403c730f541926334bb2b5ba0562a34a4e7125ae833d1becbe388a75c28,
            0x2a7157b5e13b687dd887f90435aeed7d2925c4bbd3dcfecacd01e3a01e1d9706,
            0x2fe0d5e4180a98e682baf9b918727d4b57e09ad5db8bcbc15a86654da0e3475f,
            0x35f6eb9db433bc9207dc76da8ba25c29954c9fdf1701aa82388dc70bb6c79d2,
            0x1a9794b2ac0b3bfb66bf10a003ae7b38be24991765ee2d505879e302954694a,
            0x78b5ecc05aab46de479dab0329288a2dd3dca9a6899545b0515bfbb3ec793c2,
            0x37a6331d3c8d90e06a954710eeb04a36273a4b6b30cca232dfbfc9a9de2c2c3,
            0x243ed417a6e3d0add3de218d10fa9992dda95a7925810df281b38f2292854e8e,
            0x165b1b6bd10feb4632442210b9edde9d6fcd97cb2d2e606919e43726f2c22e46,
            0x2ab75519a7d2257af30c460e1bb0e0ea2d272b6015d5002d292b2740b08499f,
            0x1119654be2ecb84a54fa6c0de4d71762dd90e441b0603a053f70a3fcabb8b49,
            0x12c58e3a45d3f1623ad0fbf567e893da2548adea020831af1c43f6b2b4b01328,
            0xb2455c8d001432e2c3725cfc667e2893eb37c32855cda6f64c6edd1176e8e41,
            0xe54949e153f94a81a0e849f0f37f85753fe6ca67b8fe9b56ce076032273bc02]

def sag_test(N=3):
    import random
    key = 0
    msgHash = rand()
    print("\"" + hex(msgHash) + "\",")
    xk = PrivKeys[0]
    key = key+1
    
    print("\"" + hex(xk) + "\",")
    j = random.randint(0,N-1)
    print("\"" + str(j) + "\",")
    print("[", end="")
    for i in range(0,N-1):
        print("\"" + hex(PubKeys[key]), end="")
        key = key + 1
        if (i != (N-2)):
            print("\",")
        else:
            print("\"],")

    print("[", end="")
    for i in range(0,N):
        rnd = rand()
        print("\"" + hex(rnd), end="")
        if (i != (N-1)):
            print("\",")
        else:
            print("\"]")

def msag_test(N=2, M=3):
    import random
    key = 0
    
    print("\"" + str(M) + "\",")
    
    msgHash = rand()
    print("\"" + hex(msgHash) + "\",")

    print("[", end="")
    for i in range(0, M):
        xk = PrivKeys[key]
        key = key+1
        print("\"" + hex(xk), end="")
        if (i != (M-1)):
            print("\",")
        else:
            print("\"],")

    print("[", end="")
    for i in range(0, M):
        j = random.randint(0,N-1)
        print("\"" + str(j), end="")
        if (i != (M-1)):
            print("\",")
        else:
            print("\"],")

    print("[", end="")
        
    for i in range(0,M*(N-1)-1):
        print("\"" + hex(PubKeys[key]), end="")
        key = key + 1
        if (i != M*(N-1)-2):
            print("\",")
        else:
            print("\"],")

    print("[", end="")
        
    for i in range(0,M*N-1):
        rnd = rand()
        print("\"" + hex(rnd), end="")
        if (i != (M*N-2)):
            print("\",")
        else:
            print("\"]")
