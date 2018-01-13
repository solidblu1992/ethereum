from ring_signatures import *
from ct import *

class StealthTransaction:
    dest_pub_key = 0
    dest_dhe_point = 0
    dest_encrypted_data = 0
    
    def __init__(self, pub_key, dhe_point, encrypted_data):
        self.dest_pub_key = pub_key
        self.dest_dhe_point = dhe_point
        self.dest_encrypted_data = encrypted_data



class RingCTToken:
    MyPrivateViewKey = 0
    MyPublicViewKey = (FQ(0), FQ(0))
    
    MyPrivateSpendKey = 0
    MyPublicSpendKey = (FQ(0), FQ(0))

    MyPrivateKeys = []
    MyPublicKeys = []

    def GenerateNewStealthAddress(self):
        self.MyPrivateViewKey = getRandom()
        self.MyPrivateSpendKey = getRandom()

        self.MyPublicViewKey = multiply(G1, self.MyPrivateViewKey)
        self.MyPublicSpendKey = multiply(G1, self.MyPrivateSpendKey)

    def GenerateNewAddress(self):
        x = getRandom()
        self.MyPrivateKeys = self.MyPrivateKeys + [x]
        self.MyPublicKeys = self.MyPublicKeys + [multiply(G1, x)]

    def GenerateNewAddresses(self, n):
        for i in range(0, n):
            self.GenerateNewAddress()

    def GenerateStealthTx(self, pubViewKey, pubSpendKey, data):
        r = getRandom()
        R = multiply(G1, r)

        ss = hash_of_point(multiply(pubViewKey, r)) % Ncurve
        dest_pub_key = add(multiply(G1, ss), pubSpendKey)

        return StealthTransaction(dest_pub_key, R, data)
    
    def PrintStealthAddress(self):
        print("Public View Key:\t" + print_point(CompressPoint(self.MyPublicViewKey)))
        print("Public Spend Key:\t" + print_point(CompressPoint(self.MyPublicSpendKey)))

    def PrintAddresses(self):
        for i in range(0, len(self.MyPublicKeys)):
            print("Public Key " + str(i) + ":\t\t" + print_point(CompressPoint(self.MyPublicKeys[i])))
    
    def __init__(self):
        self.GenerateNewStealthAddress()

def RingCTTest():
    rct = RingCTToken()
    rct.PrintStealthAddress()
    #rct.GenerateNewAddresses(5)

    rct.PrintAddresses()

    stx = rct.GenerateStealthTx(rct.MyPublicViewKey, rct.MyPublicSpendKey, 0)
    print("Stealth Tx Pub Key:\t" + print_point(CompressPoint(stx.dest_pub_key)))
    print("Stealth Tx DHE Point:\t" + print_point(CompressPoint(stx.dest_dhe_point)))
    return rp



