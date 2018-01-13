from ring_signatures import *
from ct import *
from stealth import *

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
    return rp



