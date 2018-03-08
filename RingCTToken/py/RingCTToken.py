from ring_signatures import *
from ct import *
from stealth import *
from ringct import *

class RingCTToken:
    MyPrivateViewKey = 0
    MyPublicViewKey = (FQ(0), FQ(0))
    
    MyPrivateSpendKey = 0
    MyPublicSpendKey = (FQ(0), FQ(0))

    MyUTXOPool = []
    MyPendingUTXOPool = []
    MixinTxPool = []

    debugPrintingEnabled = False

    #def __init__(self):

    def GenerateNewStealthAddress(self):
        self.MyPrivateViewKey = getRandom()
        self.MyPrivateSpendKey = getRandom()

        self.MyPublicViewKey = multiply(G1, self.MyPrivateViewKey)
        self.MyPublicSpendKey = multiply(G1, self.MyPrivateSpendKey)

        if (self.debugPrintingEnabled):
            print()
            print("New Stealth Address Generated:")
            print("Public View Key:\t" + print_point(CompressPoint(self.MyPublicViewKey)))
            print("Public Spend Key:\t" + print_point(CompressPoint(self.MyPublicSpendKey)))

        return [self.MyPublicViewKey, self.MyPublicSpendKey]

    def GetUTXOPrivKey(self, index):
        return(self.MyUTXOPool[index].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey))

    def DecryptUTXO(self, index):
        return(self.MyUTXOPool[index].DecryptData(self.MyPrivateSpendKey))

    def GenerateUTXOs(self, v, bf, pub_viewkey=None, pub_spendkey=None):
        if (type(v) != list):
            v = [v]
        if (type(bf) != list):
            bf = [bf]
        assert(len(v) == len(bf))

        count = len(v)

        if (self.debugPrintingEnabled):
            print()
            print("New Unspend Tx Outputs (" + str(count) + ") Generated:")

        for i in range(0, count):
            r = getRandom()
            if (pub_viewkey == None or pub_spendkey == None):
                stealth_tx = StealthTransaction.Generate(self.MyPublicViewKey, self.MyPublicSpendKey, v[i], bf[i], r)
                self.MyUTXOPool = self.MyUTXOPool + [stealth_tx]
                mine = True
            else:
                stealth_tx = StealthTransaction.Generate(pub_viewkey, pub_spendkey, v[i], bf[i], r)
                self.MixinTxPool = self.MixinTxPool + [stealth_tx]
                mine = False

            if (self.debugPrintingEnabled):
                print("UTXO " + str(len(self.MyUTXOPool)-1) + ":")
                    
                if (mine and self.debugPrintingEnabled):
                    print("[priv key: " + hex(self.MyUTXOPool[-1].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)) + "]")
                    print("[value: " + str(v[i]) + "]")
                    print("[bf: " + hex(bf[i]) + "]")

                stealth_tx.Print()
                print()

    def GeneratePendingUTXOs(self, v, bf, pub_viewkey=None, pub_spendkey=None):
        if (type(v) != list):
            v = [v]
        if (type(bf) != list):
            bf = [bf]
        assert(len(v) == len(bf))

        count = len(v)

        if (self.debugPrintingEnabled):
            print()
            print("New Pending Unspend Tx Outputs (" + str(count) + ") Generated:")

        for i in range(0, count):
            r = getRandom()
            if (pub_viewkey == None or pub_spendkey == None):
                stealth_tx = StealthTransaction.Generate(self.MyPublicViewKey, self.MyPublicSpendKey, v[i], bf[i], r)
                self.MyPendingUTXOPool = self.MyPendingUTXOPool + [stealth_tx]
                mine = True
            else:
                stealth_tx = StealthTransaction.Generate(pub_viewkey, pub_spendkey, v[i], bf[i], r)
                self.MixinTxPool = self.MixinTxPool + [stealth_tx]
                mine = False

            if (self.debugPrintingEnabled):
                print("UTXO " + str(len(self.MyPendingUTXOPool)-1) + ":")
                    
                if (mine and self.debugPrintingEnabled):
                    print("[priv key: " + hex(self.MyPendingUTXOPool[-1].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)) + "]")
                    print("[value: " + str(v[i]) + "]")
                    print("[bf: " + hex(bf[i]) + "]")

                stealth_tx.Print()
                print()
            
    def GenerateMixinAddresses(self, count=1):        
        if (self.debugPrintingEnabled):
            print("\nNew Mixin Transactions (" + str(count) + ") Generated:")
        
        for i in range(0, count):
            stealth_tx = StealthTransaction(multiply(G1, getRandom()), 0, multiply(G1, getRandom()), 0)
            self.MixinTxPool = self.MixinTxPool + [stealth_tx]

            if(self.debugPrintingEnabled):
                print("TX " + str(len(self.MixinTxPool)-1) + ":")
                stealth_tx.Print()
                print()

    def MarkUTXOAsSpent(self, indices):
        if (type(indices) != list):
            indices = [indices]

        index = 0
        for i in range(0, len(indices)):
            index = indices[i]-i
            self.MixinTxPool = self.MixinTxPool + [self.MyUTXOPool[index]]
            self.MyUTXOPool = self.MyUTXOPool[:index] + self.MyUTXOPool[index+1:]

            if(self.debugPrintingEnabled):
                print("Mixin Tx " + str(len(self.MixinTxPool)+1) + " Created from UTXO " + str(indices[i]))

        if(self.debugPrintingEnabled):
            print("New Mixin Tx count: " + str(len(self.MixinTxPool)))
            print("New total UTXO count: " + str(len(self.MyUTXOPool)))
            print()

    def MintPendingUTXOs(self, indices):
        if (type(indices) != list):
            indices = [indices]

        index = 0
        for i in range(0, len(indices)):
            index = indices[i]-i
            self.MyUTXOPool = self.MyUTXOPool + [self.MyPendingUTXOPool[index]]
            self.MyPendingUTXOPool = self.MyPendingUTXOPool[:index] + self.MyPendingUTXOPool[index+1:]

            if(self.debugPrintingEnabled):
                print("UTXO " + str(len(self.MyUTXOPool)+1) + " Created from Pending UTXO " + str(indices[i]))

        if(self.debugPrintingEnabled):
            print("New total UTXO count: " + str(len(self.MyUTXOPool)))
            print("New total pending UTXO count: " + str(len(self.MyPendingUTXOPool)))
            print()

    def PrintUTXOPool(self):
        for i in range(0, len(self.MyUTXOPool)):
            print("UTXO " + str(i) + ":")
            print("pub key: " + hex(CompressPoint(self.MyUTXOPool[i].pub_key)))
            print("[priv key: " + hex(self.MyUTXOPool[i].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)) + "]")
            (v, bf) = self.MyUTXOPool[i].DecryptData(self.MyPrivateSpendKey)
            print("[value: " + str(v) + "]")
            print("[bf: " + hex(bf) + "]")
            print()

    def PrintPendingUTXOPool(self):
        for i in range(0, len(self.MyPendingUTXOPool)):
            print("Pending UTXO " + str(i) + ":")
            print("pub key: " + hex(CompressPoint(self.MyPendingUTXOPool[i].pub_key)))
            print("[priv key: " + hex(self.MyPendingUTXOPool[i].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)) + "]")
            (v, bf) = self.MyPendingUTXOPool[i].DecryptData(self.MyPrivateSpendKey)
            print("[value: " + str(v) + "]")
            print("[bf: " + hex(bf) + "]")
            print()

    def PrintMixinPool(self):
        print("Mixin Tx Pool:")
        for i in range(0, len(self.MixinTxPool)):
            print("pub key " + str(i) + ": " + hex(CompressPoint(self.MixinTxPool[i].pub_key)))

        print()
        

def RingCTTokenTest(total_value=(10**17), input_count = 3, mixin_count = 3, output_count = 2):
    rct = RingCTToken()
    rct.debugPrintingEnabled = False
    
    print("Generating Initial Stealth Address...")
    rct.GenerateNewStealthAddress()

    print("Generating Input Transactions for TX0...")
    value = [total_value // input_count] * input_count
    value[-1] = value[-1] + (total_value % input_count)
    rct.GenerateUTXOs(value, [0]*input_count)

    print("Generating Mixin Transactions for TX0...")
    rct.GenerateMixinAddresses(input_count*mixin_count)

    print("Generating Output Transactions for TX0...")
    value = [total_value // output_count] * output_count
    value[-1] = value[-1] + (total_value % output_count)
    rct.GeneratePendingUTXOs(value, getRandom(output_count))

    rct.PrintUTXOPool()
    rct.PrintMixinPool()
    rct.PrintPendingUTXOPool()

    rct.debugPrintingEnabled = True
    rct.MintPendingUTXOs([0,1])

    return rct
    
rct = RingCTTokenTest()

