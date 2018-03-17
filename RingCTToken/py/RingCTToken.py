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

    def SetStealthAddress(self, privViewKey, privSpendKey):
        self.MyPrivateViewKey = privViewKey
        self.MyPrivateSpendKey = privSpendKey

        self.MyPublicViewKey = multiply(G1, self.MyPrivateViewKey)
        self.MyPublicSpendKey = multiply(G1, self.MyPrivateSpendKey)

        if (self.debugPrintingEnabled):
            print()
            print("New Stealth Address Assigned:")
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
            stealth_tx = StealthTransaction(multiply(G1, getRandom()), multiply(G1, getRandom()), multiply(G1, 1*10**16), PCAESMessage.Encrypt(getRandom(), getRandom(), getRandom()))
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

    #Import Tx's from Array
    def AddTx(self, tx):
        if (tx.CheckOwnership(self.MyPrivateViewKey, self.MyPublicSpendKey)):
            duplicate = False
            for i in range(0, len(self.MyUTXOPool)):
                if (CompressPoint(self.MyUTXOPool[i].pub_key) == CompressPoint(tx.pub_key)):
                    duplicate = True

            if (not duplicate):
                self.MyUTXOPool = self.MyUTXOPool + [tx]

        else:
            duplicate = False
            for i in range(0, len(self.MixinTxPool)):
                if (CompressPoint(self.MixinTxPool[i].pub_key) == CompressPoint(tx.pub_key)):
                    duplicate = True

            if (not duplicate):
                self.MixinTxPool = self.MixinTxPool + [tx]

    #Generate Spend Tx
    def SpendTx(self, UTXOindices, mixins=2, pubViewKey=None, pubSpendKey=None):
        UTXOindices = list(set(UTXOindices)) #remove duplicates
        mixin_count = len(UTXOindices)*mixins
        assert((len(self.MixinTxPool)+len(self.MyUTXOPool)-len(UTXOindices)) >= mixin_count) #Must have enough mixin transactions to perform Tx

        print("Generating Spend Tx...")

        #Get Private Keys, values, and blinding factors from UTXO set
        in_utxos = []
        in_values = [0] * len(UTXOindices)
        in_bfs = [0] * len(UTXOindices)
        in_xk = [0] * len(UTXOindices)
        for i in range(0, len(UTXOindices)):
            in_utxos = in_utxos + [self.MyUTXOPool[i]]
            (in_values[i], in_bfs[i]) = in_utxos[i].DecryptData(self.MyPrivateSpendKey)
            in_xk[i] = in_utxos[i].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)

        #Pick random mixin transactions from spent utxos, unknown utxos, and unspent utxos
        rem_utxo_indices = list(set(range(0, len(self.MyUTXOPool))) - set(UTXOindices))
            
        mixin_tx = []
        while (len(mixin_tx) != mixin_count):
            mixin_tx = mixin_tx + [getRandom() % (len(self.MixinTxPool) + len(rem_utxo_indices))]
            mixin_tx = list(set(mixin_tx))

        for i in range(0, mixin_count):
            index = mixin_tx[i]

            if (index < len(self.MixinTxPool)):
                mixin_tx[i] = self.MixinTxPool[mixin_tx[i]]
            else:
                index = index - len(self.MixinTxPool)
                mixin_tx[i] = self.MyUTXOPool[rem_utxo_indices[index]]

        #Generate output transaction
        out_value = 0
        out_bf = getRandom()
        for i in range(0, len(in_values)):
            out_value = out_value + in_values[i]

        if ((pubViewKey == None) or (pubSpendKey == None)):
            pubViewKey = self.MyPublicViewKey
            pubSpendKey = self.MyPublicSpendKey

        (out_rp_val, out_rp_pow10, out_rp_rem, out_rp_bits) = PCRangeProof.GenerateParameters(out_value, 4)
        out_rp = PCRangeProof.Generate(out_rp_val, out_rp_pow10, out_rp_rem, 3, out_bf)
        out_tx = StealthTransaction.Generate_GenRandom(pubViewKey, pubSpendKey, out_value, out_bf)
        sig = RingCT.Sign(in_xk, in_values, in_bfs, mixin_tx, out_tx, out_value, out_bf)
        self.MyPendingUTXOPool = self.MyPendingUTXOPool + [out_tx]

        #Print Information about Transaction
        print("total output value: " + str(out_value))

        #Print PC Range Proof Data
        print("============================================")
        print("PC Range Proof Data")
        print("============================================")
        out_rp.Print_MEW()

        #Print Send Data
        print("============================================")
        print("Send Tx Data")
        print("============================================")
        sig.Print_MEW()
        

    def PrintStealthAddress(self):
        print("Public View Key:  " + print_point(CompressPoint(self.MyPublicViewKey)))
        print("Public Spend Key: " + print_point(CompressPoint(self.MyPublicSpendKey)))

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

    def ExportStealthAddress(self):
        print("StealthAddressExport = [" + hex(self.MyPrivateViewKey) + ", " + hex(self.MyPrivateSpendKey) + "]")

    def ExportUTXOPool(self):
        print("UTXOPoolExport =\n[", end="")
        for i in range(0, len(self.MyUTXOPool)):
            #[pub_key, dhe_point, c_value, encrypted message, iv]
            print("[" + hex(CompressPoint(self.MyUTXOPool[i].pub_key)) + ",")
            print(" " + hex(CompressPoint(self.MyUTXOPool[i].dhe_point)) + ",")
            print(" " + hex(CompressPoint(self.MyUTXOPool[i].c_value)) + ",")
            print(" " + hex(bytes_to_int(self.MyUTXOPool[i].pc_encrypted_data.message)) + ",")
            print(" " + hex(bytes_to_int(self.MyUTXOPool[i].pc_encrypted_data.iv)) + "]", end= "")

            if (i < (len(self.MyUTXOPool)-1)):
                print(",")
            else:
                print("]")
        print()

    def ExportMixinPool(self):
        print("MixinPoolExport =\n[", end="")
        for i in range(0, len(self.MixinTxPool)):
            #[pub_key, dhe_point, c_value, encrypted message, iv]
            print("[" + hex(CompressPoint(self.MixinTxPool[i].pub_key)) + ",")
            print(" " + hex(CompressPoint(self.MixinTxPool[i].dhe_point)) + ",")
            print(" " + hex(CompressPoint(self.MixinTxPool[i].c_value)) + ",")
            print(" " + hex(bytes_to_int(self.MixinTxPool[i].pc_encrypted_data.message)) + ",")
            print(" " + hex(bytes_to_int(self.MixinTxPool[i].pc_encrypted_data.iv)) + "]", end= "")

            if (i < (len(self.MixinTxPool)-1)):
                print(",")
            else:
                print("]")
        print()

#Imports
from RingCTImports import *

def PrintTxExportAsDeposit(transaction_pool, stealth_addr=None):
    print("Deposit Transactions:")
    #pub_keys
    print("Pub Keys:")
    #print("[", end = "")
    for i in range (0, len(transaction_pool)):
        print(hex(transaction_pool[i][0]), end = "")
        if (i < (len(transaction_pool)-1)):
            print(",")
        else:
            print()

    #dhe_points
    print("DHE Points:")
    #print("[", end = "")
    for i in range (0, len(transaction_pool)):
        print(hex(transaction_pool[i][1]), end = "")
        if (i < (len(transaction_pool)-1)):
            print(",")
        else:
            print()

    #values
    if (stealth_addr != None):
        print("Values:")
        #print("[", end = "")
        for i in range (0, len(transaction_pool)):
            stealth_tx = StealthTransaction(ExpandPoint(transaction_pool[i][0]), #pub_key compressed
                                            ExpandPoint(transaction_pool[i][1]), #dhe_point compressed
                                            ExpandPoint(transaction_pool[i][2]), #c_value compressed
                                            PCAESMessage(int_to_bytes64(transaction_pool[i][3]),  #pc_encrypted_data.message
                                                         int_to_bytes16(transaction_pool[i][4]))) #pc_encrypted_data.iv

            data = stealth_tx.DecryptData(stealth_addr[1])
            print(int(data[0]), end = "")
            
            if (i < (len(transaction_pool)-1)):
                print(",")
            else:
                print()
    else:
        print("C Values:")
        #print("[", end = "")
        for i in range (0, len(transaction_pool)):
            print(hex(transaction_pool[i][2]), end = "")
            
            if (i < (len(transaction_pool)-1)):
                print(",")
            else:
                print()

    print()

def RingCTTokenTestImport(stealth_addr, transaction_pool):
    rct = RingCTToken()
    rct.debugPrintingEnabled = False
    
    print("Setting Stealth Address...")
    rct.SetStealthAddress(stealth_addr[0], stealth_addr[1])

    print("Importing " + str(len(transaction_pool)) + " transactions...")
    for i in range(0, len(transaction_pool)):
        stealth_tx = StealthTransaction(ExpandPoint(transaction_pool[i][0]), #pub_key compressed
                                        ExpandPoint(transaction_pool[i][1]), #dhe_point compressed
                                        ExpandPoint(transaction_pool[i][2]), #c_value compressed
                                        PCAESMessage(int_to_bytes64(transaction_pool[i][3]),  #pc_encrypted_data.message
                                                     int_to_bytes16(transaction_pool[i][4]))) #pc_encrypted_data.iv
        rct.AddTx(stealth_tx)

    print("..." + str(len(rct.MyUTXOPool)) + " UTXOs and " + str(len(rct.MixinTxPool)) + " Mixin Transactions imported")
    
    return rct

def RingCTTokenTest(total_value=(10**17), input_count = 3, mixin_count = 3, output_count = 2):
    rct = RingCTToken()
    rct.debugPrintingEnabled = False
    
    #print("Generating Initial Stealth Address...")
    #rct.GenerateNewStealthAddress()

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

    rct.ExportStealthAddress()
    rct.ExportUTXOPool()
    rct.ExportMixinPool()

    return rct

#rct = RingCTTokenTest()
rct = RingCTTokenTestImport(StealthAddressExport, UTXOPoolExport + MixinPoolExport)


