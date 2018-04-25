from RingCTToken import *
from RingCTImports import *

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

def RingCTTokenTest(total_value=(10**16), input_count = 2, mixin_count = 3, output_count = 2):
    rct = RingCTToken()
    rct.debugPrintingEnabled = False
    
    #print("Generating Initial Stealth Address...")
    #rct.GenerateNewStealthAddress()
    rct.SetStealthAddress(StealthAddressExport[0], StealthAddressExport[1])

    print("Generating Input Transactions for TX0...")
    value = [total_value // input_count] * input_count
    value[-1] = value[-1] + (total_value % input_count)
    rct.GenerateUTXOs(value, [0]*input_count)

    print("Generating Mixin Transactions for TX0...")
    #rct.GenerateMixinAddresses(input_count*mixin_count)
    rct.GenerateUTXOs([value[0]]*(input_count*mixin_count), [0]*(input_count*mixin_count))

    #print("Generating Output Transactions for TX0...")
    #value = [total_value // output_count] * output_count
    #value[-1] = value[-1] + (total_value % output_count)
    #rct.GeneratePendingUTXOs(value, getRandom(output_count))

    rct.PrintUTXOPool()
    #rct.PrintMixinPool()
    #rct.PrintPendingUTXOPool()

    rct.debugPrintingEnabled = True

    #Print Deposit Transaction for all UTXO and Mixins
    PrintTxExportAsDeposit(rct.ExportUTXOPool() + rct.ExportMixinPool(), rct.ExportStealthAddress())

    #Create Spend Transaction
    if (output_count == 1):
        output_values = None
    else:
        output_values = output_count
        #output_values = [5, 10, 7, ...]
        
    tx0 = rct.SendTx(list(range(0,input_count)), mixin_count, output_values)
    rct.MarkUTXOAsSpent(list(range(0,input_count)))
    rct.MintPendingUTXOs(list(range(0,input_count)))
    
    #tx1 = rct.WithdrawTx([7], mixin_count, None)
    
    return (rct, tx0)

(rct, tx0) = RingCTTokenTest()
#rct = RingCTTokenTestImport(StealthAddressExport, UTXOPoolExport + MixinPoolExport)
#PrintTxExportAsDeposit(UTXOPoolExport + MixinPoolExport, StealthAddressExport)
#sig = rct.SpendTx([1,5])
