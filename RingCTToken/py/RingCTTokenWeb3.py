#Imports
from RingCTTokenTest import *
import json
from web3 import Web3, HTTPProvider
from web3.contract import Contract

from web3 import Web3, HTTPProvider, TestRPCProvider
from web3.middleware import geth_poa_middleware

##############
# Fetch Web3 #
##############
web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
web3.middleware_stack.inject(geth_poa_middleware, layer=0)

#############################
# Get RingCT Token Contract #
#############################
contract_addr = "0x94820259A6C590615381b25057fFfB3Ff086BAF0";
contract_abi = open("RingCTToken.json").read()
contract = web3.eth.contract(address=contract_addr,
                             abi=contract_abi,
                             ContractFactoryClass=Contract)

#Set Ether Address and Stealth Address
EtherAddress = 0x975C076706FcfaCc721EC31b2f9fC2e41B8c596f
#StealthAddressExport = [0x95169576339c26b437843b4a8a14bccbde711e7223691c8f435069d4c6bd2d8, 0xe1442d1972fb38a3f87a8432a13e086b94386336c41fb999a5f2028dae9dffa]
rct = RingCTToken()
#rct.SetStealthAddress(StealthAddressExport[0], StealthAddressExport[1])
rct.GenerateNewStealthAddress()

#######################
# Setup Event Filters #
#######################
fromBlock = 0
PCRangeProvenEF = contract.events.PCRangeProvenEvent.createFilter(fromBlock=fromBlock)
SendEF = contract.events.SendEvent.createFilter(fromBlock=fromBlock)
StealthAddressPublishedEF = contract.events.StealthAddressPublishedEvent.createFilter(fromBlock=fromBlock)
DepositEF = contract.events.DepositEvent.createFilter(fromBlock=fromBlock)
WithdrawalEF = contract.events.WithdrawalEvent.createFilter(fromBlock=fromBlock)

#Processs positive commitments
if (True):
    print()
    entries = PCRangeProvenEF.get_all_entries()
    for i in range(0, len(entries)):
        print("Commitment[" + str(i) + "]: ", end="")
        print(bytes32_to_str(entries[i].args.get('_commitment')) + " proven positive, (", end="")
        print(str(entries[i].args.get('_min') / 10**18) + ", ", end="")
        print(str(entries[i].args.get('_resolution') / 10**18) + ", ..., ", end="")
        print(str(entries[i].args.get('_max') / 10**18) + " ETH)")

#Process Withdrawal Events
if (True):
    print()
    entries = WithdrawalEF.get_all_entries()
    for i in range(0, len(entries)):
        addr = int(entries[i].args.get('_to'), 16)
        value = entries[i].args.get('_value')
        print("Withdrawal[" + str(i) + "]: " + bytes20_to_str(addr) + " received " + str(value / 10**18) + " ETH (" + str(value) + " wei)")

#Process Deposit Events
entries = DepositEF.get_all_entries()
for i in range(0, len(entries)):
    pub_key = entries[i].args.get('_pub_key')
    dhe_point = entries[i].args.get('_dhe_point')
    value = entries[i].args.get('_value')

    tx = StealthTransaction(ExpandPoint(pub_key), ExpandPoint(dhe_point), value)
    (owned, duplicate) = rct.AddTx(tx)

    if (not duplicate):
        if (owned):
            priv_key = tx.GetPrivKey(rct.MyPrivateViewKey, rct.MyPrivateSpendKey)
            spent = contract.functions.key_images(CompressPoint(KeyImage(priv_key))).call()

            if (spent):
                rct.MarkUTXOAsSpent(len(rct.MyUTXOPool)-1)
        
        if (True):
            print()
            print("DepositEvent[" + str(i) + "]:")
            print("dest_pub_key: " + bytes32_to_str(pub_key))
            print("dhe_point:    " + bytes32_to_str(dhe_point))
            print("value:        " + str(value / 10**18) + " ETH (" + str(value) + " wei)")
            print("owned:        " + str(owned))

            if (owned):
                print("[priv_key:    " + bytes32_to_str(priv_key) + "]")
                print("[spent:       " + str(spent) + "]")
                
            print()
        

#Process Send Events
entries = SendEF.get_all_entries()
for i in range(0, len(entries)):
    pub_key = entries[i].args.get('_pub_key')
    dhe_point = entries[i].args.get('_dhe_point')
    value = entries[i].args.get('_value')
    encrypted_data_raw = entries[i].args.get('_encrypted_data')
    encrypted_data = PCAESMessage(int_to_bytes32(encrypted_data_raw[0]) + int_to_bytes32(encrypted_data_raw[1]), int_to_bytes16(encrypted_data_raw[2]))

    tx = StealthTransaction(ExpandPoint(pub_key), ExpandPoint(dhe_point), ExpandPoint(value), encrypted_data)
    (owned, duplicate) = rct.AddTx(tx)

    if (not duplicate):
        if (owned):
            priv_key = tx.GetPrivKey(rct.MyPrivateViewKey, rct.MyPrivateSpendKey)
            (value, bf) = tx.DecryptData(rct.MyPrivateSpendKey)
            print()
            spent = contract.functions.key_images(CompressPoint(KeyImage(priv_key))).call()

            if (spent):
                rct.MarkUTXOAsSpent(len(rct.MyUTXOPool)-1)
                
        if (True):
            print()
            print("SendEvent[" + str(i) + "]:")
            print("dest_pub_key:   " + bytes32_to_str(pub_key))
            print("dhe_point:      " + bytes32_to_str(dhe_point))
            print("c_value:        " + bytes32_to_str(value))
            print("encrypted_msg:  " + bytes32_to_str(bytes_to_int(encrypted_data.message[:32])) + bytes32_to_str(bytes_to_int(encrypted_data.message[32:]))[:2])
            print("encrypted_iv:   " + bytes16_to_str(bytes_to_int(encrypted_data.iv)))

            if (owned):
                print("[priv_key:      " + bytes32_to_str(priv_key) + "]")
                print("[bf:            " + bytes32_to_str(bf) + "]")
                print("[value:         " + str(value / 10**18) + " ETH (" + str(value) + " wei)]")
                print("[spent:         " + str(spent) + "]")
            print()


#Generate Transactions
#Spend
if (False):
    input_count = 2
    mixin_count = 3
    output_count = 2
    tx0 = rct.SendTx(list(range(0,input_count)), mixin_count, output_count)
    rct.MarkUTXOAsSpent(list(range(0,input_count)))
    rct.MintPendingUTXOs(list(range(0,output_count)))

#Withdraw
if (False):
    input_count = 2
    mixin_count = 3
    output_count = 2
    tx0 = rct.WithdrawTx(EtherAddress, 10**15, [0], mixin_count, None)
    rct.MarkUTXOAsSpent([0])
    #rct.MintPendingUTXOs(list(range(0,output_count)))
