from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from getpass import getpass
import json
from OneBitRangeProof import GenerateOneBitRangeProofs
import time

def SendRandomProof(account, registry_contract):
    private_commitments, proofs = GenerateOneBitRangeProofs(asset_address=0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359, count=32)

    registry_contract.SubmitRangeProofs(proofs).transact({'from': account})

#Connect to local node
w3 = Web3(HTTPProvider("http://127.0.0.1:8545"))
assert(w3.isConnected())
w3.middleware_stack.inject(geth_poa_middleware, layer=0)

#Unlock account
accounts = w3.personal.listAccounts
assert(len(accounts) > 0)
account = accounts[0]
pwd = getpass()
assert(w3.personal.unlockAccount(account, pwd))
del pwd

#Load contract address and abi
with open("IERC20ABI.json") as f:
    contract_json = json.load(f)

erc20_contract = w3.eth.contract(address=contract_json["address"], abi=contract_json["abi"])


with open("RangeProofRegistryABI.json") as f:
    contract_json = json.load(f)

registry_contract = w3.eth.contract(address=contract_json["address"], abi=contract_json["abi"])

#Loop
while True:
    #Check ERC20 allowance
    allowance = erc20_contract.functions.allowance(account, registry_contract.address).call()

    #Add more coins if necessary
    if allowance < 32*10**18:
        erc20_contract.functions.approve(registry_contract.address, 100*10**18).transact({'from': account})
    
    #Send random proof
    print("Generating proofs...", end="")
    private_commitments, proofs = GenerateOneBitRangeProofs(asset_address=0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359, count=32)
    print("DONE!")
    
    print("Sending proofs...", end="")
    registry_contract.functions.SubmitRangeProofs(proofs).transact({'from': account})
    print("DONE!")

    time.sleep(30)

    
