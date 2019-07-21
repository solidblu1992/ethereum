from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from getpass import getpass
import json
from tinydb import TinyDB, Query, where
from tinydb.operations import delete
from OneBitRangeProof import GenerateOneBitRangeProofs, MerkelizeRangeProofs, ExtractCommitmentsFromProof, MerkelizeCommitments
from time import time, sleep

def tx_wait_timeout(w3, tx_hash, timeout=30, poll_interval=1):
    start_time = time()

    tx = w3.eth.getTransaction(tx_hash)
    while(tx['blockNumber']==None):
        assert(time()-start_time < timeout)
        
        sleep(poll_interval)
        tx = w3.eth.getTransaction(tx_hash)
        print('.', end="", flush=True)

CT_Client_Options = {}
    
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

#Load contract addresses and abis
with open("IERC20ABI.json") as f:
    contract_json = json.load(f)

erc20_contract = w3.eth.contract(address=contract_json["address"], abi=contract_json["abi"])

with open("RangeProofRegistryABI.json") as f:
    contract_json = json.load(f)

registry_contract = w3.eth.contract(address=contract_json["address"], abi=contract_json["abi"])

#Open database
db = TinyDB("client_db.json")
query = db.table("sync").search(Query().blockNumber)
blockNumber = 1
if len(query) == 0:
    db.table("sync").insert({ "blockNumber": 1 })
else:
    blockNumber = max([0, query[0]['blockNumber']-40000])

print("Start block number: " + str(blockNumber))

query = db.table("commitments").search(Query().value)
if len(query) == 0:
    #Create commitments
    print("Generating new commitment set...", end="")
    private_commitments, proofs = GenerateOneBitRangeProofs(count=64, asset_address=0x0000000000000000000000000000000000000000)
    print("DONE!")

    #Check ERC20 allowance
    allowance = erc20_contract.functions.allowance(account, registry_contract.address).call()

    #Add more coins if necessary
    if allowance < 32*10**18:
        print("Not enough ERC20 coins in allowance, allowing more...", end="")
        tx = erc20_contract.functions.approve(registry_contract.address, 100*10**18).transact({'from': account})
        tx_wait_timeout(w3, tx)
        print("DONE!")

    #Submit proof
    print("Submitting proof...", end="")
    tx = registry_contract.functions.SubmitRangeProofs(proofs).transact({'from': account})
    tx_wait_timeout(w3, tx)
    print("DONE!")
    
    #Add proof and commitments to db
    print("Saving to DB...", end="")
    proof_hash = MerkelizeRangeProofs(proofs)[2:]
    db.table("my_proofs").insert({
            "proof_hash": proof_hash,
            "proof_data": proofs.hex()
        })

    commitment_data = ExtractCommitmentsFromProof(proofs)
    commitment_hash = MerkelizeCommitments(commitment_data)[2:]
    db.table("commitments").insert({
            "set_hash": commitment_hash,
            "proof_hash": proof_hash,
            "data": commitment_data.hex(),
            "private": private_commitments
        })
    print("DONE!")

#Setup filters
rpa_filter = registry_contract.events.RangeProofsAccepted.createFilter(fromBlock=blockNumber)
rpr_filter = registry_contract.events.RangeProofsRejected.createFilter(fromBlock=blockNumber)

#Parse rejected and accepted proofs
accepted_proofs = dict()
rejected_proofs = dict()

#Check range proofs
print("Polling contract for new events...")
rpa_events = rpa_filter.get_all_entries()
rpr_events = rpr_filter.get_all_entries()

def get_proof_from_event(event):
    if CT_Validator_Options['pull_proof_data_from_event']:
        #Pull data from actual event
        return event['args']['proof_data']
    else:
        #Else pull from transaction
        tx_hash = event.transactionHash
        tx = w3.eth.getTransaction(tx_hash)
        input_data = bytes.fromhex(tx['input'][2:])

        junk = input_data[:4]
        junk = input_data[4:36]
        proof_size = int.from_bytes(input_data[36:68], 'big')
        return input_data[68:68+proof_size]

while(True):
    for event in rpa_events:
        accepted_proofs[event['args']['proof_hash']] = True
        
    for event in rpr_events:
        rejected_proofs[event['args']['proof_hash']] = True

    #Update sync database
    db.table("sync").update({ "blockNumber": blockNumber })

    #Get new events
    blockNumber = w3.eth.blockNumber
    rpa_events = rpa_filter.get_new_entries()
    rpr_events = rpr_filter.get_new_entries()
