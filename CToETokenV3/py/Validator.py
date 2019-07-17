from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from getpass import getpass
import json
from tinydb import TinyDB, Query, where
from tinydb.operations import delete
from OneBitRangeProof import VerifyRangeProofs, GetMerkelProof, ExtractProof

CT_Validator_Options = {
        #Percentage of proofs to verify 0-100
        'pct_proof_check': 100,

        #Finalize all proofs, even if they are not our own (No benefit to me)
        'finalize_all_proofs': True,

        #Proof Data Source
        'pull_proof_data_from_event': False
    }
    
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
with open("RangeProofRegistryABI.json") as f:
    contract_json = json.load(f)

registry_contract = w3.eth.contract(address=contract_json["address"], abi=contract_json["abi"])

#Open database
db = TinyDB("validator_db.json")
query = db.table("sync").search(Query().blockNumber)
blockNumber = 1
if len(query) == 0:
    db.table("sync").insert({ "blockNumber": 1 })
else:
    blockNumber = max([0, query[0]['blockNumber']-40000])

print("Start block number: " + str(blockNumber))

#Setup filters
rps_filter = registry_contract.events.RangeProofsSubmitted.createFilter(fromBlock=blockNumber)
rpa_filter = registry_contract.events.RangeProofsAccepted.createFilter(fromBlock=blockNumber)
rpr_filter = registry_contract.events.RangeProofsRejected.createFilter(fromBlock=blockNumber)

#Parse rejected and accepted proofs
accepted_proofs = dict()
rejected_proofs = dict()

#Check range proofs
print("Polling contract for new events...")
rpa_events = rpa_filter.get_all_entries()
rpr_events = rpr_filter.get_all_entries()
rps_events = rps_filter.get_all_entries()

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

#Clean DB
results = db.table('pending_proofs').search(Query().proof_hash != '')
print()
print("Cleaning DB")
for result in results:
    proof_hash = result['proof_hash']
    return_data = registry_contract.functions.GetRangeProofInfo(bytes.fromhex(proof_hash)).call()
    if return_data[0] == "0x0000000000000000000000000000000000000000":
        #Drop from db
        print("Dropping proof with hash: " + proof_hash)
        db.table('pending_proofs').remove(Query().proof_hash == proof_hash)


while(True):
    for event in rpa_events:
        accepted_proofs[event['args']['proof_hash']] = True
        
    for event in rpr_events:
        rejected_proofs[event['args']['proof_hash']] = True

    if len(rps_events) > 0:
        print()
        print(str(len(rps_events)) + " new range proofs submitted")
        pct_proof_check = 100
        print("Checking " + str(CT_Validator_Options['pct_proof_check']) + "% for validity")

    for i in range(0, len(rps_events)):
        print("Proof " + str(i) + ": ", end="")
        
        #Check to see if the proof has already been accepted or rejected
        proof_hash = rps_events[i]['args']['proof_hash']
        query = db.table("pending_proofs").search(Query().proof_hash == proof_hash.hex())
        if accepted_proofs.get(proof_hash) == True:
            print ("Already Accepted")

            #Remove from DB
            db.table('pending_proofs').remove(Query().proof_hash == proof_hash)

        elif rejected_proofs.get(proof_hash) == True:
            print ("Already Rejected")

            #Remove from DB
            db.table('pending_proofs').remove(Query().proof_hash == proof_hash)

        elif len(query) > 0:
            #We've seen this proof before, do nothing
            print ("Pending, Already Checked")
            
            #Are we finalizing proofs that are not ours?
            if query[0]['valid']:
                if CT_Validator_Options['finalize_all_proofs'] or rps_events[i]['args']['submitter'] == account:
                    if rps_events[i]['args']['expiration_block'] <= w3.eth.blockNumber:
                        print("Finalizing proof...", end="")
                        registry_contract.functions.FinalizeRangeProofs(rps_events[i]['args']['proof_hash']).transact({'from': account})
                        print("DONE!")

                        #Remove from db
                        db.table('pending_proofs').update(delete('proof_hash'), where('proof_hash') == proof_hash.hex())

        #Verify proof
        else:
            proof = get_proof_from_event(rps_events[i])
            
            #Get proof size, for fun
            proof_size = (len(proof)-20) // 160
            print(str(proof_size) + " bits, ", end="")
            
            index = VerifyRangeProofs(proof, CT_Validator_Options['pct_proof_check'])
            if (index == -1):
                #Proof is probably good
                if CT_Validator_Options['pct_proof_check'] == 100:
                    print("PASSED")
                else:
                    print("PROBABLY PASSED")

                #Are we finalizing proofs that are not ours?
                if CT_Validator_Options['finalize_all_proofs'] or rps_events[i]['args']['submitter'] == account:
                    if rps_events[i]['args']['expiration_block'] <= w3.eth.blockNumber:
                        print("Finalizing proof...", end="")
                        registry_contract.functions.FinalizeRangeProofs(rps_events[i]['args']['proof_hash']).transact({'from': account})
                        print("DONE!")

                #Update DB
                db.table("pending_proofs").insert({ "proof_hash": proof_hash.hex(), "valid": True })
            else:
                #Challenge Proof
                print("FAILED")
                mp = GetMerkelProof(proof, index)
                fraudulent_proof = ExtractProof(proof, index)
                registry_contract.functions.ChallengeRangeProofs(fraudulent_proof, mp[1], mp[2]).transact({'from': account})

                #Update DB
                db.table("pending_proofs").insert({ "proof_hash": proof_hash.hex(), "valid": False })

    #Update sync database
    db.table("sync").update({ "blockNumber": blockNumber })

    #Get new events
    blockNumber = w3.eth.blockNumber
    rpa_events = rpa_filter.get_new_entries()
    rpr_events = rpr_filter.get_new_entries()
    rps_events = rps_filter.get_new_entries()
