from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import json
from getpass import getpass
from OneBitRangeProof import VerifyRangeProofs, GetMerkelProof, ExtractProof

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

#Setup filters
rps_filter = registry_contract.events.RangeProofsSubmitted.createFilter(fromBlock=1)
rpa_filter = registry_contract.events.RangeProofsAccepted.createFilter(fromBlock=1)
rpr_filter = registry_contract.events.RangeProofsRejected.createFilter(fromBlock=1)

#Parse rejected and accepted proofs
accepted_proofs = dict()
rejected_proofs = dict()

#Check range proofs
print("Polling contract for new events...")
rpa_events = rpa_filter.get_all_entries()
rpr_events = rpr_filter.get_all_entries()
rps_events = rps_filter.get_all_entries()

while(True):
    for event in rpa_events:
        accepted_proofs[event['args']['proof_hash']] = True
        
    for event in rpr_events:
        rejected_proofs[event['args']['proof_hash']] = True

    if len(rps_events) > 0:    
        print(str(len(rps_events)) + " new range proofs submitted")
        pct_proof_check = 100
        print("Checking " + str(pct_proof_check) + "% for validity")

    for i in range(0, len(rps_events)):
        #Check to see if the proof has already been accepted or rejected
        proof_hash = rps_events[i]['args']['proof_hash']
        if accepted_proofs.get(proof_hash) == True:
            print ("Proof " + str(i) + ": Already Accepted")

        elif rejected_proofs.get(proof_hash) == True:
            print ("Proof " + str(i) + ": Already Rejected")

        #Verify proof
        else:
            proof = rps_events[i]['args']['proof_data']
            index = VerifyRangeProofs(proof, pct_proof_check)
            if (index == -1):
                #Proof is probably good
                print("Proof " + str(i) + ": PASSED")
            else:
                #Challenge Proof
                print("Proof " + str(i) + ": FAILED")
                mp = GetMerkelProof(proof, index)
                fraudulent_proof = ExtractProof(proof, index)
                registry_contract.functions.ChallengeRangeProofs(fraudulent_proof, mp[1], mp[2]).transact({'from': account})

    #Get new events
    rpa_events = rpa_filter.get_new_entries()
    rpr_events = rpr_filter.get_new_entries()
    rps_events = rps_filter.get_new_entries()
