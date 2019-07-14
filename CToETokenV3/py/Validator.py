from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import json
from getpass import getpass
from OneBitRangeProof import VerifyRangeProofs, GetMerkelProof, ExtractProof

CT_Validator_Options = {
        #Percentage of proofs to verify 0-100
        'pct_proof_check': 100,

        #Finalize all proofs, even if they are not our own (No benefit to me)
        'finalize_all_proofs': True
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
        print("Checking " + str(CT_Validator_Options['pct_proof_check']) + "% for validity")

    for i in range(0, len(rps_events)):
        print("Proof " + str(i) + ": ", end="")
        
        #Check to see if the proof has already been accepted or rejected
        proof_hash = rps_events[i]['args']['proof_hash']
        if accepted_proofs.get(proof_hash) == True:
            print ("Already Accepted")

        elif rejected_proofs.get(proof_hash) == True:
            print ("Already Rejected")

        #Verify proof
        else:
            proof = rps_events[i]['args']['proof_data']
            
            #Get proof size, for fun
            proof_size = (len(proof)-20) // 160
            print(str(proof_size) + " bits, ", end="")
            
            index = VerifyRangeProofs(proof, CT_Validator_Options['pct_proof_check'])
            if (index == -1):
                #Proof is probably good
                print("PASSED")

                #Are we finalizing proofs that are not ours?
                if CT_Validator_Options['finalize_all_proofs'] or rps_events[i]['args']['submitter'] == account:
                    if rps_events[i]['args']['expiration_block'] <= w3.eth.blockNumber:
                        print("Finalizing proof...", end="")
                        registry_contract.functions.FinalizeRangeProofs(rps_events[i]['args']['proof_hash']).transact({'from': account})
                        print("DONE!")
            else:
                #Challenge Proof
                print("FAILED")
                mp = GetMerkelProof(proof, index)
                fraudulent_proof = ExtractProof(proof, index)
                registry_contract.functions.ChallengeRangeProofs(fraudulent_proof, mp[1], mp[2]).transact({'from': account})

    #Get new events
    rpa_events = rpa_filter.get_new_entries()
    rpr_events = rpr_filter.get_new_entries()
    rps_events = rps_filter.get_new_entries()
