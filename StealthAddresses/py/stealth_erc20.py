import os
import json
from tinydb import TinyDB, Query
from web3 import Web3, HTTPProvider, WebsocketProvider
from eth_keyfile import create_keyfile_json
from stealth_util import *

#Connect to Web3
provider = HTTPProvider("http://127.0.0.1:30303")
w3 = Web3(provider)
assert w3.isConnected()

contract_addr = "0xb5267Fbbce2D254017F3c9c61cE0673526aE22cD"

with open("../contracts/StealthTxToken.abi") as f:
    info_json = json.load(f)
    
abi = info_json["abi"]
contract = w3.eth.contract(address=contract_addr, abi=abi)

#Check for previous sync status
fromBlock=1
if os.path.exists("sync.json"):
    with open("sync.json") as f:
        sync_json = json.load(f)

    fromBlock = (sync_json["lastBlock"])
else:
    sync_json = dict()

#Check for previous sync DB
db = TinyDB("db.json")
    
#Check events from contract
block_num = w3.eth.blockNumber
ef_withdraw = contract.events.DepositEvent.createFilter(fromBlock=fromBlock)
ef_transfer = contract.events.TokensSpentEvent.createFilter(fromBlock=fromBlock)

#Import Stealth Wallet
password = None
wallet = ReadKeysFromFile('wallet.json')
entries = ef_withdraw.get_all_entries() + ef_transfer.get_all_entries()
print("Reading contract, " + str(len(entries)) + " entries...")
for event in entries:
    dest_addr = bytes_from_hex_string(event['args']['_dest_addr'], 20)
    R = event['args']['_point_compressed_sign'] + event['args']['_point_compressed_x']
    point = ExpandPoint(R)
    ss = GetSharedSecret(point, wallet['scan_key'])
    addr_test = GetAddrFromSharedSecret(ss, wallet['pub_spend_key'])

    if dest_addr == addr_test:
        #Check to see if it is in the database
        tx = Query()
        results = db.search(tx.address == ("0x" + dest_addr.hex()))
        if len(results) == 0:
            print("HIT!")
            priv_key = GetPrivKeyFromSharedSecret(ss, wallet['spend_key'])

            filename = "Keystore--" + hex(int.from_bytes(addr_test, 'big'))[2:] + ".json"
                
            print("Creating " + filename + " ... ", end="")

            if password==None:
                password = getpass()

            db_entry = dict()
            db_entry['address'] = "0x" + dest_addr.hex()
            db_entry['keystore'] = create_keyfile_json(int.to_bytes(priv_key, 32, 'big'), bytes(password, 'utf'))
            db.insert(db_entry)

            print("COMPLETE!")
        else:
            print("DUPLICATE!")
    else:
        print("MISS!")

sync_json["lastBlock"] = block_num

#Rewrite Sync File
with open("sync.json", "w") as f:
    json.dump(sync_json, f)

#Close DB
db.close()
