from web3 import Web3, HTTPProvider, WebsocketProvider
import json

provider = HTTPProvider("http://localhost:8545")
w3 = Web3(provider)
assert w3.isConnected()

contract_addr = "0xb5267Fbbce2D254017F3c9c61cE0673526aE22cD"

with open("../contracts/StealthTxTokenABI.json") as f:
    info_json = json.load(f)
    
abi = info_json["result"]
contract = w3.eth.contract(address=contract_addr, abi=abi)
