import json
from getpass import getpass
from py_ecc import secp256k1
from eth_keyfile import load_keyfile, decode_keyfile_json, create_keyfile_json
from stealth_util import *
from random import SystemRandom

#Generate a new spend and scan key pair, save as spend_key.json and scan_key.json
#Store resulting stealth address in stealth_address.json
def stealth_generate(directory):
    #Get password for new keypair
    password = getpass()
    
    #Generate private keys
    print("Generating stealth address key pair...", end="")
    rng = SystemRandom()
    scan_key = (rng.getrandbits(256) % secp256k1.N).to_bytes(32, "big")
    spend_key = (rng.getrandbits(256) % secp256k1.N).to_bytes(32, "big")

    pub_scan_key = secp256k1.privtopub(scan_key)
    pub_spend_key = secp256k1.privtopub(spend_key)
    stealth_address = int.from_bytes(GetStealthAddressFromKeys(pub_scan_key, pub_spend_key), 'big')
    print("DONE!")
    print("New Stealth Address: " + hex(stealth_address))

    print("Writing keystore files...", end="")
    filename = directory + "/scan_key.json"    
    with open(filename, mode='w') as file:
        js = create_keyfile_json(scan_key, bytes(password, 'utf'))
        json.dump(js, file)

    filename = directory + "/spend_key.json"
    with open(filename, mode='w') as file:
        js = create_keyfile_json(spend_key, bytes(password, 'utf'))
        json.dump(js, file)
    print("DONE!")

    filename = directory + "/stealth_address.json"
    with open(filename, mode='w') as file:
        js = "{\n"
        js += "\t\"stealth_address\":\"" + hex(stealth_address) + "\"\n"
        js += "}"
        file.write(js)

if __name__ == "__main__":
    directory = "C:/"
    stealth_generate(directory)
