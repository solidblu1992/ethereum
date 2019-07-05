import json
from getpass import getpass
from py_ecc import secp256k1
from eth_keyfile import create_keyfile_json
from stealth_util import *
from random import SystemRandom
import os.path

#Generate a new spend and scan key pair and calculate their stealth address
#Store resulting stealth address along with the two key pairs in stealth_address.json
def stealth_generate(filename):
    #Check to see if file is valid and does not already exist
    if type(filename) != str or len(filename) == 0:
        print("Stealth Address Generation Failed!")
        print("Please enter valid filename!")
        return
        
    if os.path.exists(filename):
        print("Stealth Address Generation Failed!")
        print("File \"" + filename + "\" already exists!")
        return
    
    #Get password for new keypair
    password = getpass()
    
    #Generate private keys
    print("Generating stealth address key pair...", end="")
    rng = SystemRandom()
    
    scan_key = (rng.getrandbits(256) % secp256k1.N).to_bytes(32, "big")
    pub_scan_key = secp256k1.privtopub(scan_key)
    js_scan = create_keyfile_json(scan_key, bytes(password, 'utf'))
    del scan_key
    
    spend_key = (rng.getrandbits(256) % secp256k1.N).to_bytes(32, "big")
    pub_spend_key = secp256k1.privtopub(spend_key)
    js_spend = create_keyfile_json(spend_key, bytes(password, 'utf'))
    del spend_key
    del password

    #Calculate Stealth Address and write to file with key pairs
    stealth_address = int.from_bytes(GetStealthAddressFromKeys(pub_scan_key, pub_spend_key), 'big')
    print("DONE!")
    print("New Stealth Address: " + hex(stealth_address))

    print("Writing keystore file \"" + filename + "\"...", end="")
    
    with open(filename, mode='w') as file:
        js = "{\"stealth_address\":\"" + hex(stealth_address) + "\","
        js += "\"scan_key\":"
        file.write(js)
        
        json.dump(js_scan, file)
        
        js = ",\"spend_key\":"
        file.write(js)

        json.dump(js_spend, file)
        
        js = "}"
        file.write(js)

    print("Done!")
