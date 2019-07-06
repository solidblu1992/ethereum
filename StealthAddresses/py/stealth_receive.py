import json
from getpass import getpass
from py_ecc import secp256k1
from eth_keyfile import load_keyfile, decode_keyfile_json, create_keyfile_json
from stealth_util import *

#Import stealth scan and spend keys from scan_key.json and spend_key.json (using same password)
#Read candidate stealth tx's from input.json.
#If they belong to this stealth address, create keystore files for these tx's with same password
def stealth_receive(directory):
    #Import Scan and Spend Key
    wallet = GetKeysFromFile(directory + 'wallet.json')
    scan_key = wallet['scan_key']
    spend_key = wallet['spend_key']
    del wallet

    pub_scan_key = secp256k1.privtopub(scan_key)
    pub_spend_key = secp256k1.privtopub(spend_key)
    stealth_address = GetStealthAddressFromKeys(pub_scan_key, pub_spend_key)

    print("Stealth Address Imported: " + hex(int.from_bytes(stealth_address, 'big')))

    #Import Inputs File
    input_json = json.load(open(directory + "input.json"))
    print()
    print("Input Count: " + str(len(input_json["keys"])))

    for key in input_json["keys"]:
        #Extract and pad address and key fields
        addr = key["address"][2:]
        while len(addr) < 40:
            addr = "0" + addr
        addr = bytes.fromhex(addr)
        
        key = key["key"][2:]
        while len(key) < 66:
            key = "0" + key
        key = bytes.fromhex(key)

        print("Testing " + hex(int.from_bytes(addr, 'big')) + " ... ", end="")
        point = ExpandPoint(key)

        ss = GetSharedSecret(point, scan_key)
        addr_exp = GetAddrFromSharedSecret(ss, pub_spend_key)

        if addr == addr_exp:
            print("HIT!")
            priv_key = GetPrivKeyFromSharedSecret(ss, spend_key)
            filename = "Keystore--" + hex(int.from_bytes(addr_exp, 'big'))[2:] + ".json"
            
            print("Creating " + filename + " ... ", end="")
            filename = directory + filename
            
            with open(filename, mode='w') as file:
                js = create_keyfile_json(int.to_bytes(priv_key, 32, 'big'), bytes(password, 'utf'))
                json.dump(js, file)

            print("COMPLETE!")
        else:
            print("MISS!")

    del scan_key
    del spend_key

if __name__ == "__main__":
    directory = "C:/"
    stealth_receive(directory)
