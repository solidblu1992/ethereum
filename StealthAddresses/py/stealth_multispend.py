from stealth_util import *
import json

sig = None
if __name__ == "__main__":
    from os import getcwd, listdir
    keystore_files = [x for x in listdir() if (x.find("Keystore") >= 0) ]
    wallets = ReadKeysFromFiles(keystore_files)
    sig = SchnorrMultiSign("Send,0x00000000219ab540356cBB839Cbe05303d7705Fa", wallets["priv_key"])
    assert(SchnorrMultiVerify(sig))

    sig["message"] = str(sig["message"], 'utf')
    sig["message_hash"] = hex(int.from_bytes(sig["message_hash"]))[2:]
    with open("tx.json", mode='w') as file:
        json.dump(sig, file)
        
    
    
