from stealth_util import *

#For a given stealth address, create new stealth transaction addresses
#Each tx has a key (compressed ephemeral point) and a Ethereum address
#Send ether to the address and then log the point and address in the registry
def stealth_send(stealth_address, count=5):
    if type(stealth_address) == int:
        stealth_address = int.to_bytes(stealth_address, 65, 'big')
        
    pub_scan_key, pub_spend_key = GetKeysFromStealthAddress(stealth_address)

    out = "{\n"
    out += "\t" + "\"keys\":[\n"

    tabs = 2
    for i in range(0, count):
        R, addr = CreateStealthTx(pub_scan_key, pub_spend_key)
        out += "\t"*tabs + "{\n"

        tabs += 1
        out += "\t"*tabs + "\"key\":\"" + R + "\",\n"
        out += "\t"*tabs + "\"address\":\"" + addr + "\"\n"
        tabs -= 1
        
        out += "\t"*tabs + "}"

        if i < (count-1):
            out += ","

        out += "\n"
        
    tabs -= 1
    out += "\t"*tabs + "]\n"
    
    out += "}"

    return out

if __name__ == "__main__":
    wallet = ReadAddressFromFile('wallet.json')
    out = stealth_send(wallet['stealth_address'])

    print("New tx addresses for stealth address:")
    print("0x" + wallet['stealth_address'].hex())
    print(out)
