from stealth_util import *

#For a given stealth address, create new stealth transaction addresses
#Each tx has a key (compressed ephemeral point) and a Ethereum address
#Send ether to the address and then log the point and address in the registry
def stealth_send(stealth_address, count=3):
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
    stealth_address = 0x37e6b0cc0965bf5cff98f93cce3b461ef54eeb8e8b5e63156bf87c018a02d8844a6c8cfa3271b794e1018db2a6e6e218c36934c28b33fd18800a8f9a68abd57f5
    out = stealth_send(stealth_address)

    print("New tx addresses for stealth address:")
    print(hex(stealth_address))
    print(out)
