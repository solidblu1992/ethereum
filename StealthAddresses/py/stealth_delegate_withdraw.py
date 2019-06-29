from sha3 import keccak_256
from getpass import getpass
from py_ecc import secp256k1
from eth_keyfile import load_keyfile, decode_keyfile_json
directory = "C:/Users/alegr/OneDrive/Documents/GitHub/ethereum/StealthAddresses/py/"
keystore_file = "Keystore--975fbcbaeb9b3852b096ec0242aa2d96400406af.json"
address = 0x975fbcbaeb9b3852b096ec0242aa2d96400406af
tokens = 70000000000000000
nonce = 1

tx_data = address.to_bytes(20, 'big')
tx_data += tokens.to_bytes(32, 'big')
tx_data += nonce.to_bytes(32, 'big')

message = keccak_256(tx_data).digest()

#Import Scan and Spend Key
password = getpass()
priv_key = decode_keyfile_json(load_keyfile(directory + keystore_file), bytes(password, 'utf'))

#Create Signature
from py_ecc import secp256k1

sig = secp256k1.ecdsa_raw_sign(message, priv_key)

print("data:")
print(hex(int.from_bytes(tx_data, 'big')))
print()
print("sig:")
print(sig[0])
print(hex(sig[1]))
print(hex(sig[2]))
