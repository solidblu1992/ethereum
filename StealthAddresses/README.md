# Bare-bones Stealth Addresses for Ethereum
## Basic Usage
See stealth_generate.py, stealth_send.py, and stealth_receive.py.

## Goerli Stealth Tx Registry Contract
The stealth tx registry contract, along with abi may be found at [0x1FB33bF1caac9905389Ec1fccc4BFc6266A01db6](https://goerli.etherscan.io/address/0x1FB33bF1caac9905389Ec1fccc4BFc6266A01db6)

## Stealth Address
### Format
Each stealth address is 65 bytes long and is comprised of three components: a sign byte and the x-coordinates of the public scan key and public spend key.  The sign byte gives information about the sign of each compressed public key:

| Sign Byte | Public Scan Key Sign | Public Spend Key Sign |
| :-------: | :------------------: | :-------------------: |
|       0x1 |                  0x2 |                   0x2 |
|       0x2 |                  0x3 |                   0x2 |
|       0x4 |                  0x2 |                   0x3 |
|       0x7 |                  0x3 |                   0x3 |

### Example

```python
pub_scan_key    = 0x2675ac9304b7cfe986d286ebb910ba217f59ed5bb36deb2fa643c6b7847252d63
pub_spend_key   = 0x28b3b63ae513fcb9fc28a01e9d024cbe4a1fa4571bf577d28c29e32d4bd9ebbac
stealth address = 0x1675ac9304b7cfe986d286ebb910ba217f59ed5bb36deb2fa643c6b7847252d638b3b63ae513fcb9fc28a01e9d024cbe4a1fa4571bf577d28c29e32d4bd9ebbac
```
