# RingCT Token

RingCTToken (https://rinkeby.etherscan.io/address/0x94820259a6c590615381b25057fffb3ff086baf0)
- Main Contract for RingCT Token.  All functionality is accessed through this contract.
- RingCT aims to allow for a fungible privacy token.  This is accomplished through the combination of linkable ring signatures, output stealth addresses, and confidential transactions.  Ring signatures obfuscate information about the sender, stealth address obfuscate information about the receiver(s), and confidential transactions obfuscate the number of tokens sent.
- RingCT Tokens are backed and redeemable 1:1 for ETH.
- Requires an instance of ECMath, RingCTTxVerify, and BulletproofVerify (accessed through calls)

BulletproofVerify (https://rinkeby.etherscan.io/address/0xa4481352f57715c05b60bad3dc33650b6ecc45d7)

- Contract which handle the verifcation of Bullet Proofs.  This is one of two methods for proving that output pedersen commitments are positive.  Proofs can prove multiple commitments at once, and multiple proofs can be verified at once.  This contract is mainly utilzed through the RingCTToken contract via VerifyPCBulletProof().
- Requires an instance of ECMath (accessed through calls)

RingCTTxVerify (https://rinkeby.etherscan.io/address/0xd342405b028efaedc428e6f46e737db8bf083081)

- Contract which handles the verification of RingCT transactions and Borromean Range Proofs.
- Using Borromean range proofs is a second option for proving that output pedersen commitments are positive.  In some cases this can be more effecient than Bullet Proofs.  This functionality is mainly utilzed through the RingCTToken contract via VerifyPCBorromeanRangeProof().

- The core RingCT transaction signatures are verified by this contract.  There are two types of RingCT transactions: Send() and Withdraw().  Both are accessible through the RingCTToken contract.
- Send() allows input UTXO (unspent transaction outputs) to be combined and sent to new destination stealth addresses.  This only deals in RingCT Tokens.
- Withdraw() allows all the functionality of Send() in addition to allowing a certain portion of tokens to be redeemed for ETH.  This ETH can be redeemed to either a specified receiver or offered up as a bounty for publishing the RingCT transaction.

- Requires an instance of ECMath, and MLSAGVerify (accessed through calls)

MSLAGVerify (https://rinkeby.etherscan.io/address/0x3f667759450149ea7b3826f97ea2460cfeb413de)
- (M)(L)SAG - (Multi-layered) (Linkable) Spontaneous Anonymous Group signature
- Verifies many kinds of ring signatures (linkable / non-linkable, Borromean, non-Borromean).
- Mainly used by RingCTTxVerify.  MSAG signatures are used to verify Borromean Range Proofs, while MLSAG signatures are used to verify RingCT transactions.
- Requires and instance of ECMath.

ECMath (https://rinkeby.etherscan.io/address/0x4552c90db760d5380921e18377a41edcff8d100e)

- Allows access to various Elliptic Curve math functions and access to alt_bn_128 precompiled contracts.
- Used by all other contracts.
