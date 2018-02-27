pragma solidity ^0.4.20;

contract ETHAtomicSwap {
    address public A;
    address public B;
    bytes32 public secretHash;
    uint8 public hashType;
    uint256 public timeoutBlock;
    uint256 public value;
    
    event SecretReveal (
        uint256 secret
    );
    
    //ETHAtomicSwap() contract constructor => functions as initiation for atomic swap
    //_B            =   address of ethereum recipient
    //
    //_secretHash   =   hash of secret that either only A or only B knows.
    //                  A will know it if the Ethereum contract is setup first.
    //                  B will know it if the other blockchain txs are setup first.
    //
    //_hashType     =   0 for keccak256 (32 bytes)
    //                  1 for sha256 (32 bytes)
    //                  2 for ripemd160 (20 bytes)
    //
    //_timeout      =   number of blocks before A can claim funds himself
    function ETHAtomicSwap(address _B, bytes32 _secretHash, uint8 _hashType, uint256 _timeout) public payable {
        require(_B != 0x0);
        require(_hashType < 3);
        require(msg.value > 0);
        
        require(_secretHash != 0x0);
        if (_hashType == 3) { //ripemd-160 is 20bytes not 32
            require(_secretHash <= 0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
        }
        
        //Calculate Timeout Block
        timeoutBlock = (block.number + _timeout);
        require(timeoutBlock >= block.number);
        
        //Store the other input parameters
        A = msg.sender;
        B = _B;
        secretHash = _secretHash;
        hashType = _hashType;
        value = msg.value;
    }
    
    //Redeem(secret) => can be called by B to claim funds if B knows the secret which corrosponds to hashSecret
    function Redeem(uint256 secret) public {
        //Only B can redeem
        require(msg.sender == B);
        
        //Calculate hash
        bytes32 hash;
        if (hashType == 0) { //keccak256
            hash = keccak256(secret);
        }
        else if (hashType == 1) { //sha256
            hash = sha256(secret);
        }
        else {
            hash = bytes32(ripemd160(secret));
        }
        
        //Check for secret validity
        if (hash == secretHash) {
            SecretReveal(secret);
            B.transfer(value);
            
            //Begin clearing out contract
            value = 0;
        }
    }
    
    //Can be called to transfer funds back to A either after timeout or if B has claimed their funds
    //Anyone can call the contract to clean up the ETH state
    function Kill() public {
        //Contract must have timed out or be empty
        require((value == 0) || (block.number > timeoutBlock));
        
        //Destroy contract and send remaining funds to A (in case of timeout)
        selfdestruct(A);
    }
}
