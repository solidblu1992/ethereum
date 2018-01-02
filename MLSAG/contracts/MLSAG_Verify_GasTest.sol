pragma solidity ^0.4.19;

import "./MLSAG_Verify.sol";

contract MLSAG_Verify_GasTests is MLSAG_Verify {
    function MLSAG_Verification_GasTests() public {
        //Constructor Code
    }
    
    //Gas Test Functions
    //Removes "constant" keyword from functions in order to generate a transaction
    function VerifySAG_GasTest(bytes32 msgHash, uint256[] P, uint256[] signature)
        public returns (bool success)
    {
        return VerifySAG(msgHash, P, signature);
    }
    
    function VerifySAG_Compressed_GasTest(bytes32 msgHash, uint256[] P, uint256[] signature)
        public returns (bool success)
    {
        return VerifySAG_Compressed(msgHash, P, signature);
    }
    
    function VerifyLSAG_GasTest(bytes32 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        public returns (bool success)
    {
        return VerifyLSAG(msgHash, I, P, signature);
    }
    
    function VerifyLSAG_Compressed_GasTest(bytes32 msgHash, uint256 I, uint256[] P, uint256[] signature)
        public returns (bool success)
    {
        return VerifyLSAG_Compressed(msgHash, I, P, signature);
    }
    
    function VerifyMSAG_GasTest(uint256 m, bytes32 msgHash, uint256[] P, uint256[] signature)
        public returns (bool success)
    {
        return VerifyMSAG(m, msgHash, P, signature);
    }
    
    function VerifyMSAG_Compressed_GasTest(uint256 m, bytes32 msgHash, uint256[] P, uint256[] signature)
        public returns (bool success)
    {
        return VerifyMSAG_Compressed(m, msgHash, P, signature);
    }
    
    function VerifyMLSAG_GasTest(bytes32 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        public returns (bool success)
    {
        return VerifyMLSAG(msgHash, I, P, signature);
    }
    
    function VerifyMLSAG_Compressed_GasTest(bytes32 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        public returns (bool success)
    {
        return VerifyMLSAG_Compressed(msgHash, I, P, signature);
    }
}
