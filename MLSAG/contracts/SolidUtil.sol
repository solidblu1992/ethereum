pragma solidity ^0.4.19;

import "./ECMath.sol";

contract SolidUtil is ECMath {
    function SolidUtil() public {
        //Constructor Code
    }
    
    function getPublicKeys(uint256[] xk)
        public constant returns (uint256[] P_uncomp, uint256[] P_comp)
    {
        P_uncomp = new uint256[](xk.length*2);
        P_comp = new uint256[](xk.length);
        
        uint256[2] memory temp;
        uint256 i;
        for (i = 0; i < xk.length; i++) {
            temp = ecMul(G1, xk[i]);
            (P_uncomp[2*i], P_uncomp[2*i+1]) = (temp[0], temp[1]);
            
            P_comp[i] = CompressPoint(temp);
        }
    }
}
