pragma solidity ^0.5.9;

library OneBitRangeProof {
	///Curve parameters and generators
	uint constant private N = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
	uint constant private P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
	
    function Verify(uint Cx, uint Cy, uint Hx, uint Hy, uint c0, uint s0, uint s1) internal view returns (bool) {
        //Allocate memory
        uint[] memory data = new uint[](7);
        
        
        //Do first ring segment
        //2 multiplications, 1 addition, and 1 keccak256
        data[0] = Cx;
        data[1] = Cy;
        data[2] = c0;
        data[3] = 1;    //G1x
        data[4] = 2;    //G1y
        data[5] = s0;
        //data[6] = 0;  //Unused
        
        bool success;
        assembly {
            //(Px, Py)*c0, inputs from data[0, 1, 2], store result in data[0, 1]
            success := staticcall(sub(gas, 2000), 0x07, add(data, 32), 96, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//(G1x, G1y)*s0, inputs from data[3, 4, 5], store result in data[2, 3]
         	success := staticcall(sub(gas, 2000), 0x07, add(data, 128), 96, add(data, 96), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//Add the two points, inputs from data[0, 1, 2, 3], store result in data[0, 1]
         	success := staticcall(sub(gas, 2000), 0x06, add(data, 32), 128, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//Hash the point, inputs from data[0, 1], store in data[2]
         	mstore(add(data, 96), keccak256(add(data, 32), 64))
        }
        
        //Calculate C-H
        //data[0] = 0;  //Unused
        //data[1] = 0;  //Unused
        //data[2] = c1; //Unused
        data[3] = Cx;
        data[4] = Cy;
        data[5] = Hx;
        data[6] = P - (Hy % P); //negate H
        
        assembly {
            //Add the two points in data[3, 4, 5, 6], store result in data[0, 1]
         	success := staticcall(sub(gas, 2000), 0x06, add(data, 128), 128, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
        }
        
        //Do second ring segment
        //2 multiplications, 1 addition, and 1 keccak256
        //data[0] = (C-H)x;
        //data[1] = (C-H)y;
        //data[2] = c1;
        data[3] = 1;    //G1x
        data[4] = 2;    //G1y
        data[5] = s1;
        //data[6] = 0;  //Unused
        
        assembly {
            //(Qx, Qy)*c1, inputs from data[0, 1, 2], store result in data[0, 1]
            success := staticcall(sub(gas, 2000), 0x07, add(data, 32), 96, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//(G1x, G1y)*s1, inputs from data[3, 4, 5], store result in data[2, 3]
         	success := staticcall(sub(gas, 2000), 0x07, add(data, 128), 96, add(data, 96), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//Add the two points, inputs from data[0, 1, 2, 3], store result in data[0, 1]
         	success := staticcall(sub(gas, 2000), 0x06, add(data, 32), 128, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//Hash the point, inputs from data[0, 1], store in data[2]
         	mstore(add(data, 96), keccak256(add(data, 32), 64))
         }
         
         //Check for ring continuity
         return(data[2] == c0);
    }
}

contract TestOneBitRangeProof {
    address private debugOwner;
    
    constructor() public {
        debugOwner = msg.sender;
    }
    
    function DebugKill() public {
        require(msg.sender == debugOwner);
        selfdestruct(msg.sender);
    }
    
    function Test(uint Cx, uint Cy, uint Hx, uint Hy, uint c0, uint s0, uint s1) public view returns (bool) {
        return OneBitRangeProof.Verify(Cx, Cy, Hx, Hy, c0, s0, s1);
    }
    
    function GasTest(uint Cx, uint Cy, uint Hx, uint Hy, uint c0, uint s0, uint s1) public returns (bool) {
        return OneBitRangeProof.Verify(Cx, Cy, Hx, Hy, c0, s0, s1);
    }
}