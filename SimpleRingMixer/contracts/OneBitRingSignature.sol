pragma solidity ^0.5.9;

library OneBitRingSignature {
    function Verify(uint Px, uint Py, uint Qx, uint Qy, uint c0, uint s0, uint s1) internal view returns (bool) {
        //Allocate memory
        uint[] memory data = new uint[](6);
        data[0] = Px;
        data[1] = Py;
        data[2] = c0;
        data[3] = 1;  //G1x
        data[4] = 2;  //G1y
        data[5] = s0;
        
        //Do first ring segment
        //2 multiplications, 1 addition, and 1 keccak256
        bool success;
        assembly {
            //(Px, Py)*c0
            success := staticcall(sub(gas, 2000), 0x07, add(data, 32), 96, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//(G1x, G1y)*s0
         	success := staticcall(sub(gas, 2000), 0x07, add(data, 128), 96, add(data, 96), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//Add the two points
         	success := staticcall(sub(gas, 2000), 0x06, add(data, 32), 128, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//Hash the points, store in data[2]
         	mstore(add(data, 96), keccak256(add(data, 32), 64))
         }
        
        //Update memory
        data[0] = Qx;
        data[1] = Qy;
        //data[2] = c1;
        data[3] = 1;    //G1x
        data[4] = 2;    //G1y
        data[5] = s1;
        
        //Do second ring segment
        assembly {
            //(Qx, Qy)*c1
            success := staticcall(sub(gas, 2000), 0x07, add(data, 32), 96, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//(G1x, G1y)*s1
         	success := staticcall(sub(gas, 2000), 0x07, add(data, 128), 96, add(data, 96), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//Add the two points
         	success := staticcall(sub(gas, 2000), 0x06, add(data, 32), 128, add(data, 32), 64)
         	switch success case 0 { revert(data, 64) }
         	
         	//Hash the points, store in data[2]
         	mstore(add(data, 96), keccak256(add(data, 32), 64))
         }
         
         //Check for ring continuity
         return(data[2] == c0);
    }
}

contract TestOneBitRingSignature {
    address private debugOwner;
    
    constructor() public {
        debugOwner = msg.sender;
    }
    
    function DebugKill() public {
        require(msg.sender == debugOwner);
        selfdestruct(msg.sender);
    }
    
    function Test(uint Px, uint Py, uint Qx, uint Qy, uint c0, uint s0, uint s1) public view returns (bool) {
        return OneBitRingSignature.Verify(Px, Py, Qx, Qy, c0, s0, s1);
    }
    
    function GasTest(uint Px, uint Py, uint Qx, uint Qy, uint c0, uint s0, uint s1) public returns (bool) {
        return OneBitRingSignature.Verify(Px, Py, Qx, Qy, c0, s0, s1);
    }
}