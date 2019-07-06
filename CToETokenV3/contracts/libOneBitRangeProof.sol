pragma solidity ^0.5.9;

import "./libAltBN128.sol";

library OneBitRangeProof {	
	struct Data {
		uint Cx;
		uint Cy;
		uint c0;
		uint s0;
		uint s1;
	}
	
    //Low Level Functions
    function CalcNegAssetH(address asset_address) internal view returns (uint Hx, uint Hy_neg) {
        (Hx, Hy_neg) = AltBN128.G1PointFromAddress(asset_address);
        Hy_neg = AltBN128.NegateFQ(Hy_neg);
    }	
	
	//High Level Functions
	function FromBytes(bytes memory b) internal view returns (Data[] memory proof) {
		//b must be a multiple of 32*4=128 or 32*5=160 bytes long
		bool compressed_proof = false;
		
		if (b.length % 128 == 0) {
		    compressed_proof = true;
		    proof = new Data[](b.length / 128);
		}
		else {
		    require(b.length % 160 == 0);
		    proof = new Data[](b.length / 160);
		}
		
		//Load bytes 32 at a time, shift off unused bits
		uint buffer;
		uint offset = 32; //1st byte is length, unneeded
		
		//Extract Proofs
		for (uint i = 0; i < proof.length; i++) {
		    if (compressed_proof) {
        		assembly { buffer := mload(add(b, offset)) }
        	    (proof[i].Cx, proof[i].Cy) = AltBN128.ExpandPoint(buffer);
        	    offset += 32;
		    }
		    else {
		        assembly { buffer := mload(add(b, offset)) }
        	    proof[i].Cx = buffer;
        	    offset += 32;
        	    
        	    assembly { buffer := mload(add(b, offset)) }
        	    proof[i].Cy = buffer;
        	    offset += 32;
		    }
    	    
    		assembly { buffer := mload(add(b, offset)) }
    	    proof[i].c0 = buffer;
    	    offset += 32;
    		
    		assembly { buffer := mload(add(b, offset)) }
    	    proof[i].s0 = buffer;
    	    offset += 32;
    		
    		assembly { buffer := mload(add(b, offset)) }
    	    proof[i].s1 = buffer;
    	    offset += 32;
		}
	}
	
    function Verify(Data memory proof, uint Hx, uint Hy_neg) internal view returns (bool) {
        //Allocate memory
        uint[] memory data = new uint[](7);

        //Do first ring segment
        //2 multiplications, 1 addition, and 1 keccak256
        data[0] = proof.Cx;
        data[1] = proof.Cy;
        data[2] = proof.c0;
        data[3] = 1;    //G1x
        data[4] = 2;    //G1y
        data[5] = proof.s0;
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
        data[3] = proof.Cx;
        data[4] = proof.Cy;
        data[5] = Hx;
        data[6] = Hy_neg;
        
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
        data[5] = proof.s1;
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
         return(data[2] == proof.c0);
    }
}