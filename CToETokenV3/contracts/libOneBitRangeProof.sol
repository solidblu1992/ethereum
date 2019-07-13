pragma solidity ^0.5.9;

import "./libAltBN128.sol";
import "./libMerkel.sol";

library OneBitRangeProof {	
	struct Data {
	    address asset_address;
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
	function GetProofCount(bytes memory b) internal pure returns (uint count) {
	    //b must be 20+160*N bytes long
		require(b.length >= 180);
		
		count = b.length - 20;
		require(count % 160 == 0);
		count = count / 160;
	}
	
	function FromBytes(bytes memory b, uint index) internal pure returns (Data memory proof) {
		uint num_proofs;
		num_proofs = GetProofCount(b);
		
		//Check to see if b is long enough for requested index
		require(index < num_proofs);
		
		//Load bytes 32 at a time, shift off unused bits
		uint buffer;
		uint offset = 32;
		
		//Get asset address (first 20 bytes)
		assembly { buffer := mload(add(b, offset)) }
		proof.asset_address = address(buffer >> 96);

        //Extract Proof 
		offset = 52 + 160*index;

		assembly { buffer := mload(add(b, offset)) }
		proof.Cx = buffer;
		offset += 32;
			
		assembly { buffer := mload(add(b, offset)) }
		proof.Cy = buffer;
		offset += 32;
		
		assembly { buffer := mload(add(b, offset)) }
		proof.c0 = buffer;
		offset += 32;
		
		assembly { buffer := mload(add(b, offset)) }
		proof.s0 = buffer;
		offset += 32;
		
		assembly { buffer := mload(add(b, offset)) }
		proof.s1 = buffer;
	}
	
	function FromBytesAll(bytes memory b) internal pure returns (Data[] memory proof) {
		uint num_proofs;
		num_proofs = GetProofCount(b);
        proof = new Data[](num_proofs);
		
		//Load bytes 32 at a time, shift off unused bits
		uint buffer;
		uint offset = 32; //1st byte is length, unneeded
		
		//Get asset address (first 20 bytes)
		assembly { buffer := mload(add(b, offset)) }
		address asset_address = address(buffer >> 96);
		offset += 20;
		
		//Extract Proofs
		for (uint i = 0; i < proof.length; i++) {
		    proof[i].asset_address = asset_address;
		    
		    assembly { buffer := mload(add(b, offset)) }
        	proof[i].Cx = buffer;
        	offset += 32;
        	    
        	assembly { buffer := mload(add(b, offset)) }
        	proof[i].Cy = buffer;
        	offset += 32;
    	    
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

    function Hash(bytes memory b) internal pure returns (bytes32 hash) {
        //Fetch Proofs
        Data[] memory proofs = FromBytesAll(b);
		require(proofs.length > 0);
		
		//Calculate proof hashes
		bytes32[] memory proof_hashes = new bytes32[](proofs.length);
		
		for (uint i = 0; i < proof_hashes.length; i++) {
            proof_hashes[i] = keccak256(abi.encodePacked(proofs[i].Cx, proofs[i].Cy, proofs[i].c0, proofs[i].s0, proofs[i].s1));
		}
		
		//Create Merkel Tree out of Proofs
		hash = Merkel.CreateRecursive(proof_hashes, 0, proofs.length);
		
		//Add asset address to hash
		hash = keccak256(abi.encodePacked(proofs[0].asset_address, hash));
    }
    
    function GetExpectedHash(Data memory proof, bytes32[] memory hashes, uint index) internal pure returns (bytes32 hash) {
        //Get hash of single proof, don't hash asset_address
        hash = keccak256(abi.encodePacked(proof.Cx, proof.Cy, proof.c0, proof.s0, proof.s1));
        
        //Check merkel proof
        hash = Merkel.GetExpectedRoot2N(hash, hashes, index);
        
        //Hash in asset address
        hash = keccak256(abi.encodePacked(proof.asset_address, hash));
    }
}