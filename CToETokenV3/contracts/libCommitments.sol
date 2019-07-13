pragma solidity ^0.5.9;

import "./libMerkel.sol";

library Commitments {	
	struct Data {
		uint x;
		uint y;
	}
	
	//High Level Functions
	function GetCommitmentCount(bytes memory b) internal pure returns (uint count) {
	    //b must be 64*N bytes long
	    count = b.length;
		require(count >= 64);
		require(count % 64 == 0);
		count = count / 64;
	}
	
	function FromBytes(bytes memory b) internal pure returns (Data[] memory commitments) {
		uint num_commitments;
		num_commitments = GetCommitmentCount(b);
        commitments = new Data[](num_commitments);
		
		//Load bytes 32 at a time, shift off unused bits
		uint buffer;
		uint offset = 32; //1st byte is length, unneeded
		
		//Extract Commitments
		for (uint i = 0; i < commitments.length; i++) {
		    assembly { buffer := mload(add(b, offset)) }
        	commitments[i].x = buffer;
        	offset += 32;
        	
        	assembly { buffer := mload(add(b, offset)) }
        	commitments[i].y = buffer;
        	offset += 32;
		}
	}

	function Hash(Data[] memory commitments) internal pure returns (bytes32[] memory commitment_hashes) {
	    commitment_hashes = new bytes32[](commitments.length);
	    
	    for (uint i = 0; i < commitments.length; i++) {
	        commitment_hashes[i] = keccak256(abi.encodePacked(commitments[i].x, commitments[i].y));
	    }
	}
	
	function Merkelize(Data[] memory commitments) internal pure returns (bytes32 hash) {
	    require(commitments.length > 0);
	    hash = Merkel.CreateRecursive(Hash(commitments), 0, commitments.length);
	}
}