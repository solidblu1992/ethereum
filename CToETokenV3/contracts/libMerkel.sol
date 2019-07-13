pragma solidity ^0.5.9;

library Merkel {
	//Checks merkel proof.
	//Note: Only works for merkel trees with size 2**n
	function GetExpectedRoot2N(bytes32 x, bytes32[] memory merkel_hashes, uint x_index)
		internal pure returns (bytes32 root)
	{		
		//Hash proof pieces
		uint k = x_index;
		root = x;
		for (uint i = 0; i < merkel_hashes.length; i++) {
			//x on left
			if (k & 1 == 0) {
				root = keccak256(abi.encodePacked(root, merkel_hashes[i]));
			}
			//x on right
			else {
				root = keccak256(abi.encodePacked(merkel_hashes[i], root));
			}
			
			k >>= 1;
		}
	}
	
	//Create merkel tree from slice of bytes32 data array
	//Can be used to make any size of merkel tree
	function CreateRecursive(bytes32[] memory a, uint start, uint length)
        internal pure returns (bytes32)
    {
        //Input checks
        require(length > 0);
        require(start < a.length);
        require(length <= a.length);
        require((start+length) <= a.length);
        
        if (length == 1) return a[start];
        if (length == 2) return keccak256(abi.encodePacked(a[start], a[start+1]));
        if (length == 3) return keccak256(abi.encodePacked(a[start], a[start+1], a[start+2]));
        
        //Even Recursion
        uint length_over_2 = length / 2;
        return  keccak256(
                    abi.encodePacked(
                        CreateRecursive(a, start, length_over_2),
                        CreateRecursive(a, start+length_over_2, length_over_2 + (length & 1 == 0 ? 0 : 1))
                    )
                );
    }
}