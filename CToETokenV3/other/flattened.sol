pragma solidity ^0.5.9;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP. Does not include
 * the optional functions; to access them see `ERC20Detailed`.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a `Transfer` event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through `transferFrom`. This is
     * zero by default.
     *
     * This value changes when `approve` or `transferFrom` are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * > Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an `Approval` event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a `Transfer` event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to `approve`. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

library AltBN128 {
    //Scalar Functions
	function GetN() internal pure returns (uint) {
		return 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
	}
	
	function GetP() internal pure returns (uint) {
		return 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
	}
	
	function GetCompressedPointSignFlag() internal pure returns (uint) {
	    return 0x8000000000000000000000000000000000000000000000000000000000000000;
	}
	
	function NegateFQ(uint fq) internal pure returns (uint) {
		return GetP() - (fq % GetP());
	}
	
	function NegateScalar(uint s) internal pure returns (uint) {
		return GetN() - (s % GetN());
	}
	
	//Point Functions
	function GetG1() internal pure returns (uint G1x, uint G1y) {
	    return (1, 2);
	}
	
	//Checks to see if point is zero
	function IsZero(uint Px, uint Py) internal pure returns (bool) {
	    return (Px == 0 && Py == 0);
	}
	
	function CompressPoint(uint Px, uint Py) internal pure returns (uint x_compressed) {
	    x_compressed = Px;
        
        if (Py & 1 != 0) {
            x_compressed |= GetCompressedPointSignFlag();
        }
	}
	
	function ExpandPoint(uint x_compressed) internal view returns (uint Px, uint Py) {
        //Check bit flag
        bool odd = (x_compressed & GetCompressedPointSignFlag() != 0);
        
        //Remove bit flag
        if (odd) {
            x_compressed &= ~GetCompressedPointSignFlag();
        }
        
        //Get y-coord
        (Px, Py) = G1PointFromX(x_compressed);
        
        //Check sign, correct if necessary
        if (odd) {
            if (Py & 1 == 0) {
                Py = NegateFQ(Py);
            }
        }
        else {
            if (Py & 1 == 1) {
                Py = NegateFQ(Py);
            }
        }
    }
	
	//Calculates G1 Point addition using precompile
	function AddPoints(uint Ax, uint Ay, uint Bx, uint By) internal view returns (uint Cx, uint Cy)	{
	    //Trivial Cases, no precompile call required
	    if (IsZero(Ax, Ay)) return (Bx, By);
	    if (IsZero(Bx, By)) return (Ax, Ay);
	    
	    uint[] memory data = new uint[](4);
	    data[0] = Ax;
	    data[1] = Ay;
	    data[2] = Bx;
	    data[3] = By;
	    
	    assembly {
	        //Call ECAdd
        	let success := staticcall(sub(gas, 2000), 0x06, add(data, 0x20), 0x80, add(data, 0x20), 0x40)
       	 
        	// Use "invalid" to make gas estimation work
         	switch success case 0 { revert(data, 0x80) }
	    }
	    
	    (Cx, Cy) = (data[0], data[1]);
	}
	
	//Check to see if G1Point is on curve
	function IsOnCurve(uint Px, uint Py) internal pure returns (bool) {
	    //(y^2 == x^3 + 3) % p
	    uint p = GetP();
	    uint left = mulmod(Py, Py, p);
	    uint right = addmod(mulmod(mulmod(Px, Px, p), Px, p), 3, p);
	    
	    return (left == right);
	}	
	
    //Get G1Point from desired x coordinate (increment x if not on curve)
	function G1PointFromX(uint x) internal view returns (uint Px, uint Py) {
	    uint p = GetP();
	    x = x % p;
	    
	    uint[] memory data = new uint[](6);
	    data[0] = 0x20;
	    data[1] = 0x20;
	    data[2] = 0x20;
	    //data[3] = 0;
	    data[4] = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;  // (p+1)/4
	    data[5] = p;
	    
        bool onCurve = false;
        while(!onCurve) {
            //Get y coordinate
    	    data[3] = addmod(mulmod(mulmod(x, x, p), x, p), 3, p);
    	    
    	    assembly {
    	        //Call Big Int Mod Exp: (y_squared)^a % p, store y in data[3]
        	    let success := staticcall(sub(gas, 2000), 0x05, add(data, 0x20), 0xC0, add(data, 0x80), 0x20)
    	    }
    	    
    	    //Check y coordinate
    	    onCurve = IsOnCurve(x, data[3]);
    	    if (!onCurve) {
    	        x = addmod(x, 1, p);
    	    }
        }
        
        (Px, Py) = (x, data[3]);
	}
	
	//Get G1Point from input address
	function G1PointFromAddress(address addr) internal view returns (uint Px, uint Py) {
	    uint x = uint(keccak256(abi.encodePacked(addr)));
	    return G1PointFromX(x);
	}
}

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

library Commitments {	
	struct Data {
	    address asset_address;
		uint x;
		uint y;
	}
	
	//High Level Functions
	function GetCommitmentCount(bytes memory b) internal pure returns (uint count) {
	    //b must be 20+64*N bytes long
		require(b.length >= 84);
		
		count = b.length - 20;
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
		
		//Get asset address (first 20 bytes)
		assembly { buffer := mload(add(b, offset)) }
		address asset_address = address(buffer >> 96);
		offset += 20;
		
		//Extract Commitments
		for (uint i = 0; i < commitments.length; i++) {
		    commitments[i].asset_address = asset_address;
		    
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

contract RangeProofRegistry {
    address private debugOwner;
    
    constructor() public {
        debugOwner = msg.sender;
    }
    
    function DebugKill() public {
        require(msg.sender == debugOwner);
        
        //Reclaim DAI
        IERC20 dai = IERC20(DAI_ADDRESS);
        uint value = dai.balanceOf(address(this));
        if (value > 0) dai.transfer(msg.sender, value);
        
        //Reclaim ETH and destroy contract
        selfdestruct(msg.sender);
    }
    
    //Constants
    uint constant BOUNTY_DURATION = 20;                                             //40000 blocks = 1 week
    uint constant BOUNTY_AMOUNT_PER_BIT = 500000000000000000;                       //0.25 DAI
    //address constant DAI_ADDRESS = 0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359;    //Mainnet DAI v1.0
    address constant DAI_ADDRESS = 0xfBdB3f7db18cb66327279DD3Ab86154aa66Ab95C;      //Testnet Token
    
    //Range Proof Handling
    struct RangeProofBounty {
        address submitter;
        uint amount;
        uint expiration_block;
        bytes32 commitment_merkel_root;
    }
    
    event RangeProofsSubmitted (
        bytes32 indexed proof_hash,
        uint indexed bounty_amount,
        uint indexed expiration_block,
        bytes32 commitment_merkel_root,
        bytes proof_data
    );
    
    event RangeProofsRejected (
        bytes32 indexed proof_hash
    );
    
    event RangeProofsAccepted (
        bytes32 indexed proof_hash
    );
    
    event CommitmentVerified (
        bytes32 indexed merkel_root
    );
    
	//Pending Range Proofs, may finalize into 1-bit commitments
    mapping (bytes32 => RangeProofBounty) pending_range_proofs;
	
	//Positive Commitments, stored as merkel root of batch of commitments
	//Pure single-asset one-bit commitments
    mapping (bytes32 => bool) pure_commitment_merkels;
    
	//Combination of one-bit commitments of multiple assets
	mapping (bytes32 => bool) composite_commitment_merkels;
	
    //Data structure Helper Functions
    function GetBlankBounty() internal pure returns (RangeProofBounty memory bounty) {
        return RangeProofBounty(address(0), 0, 0, bytes32(0));
    }
    
    function IsBlankBounty(RangeProofBounty memory bounty) internal pure returns (bool) {
        if (bounty.submitter != address(0)) return false;
        if (bounty.amount != 0) return false;
        if (bounty.expiration_block != 0) return false;
        if (bounty.commitment_merkel_root != 0) return false;
        
        return true;
    }
    
    //Verifies that all commitments have been proven positive
    function IsCommitmentPositive(uint Cx, uint Cy, bytes32[] memory merkel_hashes, uint index) public view returns (bool) {
        bytes32 merkel_root = Merkel.GetExpectedRoot2N(keccak256(abi.encodePacked(Cx, Cy)), merkel_hashes, index);
        
		if (pure_commitment_merkels[merkel_root]) return true;
		if (composite_commitment_merkels[merkel_root]) return true;
		
		return false;
    }
    
    //Merkelize commitment set from bytes and check to see if it has been proven positive
    function IsCommitmentSetPositive(bytes memory b) public view returns (bool) {
        Commitments.Data[] memory commitments = Commitments.FromBytes(b);
        bytes32 merkel_root = Commitments.Merkelize(commitments);
        
		if (pure_commitment_merkels[merkel_root]) return true;
		if (composite_commitment_merkels[merkel_root]) return true;
		
		return false;
    }
    
    //Submit range proof along with bounty for verification
    //If unchallenged for 1 week, they are assumed to be commitments to valid bits (0 or 1)
    function SubmitRangeProofs(bytes memory b) public {
        //Check that proof has not already been published
        bytes32 proof_hash = keccak256(abi.encodePacked(b));
        require(IsBlankBounty(pending_range_proofs[proof_hash]));
        
        //Check that proofs are properly formatted
        OneBitRangeProof.Data[] memory proofs = OneBitRangeProof.FromBytesAll(b);
        require(proofs.length > 0);
        
        uint bounty_amount = proofs.length * BOUNTY_AMOUNT_PER_BIT;
        uint expiration_block = block.number + BOUNTY_DURATION;
        
        //Check DAI Allowance
        IERC20 dai = IERC20(DAI_ADDRESS);
        require(dai.allowance(msg.sender, address(this)) >= bounty_amount);
        
        //Transfer DAI bounty
        dai.transferFrom(msg.sender, address(this), bounty_amount);
        
        //Calculate commitments merkel root
        Commitments.Data[] memory commitments = new Commitments.Data[](proofs.length);
        for (uint i = 0; i < proofs.length; i++) {
            commitments[i].x = proofs[i].Cx;
            commitments[i].y = proofs[i].Cy;
        }
        bytes32 commitment_merkel_root = Commitments.Merkelize(commitments);
        
        //Publish Range Proof Bounty
        pending_range_proofs[proof_hash] = RangeProofBounty(msg.sender, bounty_amount, expiration_block, commitment_merkel_root);
        emit RangeProofsSubmitted(proof_hash, bounty_amount, expiration_block, commitment_merkel_root, b);
    }
	
	//Return status of range proof
	function GetRangeProofInfo(bytes32 proof_hash)
		public view returns (address submitter, uint amount, uint expiration_block)
	{
		submitter = pending_range_proofs[proof_hash].submitter;
		amount = pending_range_proofs[proof_hash].amount;
		expiration_block = pending_range_proofs[proof_hash].expiration_block;
	}
    
    //Finalize Pending Range Proof
    function FinalizeRangeProofs(bytes32 proof_hash) public {
        //Check that proof exists
        RangeProofBounty memory bounty = pending_range_proofs[proof_hash];
        require(!IsBlankBounty(bounty));
        
        //Check that expiration block has passed
        require(block.number >= bounty.expiration_block);
        emit RangeProofsAccepted(proof_hash);
        
        //Clear Bounty
        pending_range_proofs[proof_hash] = GetBlankBounty();
        
        //Publish finalized commitments to mapping
        pure_commitment_merkels[bounty.commitment_merkel_root] = true;
        emit CommitmentVerified(bounty.commitment_merkel_root);
        
        //Return Bounty to submitter
        IERC20 dai = IERC20(DAI_ADDRESS);
        address payable to = address(uint(bounty.submitter));
        dai.transfer(to, bounty.amount);
    }
    
    //Challenge Range Proofs
    //Select one proof of range proof set to challenge
    //If it fails the check, all range proofs are discarded
    function ChallengeRangeProofs(bytes memory b, bytes32[] memory merkel_hashes, uint index) public {
        //Fetch proof
        OneBitRangeProof.Data memory proof = OneBitRangeProof.FromBytes(b, 0);
        
        //Get resulting hash from merkel proof
        bytes32 proof_hash = OneBitRangeProof.GetExpectedHash(proof, merkel_hashes, index);
        
        //Check that proof exists
        RangeProofBounty memory bounty = pending_range_proofs[proof_hash];
        require(bounty.expiration_block > 0);
        
        //Check Challenge
        uint Hx;
        uint Hy_neg;
        (Hx, Hy_neg) = OneBitRangeProof.CalcNegAssetH(proof.asset_address);
        require(!OneBitRangeProof.Verify(proof, Hx, Hy_neg));
        emit RangeProofsRejected(proof_hash);
        
        //Clear Bounty
        pending_range_proofs[proof_hash] = GetBlankBounty();
        
        //Give Bounty to challenger
        IERC20 dai = IERC20(DAI_ADDRESS);
        dai.transfer(msg.sender, bounty.amount);
    }
    
    //Force Prove Range Proof
    //Do not play bounty game. Verify all range proofs. High overall gas usage!
    function ForceProve(bytes memory b) public returns (bool) {
        //Get first proof
        OneBitRangeProof.Data[] memory proofs = OneBitRangeProof.FromBytesAll(b);
        require(proofs.length > 0);
        
        //Check proofs
        uint Hx;
        uint Hy_neg;
        (Hx, Hy_neg) = OneBitRangeProof.CalcNegAssetH(proofs[0].asset_address);
        
        Commitments.Data[] memory commitments = new Commitments.Data[](proofs.length);
        
        for (uint i = 0; i < proofs.length; i++) {
            if (!OneBitRangeProof.Verify(proofs[i], Hx, Hy_neg)) return false;
            
            commitments[i].x = proofs[i].Cx;
            commitments[i].y = proofs[i].Cy;
        }
        
        //Merkelize commitments and mark as positive
        bytes32 merkel_root = Commitments.Merkelize(commitments);
        pure_commitment_merkels[merkel_root] = true;
        emit CommitmentVerified(merkel_root);
        
        return true;
    }

	//Mix one-bit commitments of two previously verified commitment sets
	//Each set must be pure, that is of a single asset
	function MixOneBitCommitments(bytes memory b_A, bytes memory b_B) public returns (bytes32 mixed_merkel_root) {
	    //Unpack commitments
	    Commitments.Data[] memory commitments_a = Commitments.FromBytes(b_A);
	    Commitments.Data[] memory commitments_b = Commitments.FromBytes(b_B);
	    
	    //Check that both sets are positive
	    require(pure_commitment_merkels[Commitments.Merkelize(commitments_a)]);
	    require(pure_commitment_merkels[Commitments.Merkelize(commitments_b)]);
	    
	    //Mix commitments
	    Commitments.Data[] memory commitments_mixed = new Commitments.Data[](commitments_a.length*commitments_b.length);
	    uint index = 0;
	    for (uint i = 0; i < commitments_a.length; i++) {
	        for (uint j = 0; j < commitments_b.length; j++) {
	            (commitments_mixed[index].x, commitments_mixed[index].y) =
	                AltBN128.AddPoints( commitments_a[i].x, commitments_a[i].y,
	                                    commitments_b[j].x, commitments_b[j].y  );
	            index++;
	        }
	    }
	    
        //Merkelize commitments and mark as positive
        mixed_merkel_root = Commitments.Merkelize(commitments_mixed);
        composite_commitment_merkels[mixed_merkel_root] = true;
        emit CommitmentVerified(mixed_merkel_root);
	}

	//Build large commitments
	function BuildCommitment(bytes memory b, uint8[] memory indices) public view returns (uint Cx, uint Cy) {
		//Unpack commitments
	    Commitments.Data[] memory commitments = Commitments.FromBytes(b);
		
		//Only allow 64-bit commitments or less
		if (indices.length == 0) return (0, 0);
		if (indices.length > 64) return (0, 0);
		
		//Use Double and Add
		uint index;
		for (uint i = 0; i < indices.length; i++) {
			//Double
			(Cx, Cy) = AltBN128.AddPoints(Cx, Cy, Cx, Cy);
			
		    //Retreive next index, must be within array bounds
		    index = indices[i];
		    if (index >= commitments.length) return (0, 0);
		    
			//Add
			(Cx, Cy) = AltBN128.AddPoints(Cx, Cy, commitments[index].x, commitments[index].y);
		}
	}
}