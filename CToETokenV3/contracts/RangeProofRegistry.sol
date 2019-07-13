pragma solidity ^0.5.10;

import "./libOneBitRangeProof.sol";
import "./libCommitments.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";

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
    function IsCommitmentSetPositive(bytes32 merkel_root) public view returns (bool) {
		if (pure_commitment_merkels[merkel_root]) return true;
		if (composite_commitment_merkels[merkel_root]) return true;
		
		return false;
    }
    
    //Submit range proof along with bounty for verification
    //If unchallenged for 1 week, they are assumed to be commitments to valid bits (0 or 1)
    function SubmitRangeProofs(bytes memory b) public {
        //Check that proof has not already been published
        bytes32 proof_hash = OneBitRangeProof.Hash(b);
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
		public view returns (address submitter, uint amount, uint expiration_block, bytes32 commitment_merkel_root)
	{
		submitter = pending_range_proofs[proof_hash].submitter;
		amount = pending_range_proofs[proof_hash].amount;
		expiration_block = pending_range_proofs[proof_hash].expiration_block;
		commitment_merkel_root = pending_range_proofs[proof_hash].commitment_merkel_root;
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
        require(!IsBlankBounty(bounty));
        
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
	function BuildCommitment(bytes memory b, uint8[] memory indices)
	    public view returns (uint Cx, uint Cy)
	{
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
	
	function BuildCommitment2(bytes memory b, uint8[] memory indices0, uint8[] memory indices1)
	    public view returns (uint Ax, uint Ay, uint Bx, uint By)
    {
        //Build two commitments with one call
        (Ax, Ay) = BuildCommitment(b, indices0);
        (Bx, By) = BuildCommitment(b, indices1);
    }
    
	//Storage for built commitments
	mapping (uint => bool) commitment_storage;
    
    //Store large commitments
    function BuildAndStore(bytes memory b, uint8[] memory indices) public {
        //Build commitments
	    uint Cx;
	    uint Cy;
	    (Cx, Cy) = BuildCommitment(b, indices);
	    
	    //Check for success
	    if (!AltBN128.IsZero(Cx, Cy)) {
	        //Compress Commitment
	        Cx = AltBN128.CompressPoint(Cx, Cy);
	        
	        //Store Commitment
	        commitment_storage[Cx] = true;
	    }
	}
	
    function BuildAndStore2(bytes memory b, uint8[] memory indices0, uint8[] memory indices1) public {
        //Build commitments
	    uint Ax;
	    uint Ay;
	    uint Bx;
	    uint By;
	    (Ax, Ay, Bx, By) = BuildCommitment2(b, indices0, indices1);
	    
	    //Check for successes
	    if (!AltBN128.IsZero(Ax, Ay)) {
	        //Compress Commitment
	        Ax = AltBN128.CompressPoint(Ax, Ay);
	        
	        //Store Commitment
	        commitment_storage[Ax] = true;
	    }
	    
	    if (!AltBN128.IsZero(Bx, By)) {
	        //Compress Commitment
	        Bx = AltBN128.CompressPoint(Bx, By);
	        
	        //Store Commitment
	        commitment_storage[Bx] = true;
	    }
	}
}