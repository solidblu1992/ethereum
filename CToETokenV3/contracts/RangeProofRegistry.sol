pragma solidity ^0.5.9;

import "./libOneBitRangeProof.sol";
import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";

contract RangeProofRegistry {
    address private debugOwner;
    
    constructor() public {
        debugOwner = msg.sender;
    }
    
    function DebugKill() public {
        require(msg.sender == debugOwner);
        selfdestruct(msg.sender);
    }
    
    function DebugTrapDoor(address payable to) public {
        require(msg.sender == debugOwner);
        
        //Reclaim ETH
        uint value = address(this).balance;
        if (value > 0) to.transfer(address(this).balance);
        
        //Reclaim DAI
        IERC20 dai = IERC20(DAI_ADDRESS);
        value = dai.balanceOf(address(this));
        if (value > 0) dai.transfer(to, value);
    }
    
    //Constants
    uint constant BOUNTY_DURATION = 1;                                              //40000 blocks = 1 week
    uint constant BOUNTY_AMOUNT_PER_BIT = 250000000000000000;                       //0.25 DAI
    //address constant DAI_ADDRESS = 0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359;    //Mainnet DAI v1.0
    address constant DAI_ADDRESS = 0xfBdB3f7db18cb66327279DD3Ab86154aa66Ab95C;      //Testnet Token
    
    //Range Proof Handling
    struct RangeProofBounty {
        address submitter;
        uint amount;
        uint expiration_block;
    }
    
    event RangeProofsSubmitted (
        bytes32 indexed proof_hash,
        uint indexed bounty_amount,
        uint indexed expiration_block,
        bytes proof_data
    );
    
    event RangeProofsRejected (
        bytes32 indexed proof_hash
    );
    
    event RangeProofsAccepted (
        bytes32 indexed proof_hash
    );
    
    event CommitmentPositive (
        uint indexed point_compressed
    );
    
    mapping (bytes32 => RangeProofBounty) pending_range_proofs;
    mapping (uint => bool) positive_commitments;
    
    //Verifies that all commitments have been proven positive
    function IsPositive(uint commitment) public view returns (bool) {
        return positive_commitments[commitment];    
    }
    
    function AreAllPositive(uint[] memory commitments) public view returns (bool) {
        for (uint i = 0; i < commitments.length; i++) {
            if (!positive_commitments[commitments[i]]) return false;
        }
        
        return true;
    }
    
    //Submit range proof along with bounty for verification
    //If unchallenged for 1 week, they are assumed to be commitments to valid bits (0 or 1)
    function SubmitRangeProofs(bytes memory b) public {
        //Check that proof has not already been published
        bytes32 proof_hash = keccak256(abi.encodePacked(b));
        require(pending_range_proofs[proof_hash].amount == 0);
        require(pending_range_proofs[proof_hash].expiration_block == 0);
        
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
        
        //Publish Range Proof Bounty
        pending_range_proofs[proof_hash] = RangeProofBounty(msg.sender, bounty_amount, expiration_block);
        emit RangeProofsSubmitted(proof_hash, bounty_amount, expiration_block, b);
    }
    
    //Finalize Pending Range Proof
    function FinalizeRangeProofs(bytes memory b) public {
        //Check that proofs are properly formatted
        OneBitRangeProof.Data[] memory proofs = OneBitRangeProof.FromBytesAll(b);
        require(proofs.length > 0);        
        
        //Check that proof exists
        bytes32 proof_hash = keccak256(abi.encodePacked(b));
        RangeProofBounty memory bounty = pending_range_proofs[proof_hash];
        require(bounty.expiration_block > 0);
        
        //Check that expiration block has passed
        require(block.number > bounty.expiration_block);
        emit RangeProofsAccepted(proof_hash);
        
        //Clear Bounty
        pending_range_proofs[proof_hash] = RangeProofBounty(address(0), 0, 0);
        
        //Publish finalized commitments to mapping
        for (uint i = 0; i < proofs.length; i++) {
            uint commitment = AltBN128.CompressPoint(proofs[i].Cx, proofs[i].Cy);
            positive_commitments[commitment] = true;
            emit CommitmentPositive(commitment);
        }
        
        //Return Bounty to submitter
        IERC20 dai = IERC20(DAI_ADDRESS);
        address payable to = address(uint(bounty.submitter));
        dai.transfer(to, bounty.amount);
    }
    
    //Challenge Range Proofs
    //Select one proof of range proof set to challenge
    //If it fails the check, all range proofs are discarded
    function ChallengeRangeProofs(bytes memory b, uint index) public {
        //Check that proofs are properly formatted
        OneBitRangeProof.Data memory proof = OneBitRangeProof.FromBytes(b, index);     
        
        //Check that proof exists
        bytes32 proof_hash = keccak256(abi.encodePacked(b));
        RangeProofBounty memory bounty = pending_range_proofs[proof_hash];
        require(bounty.expiration_block > 0);
        
        //Check Challenge
        uint Hx;
        uint Hy_neg;
        (Hx, Hy_neg) = OneBitRangeProof.CalcNegAssetH(proof.asset_address);
        require(!OneBitRangeProof.Verify(proof, Hx, Hy_neg));
        emit RangeProofsRejected(proof_hash);
        
        //Clear Bounty
        pending_range_proofs[proof_hash] = RangeProofBounty(address(0), 0, 0);
        
        //Give Bounty to challenger
        IERC20 dai = IERC20(DAI_ADDRESS);
        dai.transfer(msg.sender, bounty.amount);
    }
    
    //Force Proves Range Proofs
    //Do not play bounty game. Verify all range proofs. High gas usage!
    function ForceProve(bytes memory b) public {
        //Check that proofs are properly formatted
        OneBitRangeProof.Data[] memory proofs = OneBitRangeProof.FromBytesAll(b);
        require(proofs.length > 0);
        
        //Check proofs
        uint Hx;
        uint Hy_neg;
        (Hx, Hy_neg) = OneBitRangeProof.CalcNegAssetH(proofs[0].asset_address);
        
        for (uint i = 0; i < proofs.length; i++) {
            //Can pass/fail each one individually since they are verified on-chain
            if (OneBitRangeProof.Verify(proofs[i], Hx, Hy_neg)) {
                uint commitment = AltBN128.CompressPoint(proofs[i].Cx, proofs[i].Cy);
                positive_commitments[commitment] = true;
                emit CommitmentPositive(commitment);
            }
        }
    }
}