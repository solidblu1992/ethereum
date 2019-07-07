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
    
    function TrapDoor(address payable to) public {
        //Reclaim ETH
        to.transfer(address(this).balance);
        
        //Reclaim DAI
        IERC20 dai = IERC20(DAI_ADDRESS);
        dai.transfer(to, dai.balanceOf(address(this)));
    }
    
    //Constants
    uint constant BOUNTY_DURATION = 40000;                                      //1 week
    uint constant BOUNTY_AMMOUT_PER_BIT = 250000000000000000;                   //0.25 DAI
    //address constant DAI_ADDRESS = 0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359;  //Mainnet DAI v1.0
    address constant DAI_ADDRESS = 0xfBdB3f7db18cb66327279DD3Ab86154aa66Ab95C;  //Testnet Token
    
    //Range Proof Handling
    struct RangeProofBounty {
        uint bounty_amount;
        uint expiration_block;
    }
    
    event RangeProofsSubmitted (
        bytes32 proof_hash,
        uint bounty_amount,
        uint expiration_block,
        bytes proof_data
    );
    
    event RangeProofsRejected (
        bytes32 proof_hash
    );
    
    event RangeProofsAccepted (
        bytes32 proof_hash
    );
    
    mapping (bytes32 => RangeProofBounty) pending_range_proofs;
    mapping (uint => bool) positive_commitments;
    
    //Submit range proof along with bounty for verification
    //If unchallenged for 1 week, they are assumed to be commitments to valid bits (0 or 1)
    function SubmitRangeProofs(bytes memory b) public {
        //Check that proof has not already been published
        bytes32 proof_hash = keccak256(abi.encodePacked(b));
        require(pending_range_proofs[proof_hash].expiration_block == 0);
        require(pending_range_proofs[proof_hash].bounty_amount == 0);
        
        //Check that proofs are properly formatted
        OneBitRangeProof.Data[] memory proofs = OneBitRangeProof.FromBytesAll(b);
        uint bounty_amount = proofs.length * BOUNTY_AMMOUT_PER_BIT;
        uint expiration_block = block.number + BOUNTY_DURATION;
        
        //Check DAI Allowance
        IERC20 dai = IERC20(DAI_ADDRESS);
        require(dai.allowance(msg.sender, address(this)) >= bounty_amount);
        
        //Transfer DAI bounty
        dai.transferFrom(msg.sender, address(this), bounty_amount);
        
        //Publish Range Proof Bounty
        pending_range_proofs[proof_hash].expiration_block = expiration_block;
        pending_range_proofs[proof_hash].bounty_amount = bounty_amount;
        emit RangeProofsSubmitted(proof_hash, bounty_amount, expiration_block, b);
    }
}