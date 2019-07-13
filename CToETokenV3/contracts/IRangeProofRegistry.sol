pragma solidity ^0.5.10;

contract RangeProofRegistry {
	//Build large commitments
	function BuildCommitment(bytes memory b, uint8[] memory indices) public view returns (uint Cx, uint Cy);
}

contract TestRPR {
    address private debugOwner;
    
    constructor() public {
        debugOwner = msg.sender;
    }
    
    function DebugKill() public {
        require(msg.sender == debugOwner);
        
        //Reclaim ETH and destroy contract
        selfdestruct(msg.sender);
    }
    
    function BuildCommitment_GT(bytes memory b, uint8[] memory indices) public returns (uint Cx, uint Cy) {
        return RangeProofRegistry(0x24bE0B79159F225D8B71cAAa5d28CCEC83BFC878)
                    .BuildCommitment(b, indices);
    }
}