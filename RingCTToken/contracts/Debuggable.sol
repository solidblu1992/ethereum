pragma solidity ^0.4.22;

contract Debuggable {
    //Debug Code
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier ownerOnly {
        if ( (msg.sender != owner) && (owner != 0) ) revert();
        _;
    }
    
	function Kill() public ownerOnly {
    	selfdestruct(msg.sender);
	}
	
	event DebugEvent(
		uint256[10] data
	);
}