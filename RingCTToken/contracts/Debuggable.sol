pragma solidity ^0.4.19;

contract Debuggable {
    //Debug Code
    address public owner;
    
    function Debuggable() public {
        owner = msg.sender;
    }
    
	function Kill() public {
    	if ( (msg.sender != owner) && (owner != 0) ) revert();

    	selfdestruct(msg.sender);
	}
	
	event DebugEvent(
		uint256[10] data;
	);
}
