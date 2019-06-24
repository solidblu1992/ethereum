pragma solidity ^0.5.9;

contract StealthTxToken {
    constructor() public {}
    function DebugKill() public { selfdestruct(msg.sender); }
    
	event TokensSpentEvent {
		//Source Data
		address indexed _src_addr,
		uint _tokens,
		uint _nonce,
		
		//Destination Data
		address indexed _dest_addr,
        byte _point_compressed_sign,
        bytes32 _point_compressed_x
	}	
	
    event DepositEvent (
        address indexed _dest_addr,
        byte _point_compressed_sign,
        bytes32 _point_compressed_x
    );
	
	event WithdrawalEvent (
		address indexed _addr,
		uint _tokens,
		uint _nonce
	);
	
	struct DelegatedTransferMessage {
		//Transfer Source and Amount
		address src_addr;
		uint tokens;
		uint nonce;		
		
		//Output Data
		address dest_addr;
		byte point_compressed_sign;
		bytes32 point_compressed_x;
	}
	
	struct DelegatedWithdrawMessage {
		//Transfer Source and Amount
		address src_addr;
		uint tokens;
		uint nonce;		
	}
		
	//State Variables
	mapping (address => uint) private _balances;
	mapping (address => uint) private _nonces;
	uint private _totalSupply;
	
	//Internal Helper Functions
	function getBlankNonce() internal pure returns (uint) {
		//Nonce used when withdrawal or transfer made by msg.sender
		//i.e. there is no delegation
		return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
	}
	
	function checkPointSign(byte _point_compressed_sign) internal pure returns (bool) {
		return (_point_compressed_sign == 0x02 || _point_compressed_sign == 0x03);
	}
	
	function getDelegatedWithdrawMessageLength() internal pure returns (uint) {
		//Loosely Packed, 32-bytes per member
		//Someday, maybe pack tighter
		//32*3 = 96;
		return 96;
	}
	
	function getDelegatedTransferMessageLength() internal pure returns (uint) {
		//Loosely Packed, 32-bytes per member
		//Someday, maybe pack tighter
		//32*6 = 192;
		return 192;
	}
	
	function unpackDelegatedTransferMessage(bytes memory message)
		internal pure returns (DelegatedTransferMessage memory msg_out)
	{
		//Unpack message into DelegatedTransferMessage
		require(message.length == getDelegatedTransferMessageLength());
		
		//Load bytes 32 at a time
		uint buffer;
		uint offset = 0;
		
		assembly { buffer := mload(add(message, offset)) }
		msg_out.src_addr = address(buffer);
		offset += 0x20;
		
		assembly { buffer := mload(add(message, offset)) }
		msg_out.tokens = buffer;
		offset += 0x20;
		
		assembly { buffer := mload(add(message, offset)) }
		msg_out.nonce = buffer;
		offset += 0x20;
		
		assembly { buffer := mload(add(message, offset)) }
		msg_out.dest_addr = address(buffer);
		offset += 0x20;
		
		assembly { buffer := mload(add(message, offset)) }
		require(buffer == 0x2 || buffer == 0x3);
		if (buffer == 0x2) {
		    msg_out.point_compressed_sign = 0x02;
		}
		else {
		    msg_out.point_compressed_sign = 0x03;
		}
		offset += 0x20;
		
		assembly { buffer := mload(add(message, offset)) }
		msg_out.point_compressed_x = bytes32(buffer);
	}
	
	function unpackDelegatedWithdrawMessage(bytes memory message)
		internal pure returns (DelegatedWithdrawMessage memory msg_out)
	{
		//Unpack message into DelegatedWithdrawMessage
		require(message.length == getDelegatedWithdrawMessageLength());
		
		//Load bytes 32 at a time
		uint buffer;
		uint offset = 0;
		
		assembly { buffer := mload(add(message, offset)) }
		msg_out.src_addr = address(buffer);
		offset += 0x20;
		
		assembly { buffer := mload(add(message, offset)) }
		msg_out.tokens = buffer;
		offset += 0x20;
		
		assembly { buffer := mload(add(message, offset)) }
		msg_out.nonce = buffer;
	}
	
	//Public Functions
	function totalSupply() public view returns (uint) { return _totalSupply; }
	function balanceOf(address tokenOwner) public view returns (uint balance) { balance = _balances[tokenOwner]; }
	function nonceOf(address tokenOwner) public view returns (uint nonce) { nonce = _nonces[tokenOwner]; }
	
	function Deposit(address _dest_addr, byte _point_compressed_sign, bytes32 _point_compressed_x) public payable {
		require(checkPointSign(_point_compressed_sign));
		require(msg.value > 0);
		require(_balances[_dest_addr] == 0);
		
		_balances[_dest_addr] = msg.value;
		_totalSupply += msg.value;
		
		emit DepositEvent(_dest_addr, _point_compressed_sign, _point_compressed_x);
	}
	
	function Withdraw(uint tokens) public {
		require(_balances[msg.sender] >= tokens);
		
		_balances[msg.sender] -= tokens;
		_totalSupply -= tokens;
		
		emit WithdrawalEvent(msg.sender, tokens, getBlankNonce());
	}
	
	function Transfer(address _dest_addr, byte _point_compressed_sign, bytes32 _point_compressed_x, uint _tokens) public {
		require(checkPointSign(_point_compressed_sign));
		require(_balances[_dest_addr] == 0);
		require(_balances[msg.sender] >= _tokens);
		
		_balances[msg.sender] -= _tokens;
		_balances[_dest_addr] += _tokens;
		
		emit TokensSpentEvent(	msg.sender, _tokens, getBlankNonce(),
								_dest_addr, _point_compressed_sign, _point_compressed_x);		
	}
	
	function DelegatedTransfer(	bytes memory _message,
								uint8 _v, bytes32 _r, bytes32 _s) public
	{
		//Unpack message from bytes into struct
	    DelegatedTransferMessage memory dmsg = unpackDelegateTransferMessgage(_message);
		
		//Check some inputs
		require(checkPointSign(dmsg.point_compressed_sign));
		require(_balances[dmsg.dest_addr] == 0);
		require(_balances[dmsg.src_addr] >= dmsg.tokens);
		require(_nonces[dmsg.src_addr] == dmsg.nonce);
		
		//Check ecrecover
		bytes32 dmsg_hash = keccak256(	abi.encodePacked(	dmsg.src_addr, dmsg.tokens, dmsg.nonce,
															dmsg.dest_addr, dmsg.point_compressed_sign, dmsg.point_compressed_x	));
															
		if (_v < 27) { v += 27; }
		require(ecrecover(dmsg_hash, _v, _r, _s) == dmsg.src_addr);
		
		//Perform Transfer		
		_balances[dmsg.src_addr] -= dmsg.tokens;
		_balances[dmsg.dest_addr] += dmsg.tokens;
		_nonce[dmsg.src_addr]++;
		
		emit TokensSpentEvent(	dmsg.src_addr, dmsg.tokens, dmsg.nonce,
								dmsg.dest_addr, dmsg.point_compressed_sign, dmsg.point_compressed_x);	
	}
	
	function DelegatedWithdraw(	bytes memory _message,
									uint8 _v, bytes32 _r, bytes32 _s) public
	{
		//Unpack message from bytes into struct
	    DelegatedWithdrawMessage memory dmsg = unpackDelegatedWithdrawMessage(_message);
		
		//Check some inputs
		require(_balances[dmsg.src_addr] >= dmsg.tokens);
		require(_nonces[dmsg.src_addr] == dmsg.nonce);
		
		//Check ecrecover
		bytes32 dmsg_hash = keccak256(	abi.encodePacked(	dmsg.src_addr, dmsg.tokens, dmsg.nonce	);
															
		if (_v < 27) { v += 27; }
		require(ecrecover(dmsg_hash, _v, _r, _s) == dmsg.src_addr);
		
		//Perform Transfer		
		_balances[dmsg.src_addr] -= dmsg.tokens;
		_totalSupply -= dmsg.tokens;
		_nonce[dmsg.src_addr]++;
		
		emit WithdrawalEvent(	dmsg.src_addr, dmsg.tokens, dmsg.nonce	);		
	}