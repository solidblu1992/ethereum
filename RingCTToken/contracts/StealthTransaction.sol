pragma solidity ^0.4.19;

import "./ECMath.sol";

contract StealthTransaction is ECMath {
	function StealthTransaction() public {
		//Constructor Logic
	}
	
	//Stealth Address Mappings
	mapping (address => uint256) public stx_pubviewkeys;    //Stores A=aG (public view key)
    mapping (address => uint256) public stx_pubspendkeys;   //Stores B=bG (public spend key)
    mapping (uint256 => uint256) public stx_dhe_points;     //Stores R=rG for each stealth transaction
    mapping (uint256 => bool) public stx_dhepoints_reverse; //Reverse lookup for dhe_points
	uint256 public stx_dhe_point_count;
	
	event NewStealthTx (
	    uint256 pub_key,
	    uint256 dhe_point,
	    uint256[2] encrypted_data,
	    uint256 iv
	);
	
	//Stealth Address Functions
    //For a given msg.sender (ETH address) publish EC points for public spend and view keys
    //These EC points will be used to generate stealth addresses
    function PublishSTxPublicKeys(uint256 stx_pubspendkey, uint256 stx_pubviewkey)
        public returns (bool success)
    {
        stx_pubspendkeys[msg.sender] = stx_pubspendkey;
        stx_pubviewkeys[msg.sender] = stx_pubviewkey;
        success = true;
    }
    
    //Generate stealth transaction (off-chain)
    function GenerateStealthTx(address stealth_address, uint256 random)
        public constant returns (address dest, uint256 dhe_point)
    {
        //Verify that destination address has published spend and view keys
        if (stx_pubspendkeys[stealth_address] == 0 || stx_pubviewkeys[stealth_address] == 0) return (0,0);
        
        //Generate DHE Point (R = rG)
        uint256[2] memory temp;
        
        temp = ecMul(G1, random);
        dhe_point = CompressPoint(temp);
        
        //Generate shared secret ss = H(rA) = H(arG)
        temp[0] = HashOfPoint(ecMul(ExpandPoint(stx_pubviewkeys[stealth_address]), random));
        
        //Calculate target address public key P = ss*G + B
        temp = ecMul(G1, temp[0]);
        temp = ecAdd(temp, ExpandPoint(stx_pubspendkeys[stealth_address]));
        
        //Calculate target address from public key
        dest = GetAddress(temp);
    }
    
    //Calulates Stealth Address from index i of stx_dhepoints (off-chain)
    //This function can be used to check for non-zero value addresses (are they applicable?)
    function GetStealthTxAddress(uint256 i, uint256 stx_privviewkey, uint256 stx_pubspendkey)
        public constant returns (address dest)
    {
        //If i >= stx_dhepoint_count then automatically the address is not used
        if (i >= stx_dhe_point_count) return 0;
        
        //Expand dhe point (R = rG)
        uint256[2] memory temp;
        temp = ExpandPoint(stx_dhe_points[i]);
        
        //Calculate shared secret ss = H(aR) = H(arG)
        temp[0] = HashOfPoint(ecMul(temp, stx_privviewkey));
        
        //Calculate target address public key P = ss*G + B
        temp = ecMul(G1, temp[0]);
        temp = ecAdd(temp, ExpandPoint(stx_pubspendkey));
        
        //Calculate target address from public key
        dest = GetAddress(temp);
    }
    
    //Calculates private key for stealth tx
    function GetStealthTxPrivKey(uint256 i,uint256 stx_privviewkey, uint256 stx_privspendkey)
        public constant returns (uint256 privkey)
    {
        //If i >= stx_dhepoint_count then automatically the address is not used
        if (i >= stx_dhe_point_count) return 0;
        
        //Expand dhe point (R = rG)
        uint256[2] memory temp;
        temp = ExpandPoint(stx_dhe_points[i]);
        
        //Calculate shared secret ss = H(aR) = H(arG)
        temp[0] = HashOfPoint(ecMul(temp, stx_privviewkey));
        
        //Calculate private key = ss + b
        privkey = addmod(temp[0], stx_privspendkey, NCurve);
    }
}