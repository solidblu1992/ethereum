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
}

contract ECMath is Debuggable {
	//alt_bn128 constants
	uint256[2] public G1;
	uint256[2] public H;
	uint256 constant public NCurve = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
	uint256 constant public PCurve = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

	//Used for Point Compression/Decompression
	uint256 constant internal ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000;
	uint256 constant internal a = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52; // (p+1)/4
	
	function ECMath() public {
        G1[0] = 1;
    	G1[1] = 2;
    	H = HashToPoint(G1);
	}
	
	//Base EC Functions
	function ecAdd(uint256[2] p0, uint256[2] p1)
    	internal constant returns (uint256[2] p2)
	{
    	assembly {
        	//Get Free Memory Pointer
        	let p := mload(0x40)
       	 
        	//Store Data for ECAdd Call
        	mstore(p, mload(p0))
        	mstore(add(p, 0x20), mload(add(p0, 0x20)))
        	mstore(add(p, 0x40), mload(p1))
        	mstore(add(p, 0x60), mload(add(p1, 0x20)))
       	 
        	//Call ECAdd
        	let success := call(sub(gas, 2000), 0x06, 0, p, 0x80, p, 0x40)
       	 
        	// Use "invalid" to make gas estimation work
         	switch success case 0 { revert(p, 0x80) }
        	 
         	//Store Return Data
         	mstore(p2, mload(p))
         	mstore(add(p2, 0x20), mload(add(p,0x20)))
    	}
	}
    
	function ecMul(uint256[2] p0, uint256 s)
    	internal constant returns (uint256[2] p1)
	{
    	assembly {
        	//Get Free Memory Pointer
        	let p := mload(0x40)
       	 
        	//Store Data for ECMul Call
        	mstore(p, mload(p0))
        	mstore(add(p, 0x20), mload(add(p0, 0x20)))
        	mstore(add(p, 0x40), s)
       	 
        	//Call ECAdd
        	let success := call(sub(gas, 2000), 0x07, 0, p, 0x60, p, 0x40)
       	 
        	// Use "invalid" to make gas estimation work
         	switch success case 0 { revert(p, 0x80) }
        	 
         	//Store Return Data
         	mstore(p1, mload(p))
         	mstore(add(p1, 0x20), mload(add(p,0x20)))
    	}
	}
    
	function CompressPoint(uint256[2] Pin)
    	internal pure returns (uint256 Pout)
	{
    	//Store x value
    	Pout = Pin[0];
   	 
    	//Determine Sign
    	if ((Pin[1] & 0x1) == 0x1) {
        	Pout |= ECSignMask;
    	}
	}
    
	function EvaluateCurve(uint256 x)
    	internal constant returns (uint256 y, bool onCurve)
	{
    	uint256 y_squared = mulmod(x,x, PCurve);
    	y_squared = mulmod(y_squared, x, PCurve);
    	y_squared = addmod(y_squared, 3, PCurve);
   	 
    	uint256 p_local = PCurve;
    	uint256 a_local = a;
   	 
    	assembly {
        	//Get Free Memory Pointer
        	let p := mload(0x40)
       	 
        	//Store Data for Big Int Mod Exp Call
        	mstore(p, 0x20)             	//Length of Base
        	mstore(add(p, 0x20), 0x20)  	//Length of Exponent
        	mstore(add(p, 0x40), 0x20)  	//Length of Modulus
        	mstore(add(p, 0x60), y_squared) //Base
        	mstore(add(p, 0x80), a_local)   //Exponent
        	mstore(add(p, 0xA0), p_local)   //Modulus
       	 
        	//Call Big Int Mod Exp
        	let success := call(sub(gas, 2000), 0x05, 0, p, 0xC0, p, 0x20)
       	 
        	// Use "invalid" to make gas estimation work
         	switch success case 0 { revert(p, 0xC0) }
        	 
         	//Store Return Data
         	y := mload(p)
    	}
   	 
    	//Check Answer
    	onCurve = (y_squared == mulmod(y, y, PCurve));
	}
    
	function ExpandPoint(uint256 Pin)
    	internal constant returns (uint256[2] Pout)
	{
    	//Get x value (mask out sign bit)
    	Pout[0] = Pin & (~ECSignMask);
   	 
    	//Get y value
    	bool onCurve;
    	uint256 y;
    	(y, onCurve) = EvaluateCurve(Pout[0]);
   	 
    	//TODO: Find better failure case for point not on curve
    	if (!onCurve) {
        	Pout[0] = 0;
        	Pout[1] = 0;
    	}
    	else {
        	//Use Positive Y
        	if ((Pin & ECSignMask) != 0) {
            	if ((y & 0x1) == 0x1) {
                	Pout[1] = y;
            	} else {
                	Pout[1] = PCurve - y;
            	}
        	}
        	//Use Negative Y
        	else {
            	if ((y & 0x1) == 0x1) {
                	Pout[1] = PCurve - y;
            	} else {
                	Pout[1] = y;
            	}
        	}
    	}
	}
	
	//Public Functions
	function ECMulG1(uint256 s)
	    public constant returns(uint256 P)
	{
	    P = CompressPoint(ecMul(G1, s));
	}
	
	function ECMulH(uint256 s)
	    public constant returns(uint256 P)
	{
	    P = CompressPoint(ecMul(H, s));
	}
	
	//Address Functions
	function GetAddress(uint256[2] PubKey)
        public pure returns (address addr)
    {
        addr = address( keccak256(PubKey[0], PubKey[1]) );
    }
    
    function GetAddressFromPrivateKey(uint256 privatekey)
        public constant returns (address addr)
    {
        uint256[2] memory temp;
        temp = ecMul(G1, privatekey);
        addr = GetAddress(temp);
    }

    //Return H = keccak256(p)
    function HashOfPoint(uint256[2] point)
        internal pure returns (uint256 h)
    {
        return uint256(keccak256(point[0], point[1])) % NCurve;
    }
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[2] p)
        internal constant returns (uint256[2] h)
    {
        bool onCurve;
        h[0] = uint256(HashOfPoint(p)) % NCurve;
        
        while(!onCurve) {
            (h[1], onCurve) = EvaluateCurve(h[0]);
            h[0]++;
        }
        h[0]--;
    }
}

contract StealthTxAlgorithms is ECMath {
    mapping (address => uint256) public stx_pubviewkeys;    //Stores A=aG (public view key)
    mapping (address => uint256) public stx_pubspendkeys;   //Stores B=bG (public spend key)
    mapping (uint256 => uint256) public stx_dhepoints;      //Stores R=rG for each stealth transaction
    mapping (uint256 => bool) public stx_dhepoints_reverse; //Reverse lookup for dhe_points
    uint256 public stx_dhepoint_count;                      //Stores total number of stealth transactions spent
    
    function StealthTxAlgorithms() public {
        //Constructor Code
    }
    
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
        if (i >= stx_dhepoint_count) return 0;
        
        //Expand dhe point (R = rG)
        uint256[2] memory temp;
        temp = ExpandPoint(stx_dhepoints[i]);
        
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
        if (i >= stx_dhepoint_count) return 0;
        
        //Expand dhe point (R = rG)
        uint256[2] memory temp;
        temp = ExpandPoint(stx_dhepoints[i]);
        
        //Calculate shared secret ss = H(aR) = H(arG)
        temp[0] = HashOfPoint(ecMul(temp, stx_privviewkey));
        
        //Calculate private key = ss + b
        privkey = addmod(temp[0], stx_privspendkey, NCurve);
    }
    
    //Publish dhe point for stealth tx
    function PublishDHEPoint(uint256 dhe_point)
        public returns (uint256 index, bool success)
    {
        //Check reverse lookup to make sure dhe_point hasn't already been published
        if(stx_dhepoints_reverse[dhe_point]) return (0, false);
        
        //Publish DHE Point
        stx_dhepoints_reverse[dhe_point] = true;
        stx_dhepoints[stx_dhepoint_count] = dhe_point;
        stx_dhepoint_count++;
        
        return (stx_dhepoint_count-1, true);
    }
}
