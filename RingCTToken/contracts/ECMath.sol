pragma solidity ^0.4.19;

import "./Debuggable.sol";

contract ECMath is Debuggable {
	//alt_bn128 constants
	uint256[2] public G1;
	uint256[2] public H;
	uint256 constant internal NCurve = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
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
	
	//Address Functions
	function GetAddress(uint256[2] PubKey)
        public pure returns (address addr)
    {
        addr = address( keccak256(PubKey[0], PubKey[1]) );
    }
    
    function GetPublicKeyFromPrivateKey(uint256 privatekey)
        public constant returns (uint256[2] PubKey)
    {
        PubKey = ecMul(G1, privatekey);
    }
    
    function GetAddressFromPrivateKey(uint256 privatekey)
        public constant returns (address addr)
    {
        addr = GetAddress(GetPublicKeyFromPrivateKey(privatekey));
    }

    //Return H = keccak256(p)
    function HashOfPoint(uint256[2] point)
        internal pure returns (uint256)
    {
        uint256 h = uint256(keccak256(point[0], point[1]));
        return h;
    }
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[2] p)
        internal constant returns (uint256[2] h)
    {
        bool onCurve;
        h[0] = uint256(HashOfPoint(p)) % PCurve;
        
        while(true) {
            (h[1], onCurve) = EvaluateCurve(h[0]);
            
			if (onCurve) {
				break;
			}
			else {
				h[1] = addmod(h[1], 1, PCurve);
			}
        }
    }
}