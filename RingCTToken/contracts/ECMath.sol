pragma solidity ^0.4.22;

import "./Debuggable.sol";

contract ECMath is Debuggable {
	//alt_bn128 constants
	uint256[2] private G1;
	uint256[2] private H;
	uint256[2] private Inf;
	uint256 constant private NCurve = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
	uint256 constant private PCurve = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

	//Used for Point Compression/Decompression
	uint256 constant private ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000;
	uint256 constant private a = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52; // (p+1)/4
	
	constructor() public {
        G1[0] = 1;
    	G1[1] = 2;
		
    	H = HashToPoint(G1);
		
		Inf[0] = 0;
		Inf[1] = 0;
	}
	
	//Base EC Parameters
	function GetG1() public view returns (uint256[2]) { return G1; }
	function GetH() public view returns (uint256[2]) { return H; }
	function GetInfinity() public view returns (uint256[2]) { return Inf; }
	function GetNCurve() public pure returns (uint256) { return NCurve; }
	function GetPCurve() public pure returns (uint256) { return PCurve; }
	
	function GetGHVector(uint256 length)
		public constant returns (uint256[] Gxi, uint256[] Gyi, uint256[] Hxi, uint256[] Hyi)
	{
	    require(length > 0);
	    
		uint256[2] memory temp;
		Gxi = new uint256[](length);
		Gyi = new uint256[](length);
		Hxi = new uint256[](length);
		Hyi = new uint256[](length);
		
		temp = H;
		for (uint256 i = 0; i < length; i++) {
			temp = HashToPoint(temp);
			(Gxi[i], Gyi[i]) = (temp[0], temp[1]);
			
			temp = HashToPoint(temp);
			(Hxi[i], Hyi[i]) = (temp[0], temp[1]);
		}
	}
	
	//Base EC Functions
	function Negate(uint256[2] p1)
		public pure returns (uint256[2] p2)
	{	
		p2[0] = p1[0];
		p2[1] = PCurve - (p1[1] % PCurve);
	}
	
	function Equals(uint256[2] p1, uint256[2] p2)
		public pure returns (bool)
	{
		return ((p1[0] == p2[0]) && (p1[1] == p2[1]));
	}
	
	function Add(uint256[2] p0, uint256[2] p1)
    	public constant returns (uint256[2] p2)
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
    
	function Subtract(uint256[2] p0, uint256[2] p1)
    	public constant returns (uint256[2] p2)
	{
		return Add(p0, Negate(p1));
	}
	
	function Multiply(uint256[2] p0, uint256 s)
    	public constant returns (uint256[2] p1)
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
    
    //Shortcut Functions
    function MultiplyG1(uint256 s)
        public constant returns (uint256[2] p0)
    {
        return Multiply(G1, s);
    }
    
    function MultiplyH(uint256 s)
        public constant returns (uint256[2] p0)
    {
        return Multiply(H, s);
    }
    
    //Returns p0 = p_add + s*p_mul
    function AddMultiply(uint256[2] p_add, uint256[2] p_mul, uint256 s)
        public constant returns (uint256[2] p0)
    {
        return Add(p_add, Multiply(p_mul, s));
    }
    
    //Returns p0 = p_add + s*G1    
    function AddMultiplyG1(uint256[2] p_add, uint256 s)
        public constant returns (uint256[2] p0)
    {
        return AddMultiply(p_add, G1, s);
    }
    
    //Returns p0 = p_add + s*H
    function AddMultiplyH(uint256[2] p_add, uint256 s)
        public constant returns (uint256[2] p0)
    {
        return AddMultiply(p_add, H, s);
    }
    
    function CommitG1H(uint256 s_G1, uint256 s_H)
        public constant returns (uint256[2] p0)
    {
        return Add(MultiplyG1(s_G1), MultiplyH(s_H));
    }
    
    //Returns px = x[0]*Gi[0] + x[1]*Gi[1] + ... + x[n-1]*Gi[n-1]
    //    and py = y[0]*Hi[0] + y[1]*Hi[1] + ... + y[n-1]*Hi[n-1]
    function CommitGxHx(uint256[] x, uint256[] y)
        public constant returns (uint256[2] px, uint256[2] py)
    {
        require(x.length > 0);
        require(x.length == y.length);
        
        uint256 i;
        uint256[] memory Gxi;
        uint256[] memory Gyi;
        uint256[] memory Hxi;
        uint256[] memory Hyi;
        (Gxi, Gyi, Hxi, Hyi) = GetGHVector(x.length);
        
        px = Multiply([Gxi[0], Gyi[0]], x[0]);
        py = Multiply([Hxi[0], Hyi[0]], y[0]);
        for (i = 1; i < x.length; i++) {
            px = AddMultiply(px, [Gxi[i], Gyi[i]], x[i]);
            py = AddMultiply(py, [Hxi[i], Hyi[i]], y[i]);
        }
    }
    
    //Point Compression and Expansion Functions
	function CompressPoint(uint256[2] Pin)
    	public pure returns (uint256 Pout)
	{
    	//Store x value
    	Pout = Pin[0];
   	 
    	//Determine Sign
    	if ((Pin[1] & 0x1) == 0x1) {
        	Pout |= ECSignMask;
    	}
	}
    
	function EvaluateCurve(uint256 x)
    	public constant returns (uint256 y, bool onCurve)
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
    	public constant returns (uint256[2] Pout)
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
        PubKey = Multiply(G1, privatekey);
    }
    
    function GetAddressFromPrivateKey(uint256 privatekey)
        public constant returns (address addr)
    {
        addr = GetAddress(GetPublicKeyFromPrivateKey(privatekey));
    }

    //Return H = keccak256(p)
    function HashOfPoint(uint256[2] point)
        public pure returns (uint256 h)
    {
        bytes32 b = keccak256(point[0], point[1]);
        h = uint256(b);
    }
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[2] p)
        public constant returns (uint256[2] h)
    {
        h[0] = uint256(HashOfPoint(p)) % PCurve;
        
        bool onCurve = false;
        while(!onCurve) {
            (h[1], onCurve) = EvaluateCurve(h[0]);
            
			if (!onCurve) {
				h[0] = addmod(h[0], 1, PCurve);
			}
        }
    }
}