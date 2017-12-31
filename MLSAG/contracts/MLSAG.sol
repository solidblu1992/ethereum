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

contract MLSAG_Algorithms is ECMath {
    function MLSAG_Algorithms() public {
        //Constructor
    }
    
    //Non-linkable Ring Signature Functions
    function RingHashFunction(bytes32 msgHash, uint256[2] point)
        internal pure returns (uint256 h)
    {
        return uint256(keccak256(msgHash, point[0], point[1])) % NCurve;
    }
    
    function StartRing_NoHash(uint256 alpha)
        internal constant returns (uint256[2] Pout)
    {
        Pout = ecMul(G1, alpha);
    }
    
    function StartRing(bytes32 msgHash, uint256 alpha)
        internal constant returns (uint256 ckp)
    {
        ckp = RingHashFunction(msgHash, StartRing_NoHash(alpha));
    }
    
    function CalculateRingSegment_NoHash(uint256 ck, uint256 sk, uint256[2] P)
        internal constant returns (uint256[2] Pout)
    {
        uint256[2] memory temp;
        Pout = ecMul(G1, sk);
        temp = ecMul(P, ck);
        Pout = ecAdd(Pout, temp);
    }
    
    function CalculateRingSegment(bytes32 msgHash, uint256 ck, uint256 sk, uint256[2] P)
        internal constant returns (uint256 ckp)
    {
        uint256[2] memory temp;
        temp = CalculateRingSegment_NoHash(ck, sk, P);
        ckp = RingHashFunction(msgHash, temp);
    }
    
    //CompleteRing = (alpha - c*xk) % N
    //Note: usable in both linkable and non-linkable rings.
    function CompleteRing(uint256 alpha, uint256 c, uint256 xk)
        internal pure returns (uint256 s)
    {
        s = mulmod(c, xk, NCurve);
        s = NCurve - s;
        s = addmod(alpha, s, NCurve);
    }
    
    //Linkable Ring Signature Functions
    function LinkableRingHashFunction(bytes32 msgHash, uint256[2] left, uint256[2] right)
        internal pure returns (uint256 h)
    {
        return uint256(keccak256(msgHash, left[0], left[1], right[0], right[1])) % NCurve;
    }
    
    function CalculateKeyImageFromPrivKey(uint256 pk)
        public constant returns (uint256[2] I)
    {
        uint256[2] memory temp;
        temp = ecMul(G1, pk);
        temp = HashToPoint(temp);
        temp = ecMul(temp, pk);
        I = temp;
    }
    
    function StartLinkableRing_NoHash(uint256 alpha, uint256[2] P)
        internal constant returns (uint256[2] Lout, uint256[2] Rout)
    {
        Lout = ecMul(G1, alpha);
        
        Rout = HashToPoint(P);
        Rout = ecMul(Rout, alpha);
    }
    
    function StartLinkableRing(bytes32 msgHash, uint256 alpha, uint256[2] P)
        internal constant returns (uint256 ckp)
    {
        uint256[2] memory left;
        uint256[2] memory right;
        (left, right) = StartLinkableRing_NoHash(alpha, P);
        ckp = LinkableRingHashFunction(msgHash, left, right);
    }
    
    function CalculateLinkableRingSegment_NoHash(uint256 ck, uint256 sk, uint256[2] P, uint256[2] I)
        internal constant returns (uint256[2] Lout, uint256[2] Rout)
    {
        uint256[2] memory temp;
        Lout = ecMul(G1, sk);
        temp = ecMul(P, ck);
        Lout = ecAdd(Lout, temp);
        
        Rout = HashToPoint(P);
        Rout = ecMul(Rout, sk);
        temp = ecMul(I, ck);
        Rout = ecAdd(Rout, temp);
    }
    
    function CalculateLinkableRingSegment(bytes32 msgHash, uint256 ck, uint256 sk, uint256[2] P, uint256[2] I)
        internal constant returns (uint256 ckp)
    {
        uint256[2] memory left;
        uint256[2] memory right;
        (left, right) = CalculateLinkableRingSegment_NoHash(ck, sk, P, I);
        ckp = LinkableRingHashFunction(msgHash, left, right);
    }
    
    //Calculate keccak256 of given array
    function Keccak256OfArray(uint256[] array)
        internal pure returns (uint256 out)
    {
        uint256 len = array.length;
        uint256[1] memory temp;
        
        //Construct c1 (store in c[0])
    	assembly {
    	    let p := mload(0x40)
    	    mstore(p, mul(len, 0x20))
    	    mstore(temp, keccak256(array, mload(p)))
    	}
    	
    	out = temp[0];
    }
    
    //Struct for reducing stack length
    struct MLSAGVariables {
        uint256 m;              //Number of keys (# of rings)
        uint256 n;              //Number of ring members (per ring)
        uint256 i;              //for use in "for" loop (i = {0, ..., m})
        uint256 j;              //for use in "for" loop (j = {0, ..., n})
        uint256 ck;             //Current hash input for ring segment
        uint256 index;          //General purpose uint256 for picking index of arrays
        uint256[2] point1;      //Expanded EC Point for general purpose use
        uint256[2] point2;      //Expanded EC Point for general purpose use
        uint256[2] keyImage;    //Expanded EC Point representing key image
    }
    
    //Verify SAG (Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //P = {P1, P2, ..., Pn}
    //signature = {c1, s1, s2, ... , sn}
    function VerifySAG(bytes32 msgHash, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.n = P.length;
        if (signature.length != (v.n+1)) return false;
        
        v.ck = signature[0];            //extract c1
        for (v.i = 0; v.i < v.n; v.i++) {
            v.point1 = ExpandPoint(P[v.i]); //extract public key
            v.ck = CalculateRingSegment(msgHash, v.ck, signature[v.i+1], v.point1);
        }
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify MSAG (Multilayered Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //P = {P11, P12, ..., P1m, P21, P22, ... P2m, Pn1, Pn2, ..., Pnm}
    //signature = {c1, s11, s12, ..., s1m, s21, s22, ..., s2m, ..., sn1, sn2, ..., snm}
    function VerifyMSAG(uint256 m, bytes32 msgHash, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.m = m;
        if (P.length % v.m != 0) return false;
        
        v.n = P.length / v.m;
        if (signature.length != (v.m*v.n+1)) return false;
        
        //Allocate array for calculating c1
        uint256[] memory c = new uint256[](2*v.m+1);
        c[0] = uint256(msgHash);
        
        for (v.i = 0; v.i < v.m; v.i++) {
            v.ck = signature[0];                //extract c1
            
            //Calculate (n-1) ring segments (output scalar ck)
            for (v.j = 0; v.j < (v.n-1); v.j++) {
                v.index = v.m*v.j + v.i;
                v.point1 = ExpandPoint(P[v.index]); //extract public key
                v.ck = CalculateRingSegment(msgHash, v.ck, signature[v.index+1], v.point1);
            }
            
            //Calculate last ring segment (output EC point input for c1 calculation)
            v.index = v.m*(v.n-1) + v.i;
            v.point1 = ExpandPoint(P[v.index]);
            v.point1 = CalculateRingSegment_NoHash(v.ck, signature[v.index+1], v.point1);
            
            //Store input to c1 calculation
            v.index = v.i*2+1;
            c[v.index] = v.point1[0];
            c[v.index+1] = v.point1[1];
        }
        
        //Calculate c1 from c point array = {msgHash, P1x, P1y, P2x, P2y, , ... , Pmx, Pmy}
        v.ck = Keccak256OfArray(c);
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify LSAG (Linkable Spontaneous Ad-hoc Group Signature)
    //msgHash = hash of message signed by ring signature
    //I = {I1, I2, ..., Im}
    //P = {P1, P2, ..., Pn}
    //signature = {c1, s1, s2, ... , sn}
    function VerifyLSAG(bytes32 msgHash, uint256 I, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.n = P.length;
        if (signature.length != (v.n+1)) return false;
        
        v.ck = signature[0];            //extract c1
        v.keyImage = ExpandPoint(I);    //extract key image
        for (v.i = 0; v.i < v.n; v.i++) {
            v.point1 = ExpandPoint(P[v.i]); //extract public key
            v.ck = CalculateLinkableRingSegment(msgHash, v.ck, signature[v.i+1], v.point1, v.keyImage);
        }
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify MLSAG (Multilayered Linkable Spontaneous Ad-hoc Group Signature)
    //msgHash = hash of message signed by ring signature
    //I = {I1, I2, ..., Im}
    //P = {P11, P12, ..., P1m, P21, P22, ... P2m, Pn1, Pn2, ..., Pnm}
    //signature = {c1, s11, s12, ..., s1m, s21, s22, ..., s2m, ..., sn1, sn2, ..., snm}
    function VerifyMLSAG(bytes32 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.m = I.length;
        if (P.length % v.m != 0) return false;
        
        v.n = P.length / v.m;
        if (signature.length != (v.m*v.n+1)) return false;
        
        //Allocate array for calculating c1
        uint256[] memory c = new uint256[](4*v.m+1);
        c[0] = uint256(msgHash);
        
        for (v.i = 0; v.i < v.m; v.i++) {
            v.ck = signature[0];                //extract c1
            v.keyImage = ExpandPoint(I[v.i]);   //extract key image
            
            //Calculate (n-1) ring segments (output scalar ck)
            for (v.j = 0; v.j < (v.n-1); v.j++) {
                v.index = v.m*v.j + v.i;
                v.point1 = ExpandPoint(P[v.index]); //extract public key
                v.ck = CalculateLinkableRingSegment(msgHash, v.ck, signature[v.index+1], v.point1, v.keyImage);
            }
            
            //Calculate last ring segment (output EC point input for c1 calculation)
            v.index = v.m*(v.n-1) + v.i;
            v.point1 = ExpandPoint(P[v.index]);
            (v.point1, v.point2) = CalculateLinkableRingSegment_NoHash(v.ck, signature[v.index+1], v.point1, v.keyImage);
            
            //Store input to c1 calculation
            v.index = v.i*2+1;
            c[v.index] = v.point1[0];
            c[v.index+1] = v.point1[1];
            c[v.index+2] = v.point2[0];
            c[v.index+3] = v.point2[1];
        }
        
        //Calculate c1 from c point array = {msgHash, L1x, L1y, R1x, R1y, L2x, L2y, R2x, R2y, ... , Lmx, Lmy, Rmx, Rmy}
        v.ck = Keccak256OfArray(c);
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
}
