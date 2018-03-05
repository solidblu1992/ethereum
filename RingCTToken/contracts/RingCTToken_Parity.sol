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
		uint256[10] data
	);
	
	event DebugEventVar(
		uint256[] data
	);
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
        internal pure returns (uint256 h)
    {
        bytes32 b = keccak256(point[0], point[1]);
        h = uint256(b);
    }
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[2] p)
        internal constant returns (uint256[2] h)
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
	    uint256[3] encrypted_data
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

contract MLSAG_Algorithms is ECMath {
    function MLSAG_Algorithms() public {
        //Constructor
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
        uint256[2] point3;      //Expanded EC Point for general purpose use
        uint256[2] keyImage;    //Expanded EC Point representing key image
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
    	    mstore(p, add(mul(len, 0x20), 0x20)) //0x20 = 32; 32 bytes for array length + 32 bytes per uint256
    	    mstore(temp, keccak256(array, mload(p)))
    	}
    	
    	out = temp[0];
    }
	
    function Keccak256OfArray(uint128[] array)
        internal pure returns (uint256 out)
    {
        uint256 len = array.length;
        uint256[1] memory temp;
        
        //Construct c1 (store in c[0])
    	assembly {
    	    let p := mload(0x40)
    	    mstore(p, add(mul(len, 0x20), 0x20)) //0x20 = 32; 32 bytes for array length + 32 bytes per uint256
    	    mstore(temp, keccak256(array, mload(p)))
    	}
    	
    	out = temp[0];
    }
}

contract MLSAG_Verify is MLSAG_Algorithms {
    function MLSAG_Verify() public {
        //Constructor
    }
    
    //Verify SAG (Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //P = {P1x, P1y, P2x, P2y, ..., Pnx, Pny}
    //signature = {c1, s1, s2, ... , sn}
    function VerifySAG(bytes32 msgHash, uint256[] P, uint256[] signature)
        internal constant returns (bool success)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        if (P.length % 2 != 0) return false;
        v.n = (P.length / 2);
        if (signature.length != (v.n+1)) return false;
        
        v.ck = signature[0];            //extract c1
        for (v.i = 0; v.i < v.n; v.i++) {
            (v.point1[0], v.point1[1]) = (P[2*v.i], P[2*v.i+1]); //extract public key
            v.ck = CalculateRingSegment(msgHash, v.ck, signature[v.i+1], v.point1);
        }
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify SAG (Spontaneous Ad-hoc Group Signature, non-linkable)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //P = {P1, P2, ... , Pn}
    //signature = {c1, s1, s2, ... , sn}
    function VerifySAG_Compressed(bytes32 msgHash, uint256[] P, uint256[] signature)
        internal constant returns (bool success)
    {
        uint256[2] memory temp;
        uint256[] memory P_uncomp = new uint256[](P.length*2);
        
        for (uint256 i = 0; i < P.length; i++) {
            temp = ExpandPoint(P[i]);
            P_uncomp[2*i] = temp[0];
            P_uncomp[2*i+1] = temp[1];
        }
        
        return VerifySAG(msgHash, P_uncomp, signature);
    }
    
    //Verify LSAG (Linkable Spontaneous Ad-hoc Group Signature)
    //msgHash = hash of message signed by ring signature
    //I = {Ix, Iy}
    //P = {P1x, P1y, P2x, P2y, ..., Pnx, Pny}
    //signature = {c1, s1, s2, ..., sn}
    function VerifyLSAG(bytes32 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        internal constant returns (bool success)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        if (I.length != 2) return false;
        if (P.length % 2 != 0) return false;
        v.n = (P.length / 2);
        if (signature.length != (v.n+1)) return false;
        
        v.ck = signature[0];                            //extract c1
        (v.keyImage[0], v.keyImage[1]) = (I[0], I[1]);  //extract key image
        
        for (v.i = 0; v.i < v.n; v.i++) {
            (v.point1[0], v.point1[1]) = (P[2*v.i], P[2*v.i+1]); //extract public key
            v.ck = CalculateLinkableRingSegment(msgHash, v.ck, signature[v.i+1], v.point1, v.keyImage);
        }
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify LSAG (Linkable Spontaneous Ad-hoc Group Signature)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //I = key image (compressed EC point)
    //P = {P1, P2, ... , Pn}
    //signature = {c1, s1, s2, ... , sn}
    function VerifyLSAG_Compressed(bytes32 msgHash, uint256 I, uint256[] P, uint256[] signature)
        internal constant returns (bool success)
    {
        uint256[2] memory temp;
        uint256[] memory P_uncomp = new uint256[](P.length*2);
        uint256[] memory I_uncomp = new uint256[](2);
        
        uint256 i;
        for (i = 0; i < P.length; i++) {
            temp = ExpandPoint(P[i]);
            P_uncomp[2*i] = temp[0];
            P_uncomp[2*i+1] = temp[1];
        }
        
        temp = ExpandPoint(I);
        (I_uncomp[0], I_uncomp[1]) = (temp[0], temp[1]);
        
        return VerifyLSAG(msgHash, I_uncomp, P_uncomp, signature);
    }
    
    //Verify MSAG (Multilayered Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //P = { P11x, P11y, P12x, P12y, ..., P1mx, P1my,
    //      P21x, P21y, P22x, P22y, ..., P2mx, P2my,
    //      Pn1x, P1ny, Pn2x, P2ny, ..., Pnmx, Pnmy }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMSAG(uint256 m, bytes32 msgHash, uint256[] P, uint256[] signature)
        internal constant returns (bool success)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.m = m;
        if (P.length % (2*v.m) != 0) return false;
        
        v.n = P.length / (2*v.m);
        if (signature.length != (v.m*v.n+1)) return false;
        
        //Allocate array for calculating c1
        uint256[] memory c = new uint256[](2*v.m+1);
        c[0] = uint256(msgHash);
        
        for (v.i = 0; v.i < v.m; v.i++) {
            v.ck = signature[0];                //extract c1
            
            //Calculate (n-1) ring segments (output scalar ck)
            for (v.j = 0; v.j < (v.n-1); v.j++) {
                v.index = v.m*v.j + v.i;
                (v.point1[0], v.point1[1]) = (P[2*v.index], P[2*v.index+1]); //extract public key
                v.ck = CalculateRingSegment(msgHash, v.ck, signature[v.index+1], v.point1);
            }
            
            //Calculate last ring segment (output EC point input for c1 calculation)
            v.index = v.m*(v.n-1) + v.i;
            (v.point1[0], v.point1[1]) = (P[2*v.index], P[2*v.index+1]); 
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
    
    //Verify MSAG (Multilayered Spontaneous Ad-hoc Group Signature, non-linkable)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //P = { P11, P12, ..., P1m,
    //      P21, P22, ..., P2m,
    //      Pn1, Pn2, ..., Pnm }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMSAG_Compressed(uint256 m, bytes32 msgHash, uint256[] P, uint256[] signature)
        internal constant returns (bool success)
    {
        uint256[2] memory temp;
        uint256[] memory P_uncomp = new uint256[](P.length*2);
        
        uint256 i;
        for (i = 0; i < P.length; i++) {
            temp = ExpandPoint(P[i]);
            P_uncomp[2*i] = temp[0];
            P_uncomp[2*i+1] = temp[1];
        }
        
        return VerifyMSAG(m, msgHash, P_uncomp, signature);
    }
    
    //Verify MLSAG (Multilayered Linkable Spontaneous Ad-hoc Group Signature)
    //msgHash = hash of message signed by ring signature
    //I = { I1x, I1y, I2x, I2y, ..., Imx, Imy }
    //P = { P11x, P11y, P12x, P12y, ..., P1mx, P1my,
    //      P21x, P21y, P22x, P22y, ..., P2mx, P2my,
    //      Pn1x, P1ny, Pn2x, P2ny, ..., Pnmx, Pnmy }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMLSAG(bytes32 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        internal constant returns (bool success)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        if(I.length % 2 != 0) return false;
        v.m = (I.length / 2);
        if (P.length % (2*v.m) != 0) return false;
        
        v.n = P.length / (2*v.m);
        if (signature.length != (v.m*v.n+1)) return false;
        
        //Allocate array for calculating c1
        uint256[] memory c = new uint256[](4*v.m+1);
        c[0] = uint256(msgHash);
        
        for (v.i = 0; v.i < v.m; v.i++) {
            v.ck = signature[0];                //extract c1
            v.keyImage = [I[2*v.i], I[2*v.i+1]]; //extract key image
            
            //Calculate (n-1) ring segments (output scalar ck)
            for (v.j = 0; v.j < (v.n-1); v.j++) {
                v.index = v.m*v.j + v.i;
                v.point1 = [P[2*v.index], P[2*v.index+1]]; //extract public key
                v.ck = CalculateLinkableRingSegment(msgHash, v.ck, signature[v.index+1], v.point1, v.keyImage);
            }
            
            //Calculate last ring segment (output EC point input for c1 calculation)
            v.index = v.m*(v.n-1) + v.i;
            v.point1 = [P[2*v.index], P[2*v.index+1]]; //extract public key
            (v.point1, v.point2) = CalculateLinkableRingSegment_NoHash(v.ck, signature[v.index+1], v.point1, v.keyImage);
            
            //Store input to c1 calculation
            v.index = v.i*4+1;
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
    
    //Verify MLSAG (Multilayered Linkable Spontaneous Ad-hoc Group Signature)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //I = { I1, I2, ..., Im }
    //P = { P11, P12, ..., P1m,
    //      P21, P22, ..., P2m,
    //      Pn1, Pn2, ..., Pnm }
    //signature = {c1, s11, s12, ..., s1m, s21, s22, ..., s2m, ..., sn1, sn2, ..., snm}
    function VerifyMLSAG_Compressed(bytes32 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        internal constant returns (bool success)
    {
        uint256[2] memory temp;
        uint256[] memory P_uncomp = new uint256[](P.length*2);
        uint256[] memory I_uncomp = new uint256[](I.length*2);
        
        uint256 i;
        for (i = 0; i < P.length; i++) {
            temp = ExpandPoint(P[i]);
            P_uncomp[2*i] = temp[0];
            P_uncomp[2*i+1] = temp[1];
        }
        
        for (i = 0; i < I.length; i++) {
            temp = ExpandPoint(I[i]);
            I_uncomp[2*i] = temp[0];
            I_uncomp[2*i+1] = temp[1];
        }
        
        return VerifyMLSAG(msgHash, I_uncomp, P_uncomp, signature);
    }
}

contract RingCTToken is MLSAG_Verify, StealthTransaction {
    //Storage of Token Balances
	uint256 public totalSupply;
	
	//Mapping of EC Public Key to Pedersen Commitment of Value
	mapping (uint256 => uint256) public token_committed_balance;
	
	event Withdrawal(
	    address _to,
	    uint256 _value
	);
	
	event PCRangeProven(
	    uint256 _power10,
	    uint256 _offset,
	    uint256 _commitment
	);
	
	//Mapping of EC Public Key to encrypted data (e.g. value and blinding factor)
	//mapping (uint256 => uint256) public encrypted_data0;
	//mapping (uint256 => uint256) public encrypted_data1;
	//mapping (uint256 => uint256) public encrypted_data2;
	
	//Mapping of uint256 index (0...pub_key_count-1) to known public keys (for finding mix in keys)
	mapping (uint256 => uint256) public pub_keys_by_index;
	uint256 public pub_key_count;
    
	//Storage array of commitments which have been proven to be positive
	mapping (uint256 => bool) public balance_positive;
	
	//Storage array for key images which have been used
	mapping (uint256 => bool) public key_images;
    
    function RingCTToken() public {
        //Constructor Code
    }
    
    //Transaction Functions
	//Deposit Ether as CT tokens to the specified alt_bn_128 public key
	//NOTE: this deposited amount will NOT be confidential, initial blinding factor = 0
	function Deposit(uint256 dest_pub_key, uint256 dhe_point)
    	payable public
	{
    	//Incoming Value must be non-zero
    	require(msg.value > 0);
    	
    	//Destination Public Key must be unused
    	require(token_committed_balance[dest_pub_key] == 0);
    	
    	//Generate pedersen commitment and add to existing balance
    	token_committed_balance[dest_pub_key] = CompressPoint(ecMul(H, msg.value));
    	pub_keys_by_index[pub_key_count] = dest_pub_key;
    	pub_key_count++;
    
    	//Store DHE point if not already in dhe point set
    	if (!stx_dhepoints_reverse[dhe_point]) {
        	stx_dhe_points[stx_dhe_point_count] = dhe_point;
        	stx_dhepoints_reverse[dhe_point] = true;
        	stx_dhe_point_count++;
    	}
    	
    	        	
    	//Store non-encrypted value (bf and iv = 0)
    	//encrypted_data0[dest_pub_key] = msg.value;
    	//encrypted_data1[dest_pub_key] = 0;
    	//encrypted_data_iv[dest_pub_key] = 0;
    	
    	//Log new stealth transaction
    	NewStealthTx(dest_pub_key, dhe_point, [msg.value, 0, 0]);
    	
    	//Update global token supply
    	totalSupply += msg.value;
	}
	
	//Deposit Ether as CT tokens to the specified alt_bn_128 public keys
	//This function allows multiple deposits at onces
	//NOTE: this deposited amount will NOT be confidential, initial blinding factor = 0
	function DepositMultiple(uint256[] dest_pub_keys, uint256[] dhe_points, uint256[] values)
	    payable public
    {
        //Incoming Value must be non-zero
        require(msg.value > 0);
        
        //One value per public key
        require(dest_pub_keys.length == values.length);
    	
    	//Destination Public Keys must be unused, and
    	//Values must add up to msg.value and each must not excede msg.value (prevent overflow)
    	uint256 i;
    	uint256 v;
    	for (i = 0; i < dest_pub_keys.length; i++) {
    	    require(token_committed_balance[dest_pub_keys[i]] == 0);
    	    
    	    require(values[i] <= msg.value);
    	    v = v + values[i];
    	}
    	
    	require(v == msg.value);

        //Create Tokens
    	for (i = 0; i < dest_pub_keys.length; i++) {
        	//Generate pedersen commitment and add to existing balance
        	token_committed_balance[dest_pub_keys[i]] = CompressPoint(ecMul(H, values[i]));
        	pub_keys_by_index[pub_key_count] = dest_pub_keys[i];
        	pub_key_count++;
        
        	//Store DHE point if not already in dhe point set
        	if (!stx_dhepoints_reverse[dhe_points[i]]) {
            	//Store DHE point 
            	stx_dhe_points[stx_dhe_point_count] = dhe_points[i];
            	stx_dhepoints_reverse[dhe_points[i]] = true;
            	stx_dhe_point_count++;
        	}
        	
        	//Store non-encrypted value (bf and iv = 0)
			//encrypted_data0[dest_pub_keys[i]] = values[i];
			//encrypted_data1[dest_pub_keys[i]] = 0;
			//encrypted_data_iv[dest_pub_keys[i]] = 0;
    	
    	    //Log new stealth transaction
        	NewStealthTx(dest_pub_keys[i], dhe_points[i], [values[i], 0, 0]);
    	}
    	
    	//Update global token supply
    	totalSupply += msg.value;
    }
    
    //Send - sends tokens via the Ring CT protocol
	//Verifies an MLSAG ring signature over a set of public keys and the summation of their commitments and a set of output commitments.
	//If successful, a new set of public keys (UTXO's) will be generated with masked values (pedersen commitments).  Each of these
	//also has a DHE point so that the intended receiver is able to calculate the stealth address.
	//
	//dest_pub_keys		= set of expanded EC points representing new UTXO public keys
	//values			= set of pedersen commitments (expanded EC points) representing the new values (masked) for the above UTXO's
	//dest_dhe_points	= set of DHE points to be used by the receivers to calculate the new UTXO public keys with their stealth addresses
	//encrypted_data    = uint256[3] for each output representing encrypted data which can be included.  The contract will not check this data,
	//                    but this can be an easy way to pass on the value and blinding factor of the new commitment to the receiver.
	//I					= key images for the MLSAG	{ I1x, I1y, I2x, I2y, ..., I(m+1)x, I(m+1)y }
	//input_pub_keys	= public key set for the MLSAG, each point is expanded	{	P11x, P11y, P12x, P12y, ..., P1mx, P1my,
	//																				P21x, P21y, P22x, P22y, ..., P2mx, P2my,
	//																				...
	//																				Pn1x, Pn1y, Pn2x, Pn2y, ..., Pnmx, Pnmy	}
	//signature			= signature for the MLSAG {	c1, s11, s12, ..., s1(m+1),
	//													s21, s22, ..., s2(m+1),
	//													...
	//													sn1, sn2, ..., sn(m+1)	}
	//
	//Note 1: m refers to the number of EC points in each public key vector (columns/2 of input_pub_keys).
	//		  n refers to the number of public key vectors (rows of input_pub_keys)
	//		  The actual MLSAG signs an array of n*(m+1) points as the last column is a summation of each public key in the vector
	//		  as well as each input commitment in the vector and the summation of all output commitments (sigma(Pj) + sigma(Cinj) - sigma(Couti))
	//Note 2: See https://eprint.iacr.org/2015/1098 for more details on RingCT
    function Send(  uint256[] dest_pub_keys, uint256[] values, uint256[] dest_dhe_points, uint256[] encrypted_data,
                    uint256[] I, uint256[] input_pub_keys, uint256[] signature)
        public returns (bool success)
    {
        //Need at least one destination
        if (dest_pub_keys.length == 0) return false;
        if (dest_pub_keys.length % 2 != 0) return false;
        
        //Need same number of values and dhe points
        if (values.length != dest_pub_keys.length) return false;
        if (dest_dhe_points.length != dest_pub_keys.length) return false;
		if (encrypted_data.length != ((dest_pub_keys.length/2)*3)) return false;
        
        //Check other array lengths
        if (I.length % 2 != 0) return false;
        
        MLSAGVariables memory v;
        v.m = (I.length / 2);
		
		if (v.m < 2) return false;
		v.m = v.m - 1;
        
        if (input_pub_keys.length % (2*v.m) != 0) return false;
        v.n = input_pub_keys.length / (2*v.m);
        
        //Verify output commitments have been proven positive
        for (v.i = 0; v.i < (values.length / 2); v.i++) {
            v.point1 = [values[2*v.i], values[2*v.i+1]];
            if (!balance_positive[CompressPoint(v.point1)]) return false;
        }
		
		//Verify key images are unused
        for (v.i = 0; v.i < (v.m+1); v.i++) {
            v.keyImage[0] = CompressPoint([I[2*v.i], I[2*v.i+1]]);
            if (key_images[v.keyImage[0]]) return false;
        }
        
		//Create last two columns of MLSAG public key set (sigma{input_pub_keys} + sigma{input_commitments} - sigma{output_commitments}
		//Calculate negative of total destination commitment
		//Note, here keyImage is used, but this is just because another EC point in memory is needed (not an actual key image)
        v.keyImage = [values[0], values[1]];
        for (v.i = 1; v.i < (values.length / 2); v.i++) {
            v.keyImage = ecAdd(v.keyImage, [values[2*v.i], values[2*v.i+1]]);
        }
        v.keyImage[1] = PCurve - v.keyImage[1];	//Negate EC Point
		
        uint256[] memory P = new uint256[](2*v.n);
		for (v.i = 0; v.i < v.n; v.i++) {
			//Sum input public keys and their commitments			
			for (v.j = 0; v.j < v.m; v.j++) {
				v.index = 2*(v.m*v.i+v.j);
				v.point1 = [input_pub_keys[v.index], input_pub_keys[v.index+1]];
				v.point2[0] = CompressPoint(v.point1);
				v.point2[0] = token_committed_balance[v.point2[0]];
				if (v.point2[0] == 0) return false; //No commitment found!
				
				v.point2 = ExpandPoint(v.point2[0]);
				
				if (v.j == 0) {
					v.point3 = ecAdd(v.point1, v.point2);
				}
				else {
					v.point3 = ecAdd(v.point3, v.point1);
					v.point3 = ecAdd(v.point3, v.point2);
				}
			}
			
			//Add negated output commitments
			v.point3 = ecAdd(v.point3, v.keyImage);
			
			//Store point 3 into P
			(P[2*v.i], P[2*v.i+1]) = (v.point3[0], v.point3[1]);
		}
		
        //Combine original public key set with new summations
		//Note: this resizes P from (2*v.n) to (2*v.n*(v.m+1))
		//P(before) =	{	P11x, P11y, P12x, P12y, ..., P1mx, P1my,
		//					P21x, P21y, P22x, P22y, ..., P2mx, P2my,
		//					...
		//					Pn1x, Pn1y, Pn2x, Pn2y, ..., Pnmx, Pnmy	}
		//
		//P(after) =	{	P11x, P11y, P12x, P12y, ..., P1mx, P1my, sigma(P1j) + sigma(C1j) - sigma(Ciout),
		//					P21x, P21y, P22x, P22y, ..., P2mx, P2my, sigma(P2j) + sigma(C2j) - sigma(Ciout),
		//					...
		//					Pn1x, Pn1y, Pn2x, Pn2y, ..., Pnmx, Pnmy, sigma(Pnj) + sigma(Pnj) - sigma(Ciout)	}
		P = AddColumnsToArray(input_pub_keys, (2*v.m), P, 2);
        
        //Verify ring signature (MLSAG)
        if (!VerifyMLSAG(HashSendMsg(dest_pub_keys, values, dest_dhe_points, encrypted_data), I, P, signature)) return false;
    
        //Store key images (point of no return, all returns need to be reverts after this point)
        for (v.i = 0; v.i < (I.length / 2); v.i++) {
            v.point1 = [I[2*v.i], I[2*v.i+1]];
            key_images[CompressPoint(v.point1)] = true;
        }
		
		//Generate new UTXO's
		for (v.i = 0; v.i < (dest_pub_keys.length / 2); v.i++) {
			v.index = 2*v.i;
			v.point1 = [dest_pub_keys[v.index], dest_pub_keys[v.index+1]];
			v.point1[0] = CompressPoint(v.point1);
			
			v.point2 = [values[v.index], values[v.index+1]];
			v.point2[0] = CompressPoint(v.point2);
			
			v.point3 = [dest_dhe_points[v.index], dest_dhe_points[v.index+1]];
			v.point3[0] = CompressPoint(v.point3);
			
			token_committed_balance[v.point1[0]] = v.point2[0];	//Store output commitment			
			pub_keys_by_index[pub_key_count] = v.point1[0];		//Store public key
			pub_key_count++;
			
			//Publish DHE point if not already in published set
			if (!stx_dhepoints_reverse[v.point3[0]]) {
    			stx_dhe_points[stx_dhe_point_count] = v.point3[0];			//Store DHE point (for calculating stealth address)
    			stx_dhepoints_reverse[v.point3[0]] = true;
    			stx_dhe_point_count++;
			}
			
			//Store encrypted data and iv
			//encrypted_data0[v.point1[0]] = encrypted_data[3*v.i];
			//encrypted_data1[v.point1[0]] = encrypted_data[3*v.i+1];
			//encrypted_data2[v.point1[0]] = encrypted_data[3*v.i+2];
			
			//Log new stealth transaction
			NewStealthTx(v.point1[0], v.point3[0], [encrypted_data[3*v.i], encrypted_data[3*v.i+1], encrypted_data[3*v.i+2]]);
		}
		
		return true;
    }
    
    	//Withdraw - destorys tokens via RingCT and redeems them for ETH
	//Verifies an MLSAG ring signature over a set of public keys and the summation of their commitments and a set of output commitments.
	//If successful, a new set of public keys (UTXO's) will be generated with masked values (pedersen commitments).  Each of these
	//also has a DHE point so that the intended receiver is able to calculate the stealth address.  Additionally, the redeemed tokens
	//will be destoryed and sent to an ETH address for their ETH value
	//
	//redeem_eth_address		= ETH address to send ETH value of redeemed tokens to
	//redeem_value				= total value masked by UTXO's to redeem
	//redeem_blinding_factor	= total blinding factor of UTXO's to redeem
	//See Send(...) for other inputs
	//
	//Note: Every withdrawal must create at least one new masked UTXO, otherwise the privacy of all spent input public keys are compromised.
	//		(The network will know which key vector has been spent.)  At a minimum, one new UTXO may be created with a commitment to zero.
    function Withdraw(  address redeem_eth_address, uint256 redeem_value, uint256 redeem_blinding_factor,
						uint256[] dest_pub_keys, uint256[] values, uint256[] dest_dhe_points, uint256[] encrypted_data,
						uint256[] I, uint256[] input_pub_keys, uint256[] signature)
        public returns (bool success)
    {
        //Need at least one destination
        if (dest_pub_keys.length == 0) return false;
        if (dest_pub_keys.length % 2 != 0) return false;
        
        //Need same number of values and dhe points
        if (values.length != dest_pub_keys.length) return false;
        if (dest_dhe_points.length != dest_pub_keys.length) return false;
		if (encrypted_data.length != ((dest_pub_keys.length/2)*3)) return false;
        
        //Check other array lengths
        if (I.length % 2 != 0) return false;
        
        MLSAGVariables memory v;
        v.m = (I.length / 2);
		
		if (v.m < 2) return false;
		v.m = v.m - 1;
        
        if (input_pub_keys.length % (2*v.m) != 0) return false;
        v.n = input_pub_keys.length / (2*v.m);
        
        //Verify key images are unused
        for (v.i = 0; v.i < (v.m+1); v.i++) {
            v.keyImage[0] = CompressPoint([I[2*v.i], I[2*v.i+1]]);
            if (key_images[v.keyImage[0]]) return false;
        }
        
        //Verify output commitments have been proven positive
        for (v.i = 0; v.i < (values.length / 2); v.i++) {
            v.point1 = [values[2*v.i], values[2*v.i+1]];
            if (!balance_positive[CompressPoint(v.point1)]) return false;
        }
		
		//Verify key images are unused
        for (v.i = 0; v.i < v.m; v.i++) {
            v.keyImage[0] = CompressPoint([I[2*v.i], I[2*v.i+1]]);
            if (key_images[v.keyImage[0]]) return false;
        }
        
		//Create last two columns of MLSAG public key set (sigma{input_pub_keys} + sigma{input_commitments} - sigma{output_commitments  + redeem_commitment}
		//Calculate negative of total destination commitment
		//Note, here keyImage is used, but this is just because another EC point in memory is needed (not an actual key image)
        v.keyImage = [values[0], values[1]];
        for (v.i = 1; v.i < (values.length / 2); v.i++) {
            v.keyImage = ecAdd(v.keyImage, [values[2*v.i], values[2*v.i+1]]);
        }
		
		//Add unmasked value as a commitment
		v.keyImage = ecAdd(v.keyImage, ecMul(G1, redeem_blinding_factor));
		v.keyImage = ecAdd(v.keyImage, ecMul(H, redeem_value));
        v.keyImage[1] = PCurve - v.keyImage[1];	//Negate EC Point
		
        uint256[] memory P = new uint256[](2*v.n);
		for (v.i = 0; v.i < v.n; v.i++) {
			//Sum input public keys and their commitments			
			for (v.j = 0; v.j < v.m; v.j++) {
				v.index = 2*(v.m*v.i+v.j);
				v.point1 = [input_pub_keys[v.index], input_pub_keys[v.index+1]];
				v.point2[0] = CompressPoint(v.point1);
				v.point2[0] = token_committed_balance[v.point2[0]];
				if (v.point2[0] == 0) return false; //No commitment found!
				
				v.point2 = ExpandPoint(v.point2[0]);
				
				if (v.j == 0) {
					v.point3 = ecAdd(v.point1, v.point2);
				}
				else {
					v.point3 = ecAdd(v.point3, v.point1);
					v.point3 = ecAdd(v.point3, v.point2);
				}
			}
			
			//Add negated output commitments
			v.point3 = ecAdd(v.point3, v.keyImage);
			
			//Store point 3 into P
			(P[2*v.i], P[2*v.i+1]) = (v.point3[0], v.point3[1]);
		}
		
        //Combine original public key set with new summations
		//Note: this resizes P from (2*v.n) to (2*v.n*(v.m+1))
		//P(before) =	{	P11x, P11y, P12x, P12y, ..., P1mx, P1my,
		//					P21x, P21y, P22x, P22y, ..., P2mx, P2my,
		//					...
		//					Pn1x, Pn1y, Pn2x, Pn2y, ..., Pnmx, Pnmy	}
		//
		//P(after) =	{	P11x, P11y, P12x, P12y, ..., P1mx, P1my, sigma(P1j) + sigma(C1j) - sigma(Ciout),
		//					P21x, P21y, P22x, P22y, ..., P2mx, P2my, sigma(P2j) + sigma(C2j) - sigma(Ciout),
		//					...
		//					Pn1x, Pn1y, Pn2x, Pn2y, ..., Pnmx, Pnmy, sigma(Pnj) + sigma(Pnj) - sigma(Ciout)	}
		P = AddColumnsToArray(input_pub_keys, (2*v.m), P, 2);
        
        //Verify ring signature (MLSAG)
        if (!VerifyMLSAG(HashWithdrawMsg(redeem_eth_address, redeem_value, redeem_blinding_factor, dest_pub_keys, values, dest_dhe_points), I, P, signature)) return false;
    
        //Store key images (point of no return, all returns need to be reverts after this point)
        for (v.i = 0; v.i < (I.length / 2); v.i++) {
            v.point1 = [I[2*v.i], I[2*v.i+1]];
            key_images[CompressPoint(v.point1)] = true;
        }
		
		//Generate new UTXO's
		for (v.i = 0; v.i < (dest_pub_keys.length / 2); v.i++) {
			v.index = 2*v.i;
			v.point1 = [dest_pub_keys[v.index], dest_pub_keys[v.index+1]];
			v.point1[0] = CompressPoint(v.point1);
			
			v.point2 = [values[v.index], values[v.index+1]];
			v.point2[0] = CompressPoint(v.point2);
			
			v.point3 = [dest_dhe_points[v.index], dest_dhe_points[v.index+1]];
			v.point3[0] = CompressPoint(v.point3);
			
			token_committed_balance[v.point1[0]] = v.point2[0];	//Store output commitment			
			pub_keys_by_index[pub_key_count] = v.point1[0];		//Store public key
			pub_key_count++;
			
			//Publish DHE point if not already in published set
			if (!stx_dhepoints_reverse[v.point3[0]]) {
    			stx_dhe_points[stx_dhe_point_count] = v.point3[0];			//Store DHE point (for calculating stealth address)
    			stx_dhepoints_reverse[v.point3[0]] = true;
    			stx_dhe_point_count++;
			}
			
		   //Store encrypted data and iv
			//encrypted_data0[v.point1[0]] = encrypted_data[3*v.i];
			//encrypted_data1[v.point1[0]] = encrypted_data[3*v.i+1];
			//encrypted_data2[v.point1[0]] = encrypted_data[3*v.i+2];
			
			//Log new stealth transaction
			NewStealthTx(v.point1[0], v.point3[0], [encrypted_data[3*v.i], encrypted_data[3*v.i+1], encrypted_data[3*v.i+2]]);
		}
		
		//Send redeemed value
		redeem_eth_address.transfer(redeem_value);
		
		//Log Withdrawal
		Withdrawal(redeem_eth_address, redeem_value);
		
		return true;
    }
	
    //CT Functions
    //CTProvePositive
    //total_commit = uncompressed EC Point for total hidden value (pederen commitment)
    //power10 = additional scalar to be applied to bitwise commitments (public information)
    //offset = additional offset to be added to bitwise commitments (public information)
    //bit_commits = uncompressed EC Points representing bitwise pedersen commitments
    //signature = borromean ring signature on bitwise commitments and counter commitments (MSAG, n = 4, m = # of bits)
    //          = { c0, s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  s31, s32, ..., s3m,
    //                  s41, s42, ..., s4m  }
    //NOTE: Signature should be made over the following "public keys":
    //  P = {   C1,    C2,    ..., Cm,
    //          C1',   C2',   ..., Cm',
    //          C1'',  C2'',  ..., Cm'',
    //          C1''', C2''', ..., Cm''' }
    function CTProvePositive(uint256[2] total_commit, uint256 power10, uint256 offset, uint256[] bit_commits, uint256[] signature)
        public returns (bool success)
    {
        //Get number of bits to prove
        if(bit_commits.length % 2 != 0) return false;
        uint256 bits = (bit_commits.length / 2);
        if (bits == 0) return false;
        
        //Check that maximum committed value cannot be negative (over NCurve / 2)
        if (power10 > 75) return false;
        if (offset > (NCurve / 2)) return false;
        if (((4**bits-1)*(10**power10) + offset) > (NCurve / 2)) return false;
        
        //Check for proper signature size
        if (signature.length != (4*bits+1)) return false;
        
        //Check that bitwise commitments add up to total commitment
        uint256 i;
        uint256[2] memory temp1;
        (temp1[0], temp1[1]) = (bit_commits[0], bit_commits[1]);
        for (i = 1; i < bits; i++) {
            temp1 = ecAdd(temp1, [bit_commits[2*i], bit_commits[2*i+1]]);
        }
		
		if (offset > 0) {
			temp1 = ecAdd(temp1, ecMul(H, offset));
        }
		
        if ( (total_commit[0] != temp1[0]) || (total_commit[1] != temp1[1]) ) return false;
        
        //Build Public Keys for Signature Verification
        uint256[] memory P = new uint256[](8*bits);
        uint256[2] memory temp2;
        for (i = 0; i < bits; i++) {
            //Store bitwise commitment
            temp1 = [bit_commits[2*i], bit_commits[2*i+1]];
            (P[2*i], P[2*i+1]) = (temp1[0], temp1[1]);
            
            //Calculate -(4**bit)*(10**power10)*H
            temp2 = ecMul(H, (4**i)*(10**power10));
            temp2[1] = PCurve - temp2[1];
            
            //Calculate 1st counter commitment: C' = C - (4**bit)*(10**power10)*H
            temp1 = ecAdd(temp1, temp2);
            (P[2*(i+bits)], P[2*(i+bits)+1]) = (temp1[0], temp1[1]);
            
            //Calculate 2nd counter commitment: C'' = C - 2*(4**bit)*(10**power10)*H
            temp1 = ecAdd(temp1, temp2);
            (P[2*(i+2*bits)], P[2*(i+2*bits)+1]) = (temp1[0], temp1[1]);
            
            //Calculate 3rd counter commitment: C''' = C - 3*(4**bit)*(10**power10)*H
            temp1 = ecAdd(temp1, temp2);
            (P[2*(i+3*bits)], P[2*(i+3*bits)+1]) = (temp1[0], temp1[1]);
        }
        
        //Verify Signature
        total_commit[0] = CompressPoint(total_commit);
        success = VerifyMSAG(bits, bytes32(CompressPoint(total_commit)), P, signature);
        
        if (success) {
            balance_positive[total_commit[0]] = true;
            PCRangeProven(power10, offset, total_commit[0]);
        }
    }
    
    //Utility Functions
    function HashSendMsg(uint256[] dest_pub_keys, uint256[] output_commitments, uint256[] dest_dhe_points, uint256[] encrypted_data)
        public pure returns (bytes32 msgHash)
    {
        msgHash = keccak256(Keccak256OfArray(dest_pub_keys), Keccak256OfArray(output_commitments), Keccak256OfArray(dest_dhe_points), Keccak256OfArray(encrypted_data));
    }
	
	function HashWithdrawMsg(	address ethAddress, uint256 value, uint256 bf,
								uint256[] dest_pub_keys, uint256[] output_commitments, uint256[] dest_dhe_points)
		public pure returns (bytes32 msgHash)
	{
		msgHash = keccak256(ethAddress, value, bf, Keccak256OfArray(dest_pub_keys), Keccak256OfArray(output_commitments), Keccak256OfArray(dest_dhe_points));
	}
	
	//AddColumnsToArray
	//Combines two arrays into one (joining them at the columns)
	//e.g.
	//baseArray = 	{	a, b, c, d,
	//					e, f, g, h,
	//					i, j, k, m	}
	//baseWidth = 4 (# of columns)
	//newColumns =	{	1, 2,
	//					3, 4,
	//					5, 6	}
	//newWidth = 2 (# of columns)
	//-----------------------------
	//outArray =	{	a, b, c, d, 1, 2,
	//					e, f, g, h, 3, 4,
	//					i, j, k, m, 5, 6	}
	function AddColumnsToArray(uint256[] baseArray, uint256 baseWidth, uint256[] newColumns, uint256 newWidth)
		public pure returns (uint256[] outArray)
	{
		//Check Array dimensions
		if (baseArray.length % baseWidth != 0) return;
		if (newColumns.length % newWidth != 0) return;
		
		uint256 n = baseArray.length / baseWidth;
		if ( (newColumns.length / newWidth) != n ) return;
		
		//Create output Array
		outArray = new uint256[](baseArray.length + newColumns.length);
		uint256 outWidth = baseWidth + newWidth;
		
		//Assemble new array
		uint256 i;
		uint256 j;
		for (i = 0; i < n; i++) {
			for (j = 0; j < baseWidth; j++) {
				//Copy over Base Array
				outArray[outWidth*i + j] = baseArray[baseWidth*i + j];
			}
			
			for (j = 0; j < newWidth; j++) {
				//Copy over New Array
				outArray[outWidth*i + baseWidth + j] = newColumns[newWidth*i + j];
			}
		}
	}
}