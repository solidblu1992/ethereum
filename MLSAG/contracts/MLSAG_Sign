pragma solidity ^0.4.19;

import "./ECMath.sol";

contract MLSAG_Sign is ECMath {
    function MLSAG_Sign() public {
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
    
    //Sign SAG (Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //xk = known private key
    //i = index at which to put the known key
    //P = {P1, P2, ..., P(n-1)}
    //random = random numbers, need one for each public key (including the known one)
    function SignSAG(bytes32 msgHash, uint256 xk, uint256 i, uint256[] Pin, uint256[] random)
        public constant returns (uint256[] Pout, uint256[] signature)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.n = (Pin.length+1);
        if (random.length != v.n) return;
        
        //Make sure index is mod n
        i = i % v.n;
        
        //Initalize arrays
        Pout = new uint256[](v.n);
        signature = new uint256[](v.n+1);
        
        //Start ring
        v.ck = StartRing(msgHash, random[i]);
        
        //Move around ring
        for (v.i = ((i+1) % v.n); v.i != i; v.i = (v.i+1) % v.n) {
            //Store c0
            if (v.i == 0) {
                signature[0] = v.ck;
            }
            
            if (v.i > i) {
                v.point1 = ExpandPoint(Pin[v.i-1]); //extract public key
                Pout[v.i] = Pin[v.i-1]; //for usability only
            }
            else {
                v.point1 = ExpandPoint(Pin[v.i]); //extract public key
                Pout[v.i] = Pin[v.i]; //for usability only
            }
            
            v.ck = CalculateRingSegment(msgHash, v.ck, random[v.i], v.point1);
            
            //Store s value
            signature[v.i+1] = random[v.i];
        }
        
        //Store c0
        if (v.i == 0) {
            signature[0] = v.ck;
        }
        
        //Close Ring
        signature[i+1] = CompleteRing(random[i], v.ck, xk);
        
        Pout[i] = CompressPoint(ecMul(G1, xk)); //for usability only
    }
    
    //Sign LSAG (Linkable Spontaneous Ad-hoc Group Signature)
    //m = # of rings to sign at once
    //msgHash = hash of message signed by ring signature
    //xk = known private keys {x1, x2, ..., xm}
    //i = index at which to put the known keys {i1, i2, ..., im}
    //P = {P1, P2, ..., P(n-1)}
    //random = random numbers, need one for each public key (including the known one)
    function SignLSAG(bytes32 msgHash, uint256 xk, uint256 i, uint256[] Pin, uint256[] random)
        public constant returns (uint256 I, uint256[] Pout, uint256[] signature)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.n = (Pin.length+1);
        if (random.length != v.n) return;
        
        //Make sure index is mod n
        i = i % v.n;
        
        //Initalize arrays
        Pout = new uint256[](v.n);
        signature = new uint256[](v.n+1);
        
        //Generate key Image
        v.keyImage = CalculateKeyImageFromPrivKey(xk);
        I = CompressPoint(v.keyImage);
        
        //Start ring
        v.point2 = ecMul(G1, xk);
        v.ck = StartLinkableRing(msgHash, random[i], v.point2);
        Pout[i] = CompressPoint(v.point2); //for usability only
        
        //Move around ring
        for (v.i = ((i+1) % v.n); v.i != i; v.i = (v.i+1) % v.n) {
            //Store c0
            if (v.i == 0) {
                signature[0] = v.ck;
            }
            
            if (v.i > i) {
                v.point1 = ExpandPoint(Pin[v.i-1]); //extract public key
                Pout[v.i] = Pin[v.i-1]; //for usability only
            }
            else {
                v.point1 = ExpandPoint(Pin[v.i]); //extract public key
                Pout[v.i] = Pin[v.i]; //for usability only
            }
            
            v.ck = CalculateLinkableRingSegment(msgHash, v.ck, random[v.i], v.point1, v.keyImage);
            
            //Store s value
            signature[v.i+1] = random[v.i];
        }
        
        //Store c0
        if (v.i == 0) {
            signature[0] = v.ck;
        }
        
        //Close Ring
        signature[i+1] = CompleteRing(random[i], v.ck, xk);
    }

    //Sign MSAG (Multilayered Spontaneous Ad-hoc Group Signature, non-linkable)
    //m = number of keys in vector (# of inputs to be signed)
    //msgHash = hash of message signed by ring signature
    //xk = known private key
    //i = index at which to put the known key
    //P = {P11, P12, ..., P1m, P21, P22, ... P2m, P(n-1)1, P(n-1)2, ..., P(n-1)m}
    //random = random numbers, need one for each public key (including the known ones)
    function SignMSAG(uint256 m, bytes32 msgHash, uint256[] xk, uint256[] i, uint256[] Pin, uint256[] random)
        public constant returns (uint256[] Pout, uint256[] signature)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.m = m;
        if(xk.length != v.m) return;
        if(i.length != v.m) return;
        if (Pin.length % v.m != 0) return;
        v.n = (Pin.length / v.m)+1;
        if (random.length != (v.m*v.n)) return;
        
        //Initalize arrays
        Pout = new uint256[](v.m*v.n);
        signature = new uint256[](v.m*v.n+1);

        //Allocate array for calculating c1
        uint256[] memory c = new uint256[](2*v.m+1);
        c[0] = uint256(msgHash);
        
        //Calculate first half of each ring
        for (v.i = 0; v.i < v.m; v.i++) {
            //Make sure index is modulo n
            i[v.i] = i[v.i] % v.n;
            
            //Calculate (n-1) ring segments (output point for c1 calculation)
            v.j = ((i[v.i]+1) % v.n);
            
            //No segment to calculate, just need starting segment to point
            v.point2 = ecMul(G1, xk[v.i]);                  //for usability only
            Pout[v.m*i[v.i]+v.i] = CompressPoint(v.point2); //for usability only
                
            if(i[v.i] == (v.n-1)) {
                v.point1 = StartRing_NoHash(random[v.m*i[v.i]+v.i]);
            }
            else {
                //Start ring
                v.ck = StartRing(msgHash, random[v.m*i[v.i]+v.i]);
                
                for (; v.j < (v.n-1); v.j++) {
                    v.index = v.m*v.j + v.i;
                    
                    if (v.j > i[v.i]) {
                        v.point1 = ExpandPoint(Pin[v.index-v.m]); //extract public key
                        Pout[v.index] = Pin[v.index-v.m]; //for usability only
                    } else {
                        v.point1 = ExpandPoint(Pin[v.index]); //extract public key
                        Pout[v.index] = Pin[v.index]; //for usability only
                    }
                    
                    v.ck = CalculateRingSegment(msgHash, v.ck, random[v.index], v.point1);
                    
                    //Store s value
                    signature[v.index+1] = random[v.index];
                }
                
                //Calculate last ring segment (output EC point input for c1 calculation)
                v.index = v.m*(v.n-1) + v.i;
                v.point1 = ExpandPoint(Pin[v.index-v.m]);
                Pout[v.index] = Pin[v.index-v.m]; //for usability only
                
                v.point1 = CalculateRingSegment_NoHash(v.ck, random[v.index], v.point1);
                
                //Store s value
                signature[v.index+1] = random[v.index];
            }
            
            //Store input to c1 calculation
            v.index = v.i*2+1;
            c[v.index] = v.point1[0];
            c[v.index+1] = v.point1[1];
        }
        
        //Calculate c1 from c point array = {msgHash, P1x, P1y, P2x, P2y, , ... , Pmx, Pmy}
        signature[0] = Keccak256OfArray(c);
        
        //Calculate 2nd half of each ring
        for (v.i = 0; v.i < v.m; v.i++) {
            //Store c1
            v.ck = signature[0];            
            
            //Calculate remaining ring segments (output scalar ck)
            for (v.j = 0; v.j < i[v.i]; v.j++) {
                v.index = v.m*v.j + v.i;
                v.point1 = ExpandPoint(Pin[v.index]); //extract public key
                Pout[v.index] = Pin[v.index]; //for usability only
                
                v.ck = CalculateRingSegment(msgHash, v.ck, random[v.index], v.point1);
                
                //Store s value
                signature[v.index+1] = random[v.index];
            }
            
            //Close Ring
            v.index = v.m*i[v.i] + v.i;
            signature[v.index+1] = CompleteRing(random[v.index], v.ck, xk[v.i]);
        }
    }
    
    //Sign MLSAG (Multilayered Linkable Spontaneous Ad-hoc Group Signature)
    //m = number of keys in vector (# of inputs to be signed)
    //msgHash = hash of message signed by ring signature
    //xk = known private key
    //i = index at which to put the known key
    //P = {P11, P12, ..., P1m, P21, P22, ... P2m, P(n-1)1, P(n-1)2, ..., P(n-1)m}
    //random = random numbers, need one for each public key (including the known ones)
    function SignMLSAG(uint256 m, bytes32 msgHash, uint256[] xk, uint256[] i, uint256[] Pin, uint256[] random)
        public constant returns (uint256[] I, uint256[] Pout, uint256[] signature)
    {
        //Check input array lengths
        MLSAGVariables memory v;
        v.m = m;
        if(xk.length != v.m) return;
        if(i.length != v.m) return;
        if (Pin.length % v.m != 0) return;
        v.n = (Pin.length / v.m)+1;
        if (random.length != (v.m*v.n)) return;
        
        //Initalize arrays
        I = new uint256[](v.m);
        Pout = new uint256[](v.m*v.n);
        signature = new uint256[](v.m*v.n+1);

        //Allocate array for calculating c1
        uint256[] memory c = new uint256[](4*v.m+1);
        c[0] = uint256(msgHash);
        
        //Calculate first half of each ring
        for (v.i = 0; v.i < v.m; v.i++) {
            //Make sure index is modulo n
            i[v.i] = i[v.i] % v.n;
            
            //Extract key image
            v.keyImage = CalculateKeyImageFromPrivKey(xk[v.i]);
            I[v.i] = CompressPoint(v.keyImage);
            
            //Calculate (n-1) ring segments (output point for c1 calculation)
            v.j = ((i[v.i]+1) % v.n);
            
            //No segment to calculate, just need starting segment to point
            v.point2 = ecMul(G1, xk[v.i]);                  //for usability only
            Pout[v.m*i[v.i]+v.i] = CompressPoint(v.point2); //for usability only
                
            if(i[v.i] == (v.n-1)) {
                (v.point1, v.point2) = StartLinkableRing_NoHash(random[v.m*i[v.i]+v.i], ecMul(G1, xk[v.i]));
            }
            else {
                //Start ring
                v.ck = StartLinkableRing(msgHash, random[v.m*i[v.i]+v.i], ecMul(G1, xk[v.i]));
                
                for (; v.j < (v.n-1); v.j++) {
                    v.index = v.m*v.j + v.i;
                    
                    if (v.j > i[v.i]) {
                        v.point1 = ExpandPoint(Pin[v.index-v.m]); //extract public key
                        Pout[v.index] = Pin[v.index-v.m]; //for usability only
                    } else {
                        v.point1 = ExpandPoint(Pin[v.index]); //extract public key
                        Pout[v.index] = Pin[v.index]; //for usability only
                    }
                    
                    v.ck = CalculateLinkableRingSegment(msgHash, v.ck, random[v.index], v.point1, v.keyImage);
                    
                    //Store s value
                    signature[v.index+1] = random[v.index];
                }
                
                //Calculate last ring segment (output EC point input for c1 calculation)
                v.index = v.m*(v.n-1) + v.i;
                v.point1 = ExpandPoint(Pin[v.index-v.m]);
                Pout[v.index] = Pin[v.index-v.m]; //for usability only
                
                (v.point1, v.point2) = CalculateLinkableRingSegment_NoHash(v.ck, random[v.index], v.point1, v.keyImage);
                
                //Store s value
                signature[v.index+1] = random[v.index];
            }
            
            //Store input to c1 calculation
            v.index = v.i*4+1;
            c[v.index] = v.point1[0];
            c[v.index+1] = v.point1[1];
            c[v.index+2] = v.point2[0];
            c[v.index+3] = v.point2[1];
        }
        
        //Calculate c1 from c point array = {msgHash, P1x, P1y, P2x, P2y, , ... , Pmx, Pmy}
        signature[0] = Keccak256OfArray(c);
        
        //Calculate 2nd half of each ring
        for (v.i = 0; v.i < v.m; v.i++) {
            //Store c1
            v.ck = signature[0];    
            
            //Re-extract key image
            v.keyImage = ExpandPoint(I[v.i]);
            
            //Calculate remaining ring segments (output scalar ck)
            for (v.j = 0; v.j < i[v.i]; v.j++) {
                v.index = v.m*v.j + v.i;
                v.point1 = ExpandPoint(Pin[v.index]); //extract public key
                Pout[v.index] = Pin[v.index]; //for usability only
                
                v.ck = CalculateLinkableRingSegment(msgHash, v.ck, random[v.index], v.point1, v.keyImage);
                
                //Store s value
                signature[v.index+1] = random[v.index];
            }
            
            //Close Ring
            v.index = v.m*i[v.i] + v.i;
            signature[v.index+1] = CompleteRing(random[v.index], v.ck, xk[v.i]);
        }
    }
}
