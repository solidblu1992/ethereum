pragma solidity ^0.4.19;

import "./MLSAG_Algorithms.sol";

contract MLSAG_Sign is MLSAG_Algorithms {
    function MLSAG_Sign() public {
        //Constructor
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
