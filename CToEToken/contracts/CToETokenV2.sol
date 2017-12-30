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

contract ECMath {
	//alt_bn128 constants
	uint256[2] internal G1;
	uint256[2] internal H;
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

    //Ring Signature Functions
    function CalculateRingSegment_NoHash(uint256 ck, uint256[2] Pk, uint256 sk)
        internal constant returns (uint256[2] Pout)
    {
        uint256[2] memory temp1;
        temp1 = ecMul(Pk, ck);
        Pout = ecMul(G1, sk);
        Pout = ecAdd(temp1, Pout);
    }
    
    function CalculateRingSegment(uint256 ck, uint256[2] Pk, uint256 sk)
        internal constant returns (uint256 ckp)
    {
        ckp = HashOfPoint(CalculateRingSegment_NoHash(ck, Pk, sk));
    }
    
    //CompleteRing = (alpha - c*xk) % N
    function CompleteRing(uint256 alpha, uint256 c, uint256 xk)
        internal pure returns (uint256 s)
    {
        s = mulmod(c, xk, NCurve);
        s = NCurve - s;
        s = addmod(alpha, s, NCurve);        
    }
}

contract CToETokenAlgorithms is ECMath, Debuggable {
    function CToETokenAlgorithms() public {
        //Constructor Code
    }
    
    //Determine how many bits are needed to represent value from 0 to 32.
	function getBitSize(uint256 value)
    	public pure returns (uint8 bits)
	{
    	uint256 bit = 3;
    	
    	while (value != 0) {
    	    bits++;
    	    value = value & ~bit;
    	    bit = bit << 2;
    	}
	}
	
	//Determine possible range for given CT Range Proof and parameters
	function getCTRange(uint256 power, uint256 offset, uint256 bits)
	    public pure returns (uint256 low, uint256 high, uint256 possible_values)
	{
	    possible_values = (4**bits);
	    low = offset;
	    high = (4**bits)*(10**power) + offset;
	}
	
	//Determine how many random numbers must be supplied for a given value
	function getRequiredRandomNumbers(uint256 value)
	    public pure returns (uint256 random_count)
	{
	    random_count = 5*getBitSize(value)-1;
	}
    
    //function: CTGenerateTx
    //  description: Creates Pedersen Commitment set and Range Proof to be verified on blockchain
    //  notes:
    //      N   - the number of "base4 bits" in the commitment
    //            e.g. 19 can be represented by 3 base4 bits: 3*(4^0) + 0*(4^1) + 1*(4^2)
    //  inputs:
    //      ip (uint256[])      - total set of all input parameters
    //          ip[0]           - value to be hidden in pedersen commitment
    //          ip[1]           - power of 10 to be added to committed value (publicly known)
    //          ip[2]           - offset to be added to committed value (publicly known)
    //          ip[3]           - desired total blinding factor (all other blinding factors will add up to this one)
    //          ip[4 ... 5N+2]  - random numbers (need a total of 5N-1 random numbers: N-1 for blinding factors and 4N for range proof)
    //  outputs:
    //      out (uint256[])      - transaction data ready to be processed by the contract
    //          out[0]           - power of 10 to be added to committed value (publicly known)
    //          out[1]           - offset to be added to committed value (publicly known)
    //          out[2]           - total pedersen commitment (compresed EC Point)
    //          out[3 ... N+1]   - base4 bit pedersen commitments (minus the last one which is implied, total of N-1 compressed EC Points)
    //          out[N+2]         - c0 for borromean ring signatures (start of range proof)
    //          out[N+3 ... 5N+2]- sk values for borromean ring signatures (4 for each base4 bit)
    function CTGenerateTx(uint256[] ip)
        public constant returns (uint256[] out)
    {
        //Check for proper number of input parameters (5N+3), must be at least one bit
        require( (ip.length >= 8) );
        require( (ip.length - 3) % 5 == 0 );
        uint256 N = (ip.length - 3) / 5 ;
        
        //Initialize out
        out = new uint256[](ip.length);
        
        //Temporary Registers
        uint256[2] memory temp1;
        uint256[2] memory temp2;
        uint256 i;
        uint256 lastBF;
        
        //Memory for uncompressed pedersen commitments
        uint256[] memory PC = new uint256[](2*N+2);
    
        //Encodes which pedersen commitment the blinding factor is a key to for the range proof
        uint8[] memory pkKnown = new uint8[](N);
        
        //Pass on power of 10 and offset
        out[0] = ip[1];
        out[1] = ip[2];
        
        //Calculate total Pedersen Commitment
        temp1 = ecMul(G1, ip[3]);                   //bf*G
        temp2 = ecMul(H, (ip[0]*(10**ip[1])+ip[2])); //(value*(10^power)+offset)*H
        temp1 = ecAdd(temp1, temp2);
        (PC[2*N], PC[2*N+1]) = (temp1[0], temp1[1]);
        out[2] = CompressPoint(temp1);               //Store compressed total Pedersen Commitment
        
        //Calculate base4 Pedersen Commitments
        {
            uint256[2] memory bits;
            bits[0] = 1; //select 0 or 1
            bits[1] = 2; //select 0 or 2
            
            for (i = 0; i < N; i++) {
                
                if (i < (N-1)) {
                    //Add bf to total BF (in order to calculate last commitment
                    lastBF = addmod(lastBF, ip[4+i], NCurve);
                
                    //Calculate bf*G
                    temp1 = ecMul(G1, ip[4+i]);                    
                }
                else {
                    //Computed implied Pedersen Commitment
                    //Calculate Last Blinding Factor
                    lastBF = NCurve - lastBF;               //Negate total bitwise Blinding factors
                    lastBF = addmod(ip[3], lastBF, NCurve); //Subtract from Total Blinding Factor  
                    
                    //Calculate bf*G
                    temp1 = ecMul(G1, lastBF);
                }
                
                //Break down value into base 4
                if (ip[0] & bits[1] == 0) {
                    //Encode 0*(4^k)
                    if (ip[0] & bits[0] == 0) {
                        pkKnown[i] = 0;
                    }
                    //Encode 1*(4^k)
                    else {
                        temp2 = ecMul(H, (4**i)*(10**ip[1]));   //1*(4^i)*(10^power)*H
                        temp1 = ecAdd(temp1, temp2);            //Add xG to value*H
                        pkKnown[i] = 1;
                    }
                }
                else {
                    //Encode 2*(4^k)
                    if (ip[0] & bits[0] == 0) {
                        temp2 = ecMul(H, 2*(4**i)*(10**ip[1])); //2*(4^i)*(10^power)*H
                        temp1 = ecAdd(temp1, temp2);            //Add xG to value*H
                        pkKnown[i] = 2;
                    }
                    //Encode 3*(4^k)
                    else {
                        temp2 = ecMul(H, 3*(4**i)*(10**ip[1])); //2*(4^i)*(10^power)*H
                        temp1 = ecAdd(temp1, temp2);            //Add xG to value*H
                        pkKnown[i] = 3;
                    }
                }
                
                (PC[2*i], PC[2*i+1]) = (temp1[0], temp1[1]);    //Store uncompressed Pedersen Commitment
                
                if (i < (N-1)) {
                    out[3+i] = CompressPoint(temp1);             //Store compressed Pedersen Commitment (if not last one)
                }
                
                //Shift bit selectors
                bits[0] = bits[0] << 2;
                bits[1] = bits[1] << 2;
            }
        }
        
        //Calculate Range Proof
        {
            //Memory for uncompressed pedersen counter commitments
            uint256[] memory PCp = new uint256[](6*N);
            uint256[] memory c_points = new uint256[](2*N);
            
            for (i = 0; i < N; i++) {
                //Calculate counter Pedersen Comitments
                temp1 = ecMul( H, (4**i)*(10**ip[1]) );
                temp1[1] = PCurve - temp1[1];   //Negate EC Point (use other y-value)
                
                (temp2[0], temp2[1]) = (PC[2*i], PC[2*i+1]);
                
                temp2 = ecAdd(temp1, temp2);    //  PC' = PC - (4^i)*(10^power)*H
                (PCp[6*i], PCp[6*i+1]) = (temp2[0], temp2[1]);
                
                temp2 = ecAdd(temp1, temp2);    // PC'' = PC' - (4^i)*(10^power)*H
                (PCp[6*i+2], PCp[6*i+3]) = (temp2[0], temp2[1]);
                
                temp2 = ecAdd(temp1, temp2);    //PC''' = PC'' - (4^i)*(10^power)*H
                (PCp[6*i+4], PCp[6*i+5]) = (temp2[0], temp2[1]);
                
                //Calculate 1st Half of All Rings
                //pk is known for PC
                if (pkKnown[i] == 0) {
                    //Start Ring
        	        temp1[0] = HashOfPoint(ecMul(G1, ip[4*i+N+3]));
        	        
        	        //Calculate c2 = HashOfPoint(c1*PC'+s1*G)
        	        temp1[0] = CalculateRingSegment(temp1[0], [PCp[6*i], PCp[6*i+1]], ip[4*i+N+4]);
        	        
        	        //Calculate c3 = HashOfPoint(c2*PC''+s2*G)
        	        temp1[0] = CalculateRingSegment(temp1[0],  [PCp[6*i+2], PCp[6*i+3]], ip[4*i+N+5]);
        	        
        	        //Calculate input point for c0 = c3*PC'''+ s3G
        	        temp1 = CalculateRingSegment_NoHash(temp1[0],  [PCp[6*i+4], PCp[6*i+5]], ip[4*i+N+6]);
                }
                //pk is known for PC - (4^i)*(10^power)*H
                else if (pkKnown[i] == 1) {
                    //Start Ring
        	        temp1[0] = HashOfPoint(ecMul(G1, ip[4*i+N+4]));
        	        
        	        //Calculate c3 = HashOfPoint(c2*PC''+s2*G)
        	        temp1[0] = CalculateRingSegment(temp1[0],  [PCp[6*i+2], PCp[6*i+3]], ip[4*i+N+5]);
        	        
        	        //Calculate input point for c0 = c3*PC'''+ s3G
        	        temp1 = CalculateRingSegment_NoHash(temp1[0],  [PCp[6*i+4], PCp[6*i+5]], ip[4*i+N+6]);
                }
                //pk is known for PC - 2*(4^i)*(10^power)*H
                else if (pkKnown[i] == 2) {
                    //Start Ring
        	        temp1[0] = HashOfPoint(ecMul(G1, ip[4*i+N+5]));
        	        
        	        //Calculate input point for c0 = c3*PC'''+ s3G
        	        temp1 = CalculateRingSegment_NoHash(temp1[0],  [PCp[6*i+4], PCp[6*i+5]], ip[4*i+N+6]);
                }
                //pk is known for PC - 3*(4^i)*(10^power)*H
                else {
                    //Start Ring (no hash)
                    temp1 = ecMul(G1, ip[4*i+N+6]);
                }
                
                //Store Intermediate Point into array
                (c_points[2*i], c_points[2*i+1]) = (temp1[0], temp1[1]);
            }
            
            //Construct c0 (store in out[N+2])
        	//  = keccak256 of either c1*PC'+s1*G (x for PC known) or alpha*G (x for PC' known) from each ring
        	//  = keccak256(c1*PC'+s1*G, alpha*G, alpha*G, ... etc)
        	assembly {
        	    let p := mload(0x40)
        	    mstore(p, mul(mul(N, 2), 0x20))
        	    mstore(temp1, keccak256(c_points, mload(p)))
        	}
            out[N+2] = temp1[0];
            
            //Calculate 2nd Half of Rings
            for (i = 0; i < N; i++) {
                //Store correct blinding factor
                if (i == (N-1)) {
                    temp2[0] = lastBF;
                }
                else {
                    temp2[0] = ip[4+i];
                }
                
                //pk is known for PC
                if (pkKnown[i] == 0) {
                    //Close Ring and store other s values
                    out[4*i+N+3] = CompleteRing(ip[4*i+N+3], out[N+2], temp2[0]);
        	        out[4*i+N+4] = ip[4*i+N+4];
        	        out[4*i+N+5] = ip[4*i+N+5];
        	        out[4*i+N+6] = ip[4*i+N+6];
                }
                //pk is known for PC'
                else if (pkKnown[i] == 1) {
                    //Calculate c1 = HashOfPoint(c0*PC+s0*G)
        	        temp1[0] = CalculateRingSegment(out[N+2], [PC[2*i], PC[2*i+1]], ip[4*i+N+3]);
                    
                    //Close Ring and store other s values
                    out[4*i+N+3] = ip[4*i+N+3];
        	        out[4*i+N+4] = CompleteRing(ip[4*i+N+4], temp1[0], temp2[0]);
        	        out[4*i+N+5] = ip[4*i+N+5];
        	        out[4*i+N+6] = ip[4*i+N+6];
                }
                //pk is known for PC''
                else if (pkKnown[i] == 2) {
                    //Calculate c1 = HashOfPoint(c0*PC+s0*G)
        	        temp1[0] = CalculateRingSegment(out[N+2], [PC[2*i], PC[2*i+1]], ip[4*i+N+3]);
        	        
        	        //Calculate c2 = HashOfPoint(c1*PC'+s1*G)
        	        temp1[0] = CalculateRingSegment(temp1[0], [PCp[6*i], PCp[6*i+1]], ip[4*i+N+4]);

                    //Close Ring and store other s values
                    out[4*i+N+3] = ip[4*i+N+3];
        	        out[4*i+N+4] = ip[4*i+N+4];
        	        out[4*i+N+5] = CompleteRing(ip[4*i+N+5], temp1[0], temp2[0]);
        	        out[4*i+N+6] = ip[4*i+N+6];
                }
                //pk is known for PC'''
                else {
                    //Calculate c1 = HashOfPoint(c0*PC+s0*G)
        	        temp1[0] = CalculateRingSegment(out[N+2], [PC[2*i], PC[2*i+1]], ip[4*i+N+3]);
        	        
        	        //Calculate c2 = HashOfPoint(c1*PC'+s1*G)
        	        temp1[0] = CalculateRingSegment(temp1[0], [PCp[6*i], PCp[6*i+1]], ip[4*i+N+4]);
        	        
        	        //Calculate c3 = HashOfPoint(c2*PC''+s2*G)
        	        temp1[0] = CalculateRingSegment(temp1[0],  [PCp[6*i+2], PCp[6*i+3]], ip[4*i+N+5]);

                    //Close Ring and store other s values
                    out[4*i+N+3] = ip[4*i+N+3];
        	        out[4*i+N+4] = ip[4*i+N+4];
        	        out[4*i+N+5] = ip[4*i+N+5];
        	        out[4*i+N+6] = CompleteRing(ip[4*i+N+6], temp1[0], temp2[0]);
                }
            }
        }
    }
    
    //function: CTVerifyTx
    //  description: Verifies a Pedersen Commitment set and Range Proof
    //  notes:
    //      N   - the number of "base4 bits" in the commitment
    //            e.g. 19 can be represented by 3 base4 bits: 3*(4^0) + 0*(4^1) + 1*(4^2)
    //  inputs:
    //      ip (uint256[])      - transaction data ready to be processed by the contract
    //          ip[0]           - power of 10 to be added to committed value (publicly known)
    //          ip[1]           - offset to be added to committed value (publicly known)
    //          ip[2]           - total pedersen commitment (compresed EC Point)
    //          ip[3 ... N+1]   - base4 bit pedersen commitments (minus the last one which is implied, total of N-1 compressed EC Points)
    //          ip[N+2]         - c0 for borromean ring signatures (start of range proof)
    //          ip[N+3 ... 5N+2]- sk values for borromean ring signatures (4 for each base4 bit)
    //  outputs:
    //      result (uint256)    - result of verification, different codes mean different things
    function CTVerifyTx(uint256[] ip)
        public constant returns (bool success)
    {
        //Check for proper number of input parameters (5N+3), must be at least one bit
        require( (ip.length >= 8) );
        require( (ip.length - 3) % 5 == 0 );
        uint256 N = (ip.length - 3) / 5 ;
        
        //Expand Pedersen Commitments
        uint256 i;
        uint256[2] memory temp1;
        uint256[2] memory temp2;
        uint256[] memory PC = new uint256[](2*N+2);
        
        //Expand Total Pedersen Commitment
        temp2 = ExpandPoint(ip[2]);
        
        //Store Total Pedersen Commitment
        (PC[2*N], PC[2*N+1]) = (temp2[0], temp2[1]);
        
        //Expand Stored Bitwise Pedersen Commitments and generate last one
        for (i = 0; i < (N-1); i++) {
            //Expand Stored Point
            temp1 = ExpandPoint(ip[i+3]);
            
            //Store Bitwise Pedersen Commitment
            (PC[2*i], PC[2*i+1]) = (temp1[0], temp1[1]);
            
            //Negate Bitwise Pedersen Commitment
            temp1[1] = PCurve - temp1[1];
            
            //Add Bitwise Pedersen Commitment to total
            temp2 = ecAdd(temp2, temp1);
        }
        
        //Subtract offset*H
        if (ip[1] > 0) {
            temp1 = ecMul(H, ip[1]);
            temp1[1] = PCurve - temp1[1];
            temp2 = ecAdd(temp1, temp2);
        }
        
        //Store Final Bitwise Pedersen Commitment
        (PC[2*N-2], PC[2*N-1]) = (temp2[0], temp2[1]);
        
        //Verify Range Proof
        {
            //Memory for uncompressed pedersen counter commitments
            uint256[] memory PCp = new uint256[](6*N);
            uint256[] memory c_points = new uint256[](2*N);
            
            for (i = 0; i < N; i++) {
                //Calculate counter Pedersen Comitments
                temp1 = ecMul( H, (4**i)*(10**ip[0]) );
                temp1[1] = PCurve - temp1[1];   //Negate EC Point (use other y-value)
                
                (temp2[0], temp2[1]) = (PC[2*i], PC[2*i+1]);
                
                temp2 = ecAdd(temp1, temp2);    //  PC' = PC - (4^i)*(10^power)*H
                (PCp[6*i], PCp[6*i+1]) = (temp2[0], temp2[1]);
                
                temp2 = ecAdd(temp1, temp2);    // PC'' = PC' - (4^i)*(10^power)*H
                (PCp[6*i+2], PCp[6*i+3]) = (temp2[0], temp2[1]);
                
                temp2 = ecAdd(temp1, temp2);    //PC''' = PC'' - (4^i)*(10^power)*H
                (PCp[6*i+4], PCp[6*i+5]) = (temp2[0], temp2[1]);
                
                //Calculate c1 = HashOfPoint(c0*PC+s0*G)
    	        temp1[0] = CalculateRingSegment(ip[N+2], [PC[2*i], PC[2*i+1]], ip[4*i+N+3]);
    	        
    	        //Calculate c2 = HashOfPoint(c1*PC'+s1*G)
    	        temp1[0] = CalculateRingSegment(temp1[0], [PCp[6*i], PCp[6*i+1]], ip[4*i+N+4]);
    	        
    	        //Calculate c3 = HashOfPoint(c2*PC''+s2*G)
    	        temp1[0] = CalculateRingSegment(temp1[0],  [PCp[6*i+2], PCp[6*i+3]], ip[4*i+N+5]);
    	        
    	        //Calculate input point for c0 = c3*PC'''+ s3G
        	    temp1 = CalculateRingSegment_NoHash(temp1[0],  [PCp[6*i+4], PCp[6*i+5]], ip[4*i+N+6]);
        	    (c_points[2*i], c_points[2*i+1]) = (temp1[0], temp1[1]);
            }
            
            //Construct c0 (store in out[N+2])
        	//  = keccak256 of either c1*PC'+s1*G (x for PC known) or alpha*G (x for PC' known) from each ring
        	//  = keccak256(c1*PC'+s1*G, alpha*G, alpha*G, ... etc)
        	assembly {
        	    let p := mload(0x40)
        	    mstore(p, mul(mul(N, 2), 0x20))
        	    mstore(temp1, keccak256(c_points, mload(p)))
        	}
            
            //Check that original c0 matchs the new one (ring is closed)
            if (temp1[0] == ip[N+2]) {
                success = true;
            }
            else {
                success = false;
            }
        }
    }
    
    function CTVerifyTx_GasTest(uint256[] ip)
        public returns (bool success)
    {
        return CTVerifyTx(ip);   
    }
}

contract CToETokenV2 is CToETokenAlgorithms {
	function CToETokenV2() public {
        //Constructor Code
	}

	//Storage of Token Balances
	uint256 public totalSupply;
	mapping (address => uint256) public token_committed_balance;
	
	//Storage array of commitments which have been proven to be positive
	mapping (uint256 => bool) public balance_positive;
    
	//Transaction Functions
	//Deposit Ether as CT tokens to the specified ETH address
	//NOTE: this deposited amount will NOT be confidential, also it is the depositer's responsiblity to remember their own blinding factors
	function Deposit(uint256 initial_blinding_factor)
    	payable public
	{
    	//Incoming Value must be non-zero
    	require(msg.value > 0);
    	
    	//Generate pedersen commitment and add to existing balance
    	uint256[2] memory temp1;
    	uint256[2] memory temp2;
    	temp1 = ecMul(H, msg.value);
    	temp2 = ecMul(G1, initial_blinding_factor);
    	temp1 = ecAdd(temp1, temp2);
    	
    	if (token_committed_balance[msg.sender] != 0) {
    	    temp2 = ExpandPoint(token_committed_balance[msg.sender]);
    	    temp1 = ecAdd(temp1, temp2);
    	}
    	
    	totalSupply += msg.value;
    	token_committed_balance[msg.sender] = CompressPoint(temp1);
	}
	
	//Prove that overall pedersen commitment is positive
	//This function is provided so that high gas cost CT transactions may be split up
	//across multiple blocks
	function CTProvePositiveBalance(uint256[] ip)
	    public returns (bool success)
    {
        //Check for proper number of input parameters (5N+3), must be at least one bit
        require( (ip.length >= 8) );
        require( (ip.length - 3) % 5 == 0 );
        
        //Check to see if balance has already been proven positive
        if (balance_positive[ip[2]]) {
            return true;
        }
        
        //Prove balance is positive
        if (CTVerifyTx(ip)) {
            balance_positive[ip[2]] = true;
            return true;
        }
        else {
            return false;
        }
	}
	
	//Send CT Token to destination address
	//inputs:
	//  to (address)          - ETH address of recepient
	//  PC_to (uint256)       - total pedersen commitment for amount to transfer
	//  PC_remaining(uint256) - total pedersen commitment for amount remaining
	//NOTE 1: PC_to and PC_remaining must be proven with CTProveRange() prior to calling Send()
	//NOTE 2: Sending is only allowed to empty addresses currently to
	//          a) encourage the use of stealth addresses, and
	//          b) make up for the short comings of this contract (no elegant way to pass on blinding factors)
	function Send(address to_A, address to_B, uint256 PC_A, uint256 PC_B)
	    public returns (bool)
	{
	    //Check that new PC commitments are positive
	    if (!balance_positive[PC_A] || !balance_positive[PC_B]) return false;
	    
	    //Verify that the to address has a zero balance
	    if (token_committed_balance[to_A] != 0) return false;
	    if (token_committed_balance[to_B] != 0) return false;
	    
	    //Check that no tokens were created or destroyed
	    uint256[2] memory temp1;
	    uint256[2] memory temp2;
	    temp1 = ExpandPoint(PC_A);
	    temp2 = ExpandPoint(PC_B);
	    temp1 = ecAdd(temp1, temp2); //temp1 = PC_to + PC_remaining
	    temp2 = ExpandPoint(token_committed_balance[msg.sender]); //temp2 = PC_total
	    if ( (temp1[0] != temp2[0]) || (temp1[1] != temp2[1]) ) return false;
	    
	    //Update token balance
	    token_committed_balance[msg.sender] = 0;
	    token_committed_balance[to_A] = PC_A;
	    token_committed_balance[to_B] = PC_B;
	    
	    return true;
	}
	
	//Send all CT Tokens to destination address
	//inputs:
	//  to (address)          - ETH address of recepient
	//NOTE 1: Sending is only allowed to empty addresses currently to
	//          a) encourage the use of stealth addresses, and
	//          b) make up for the short comings of this contract (no elegant way to pass on blinding factors)
	function SendAll(address to)
	    public returns (bool)
	{
	    //Verify that the to address has a zero balance
	    if (token_committed_balance[to] != 0) return false;
	    
	    //Check that no tokens were created or destroyed
	    uint256[2] memory temp1;
	    
	    //Update sending token balance
	    temp1[0] = token_committed_balance[msg.sender];
	    token_committed_balance[msg.sender] = 0;
        token_committed_balance[to] = temp1[0];
	    
	    return true;
	}
	
	//Test conversion of all owned CT tokens into ETH without sending a tx to the blockchain
	//Can be used to not accidentally reveal value/blinding factor
    function Withdraw_test(uint256 value, uint256 blinding_factor)
	    public constant returns (bool)
	{
	    //Calculate pedersen commitment and compare to token balance
    	uint256[2] memory temp1;
    	uint256[2] memory temp2;
    	temp1 = ecMul(H, value);
    	temp2 = ecMul(G1, blinding_factor);
    	temp1 = ecAdd(temp1, temp2);
    	temp1[0] = CompressPoint(temp1);
	    
	    if (temp1[0] == token_committed_balance[msg.sender]) {
	        return true;
	    }
	    else {
	        return false;
	    }
	}
	
    //Convert all owned CT tokens into ETH
	function Withdraw(uint256 value, uint256 blinding_factor)
	    public returns (bool)
	{
	    if (Withdraw_test(value, blinding_factor)) {
	        token_committed_balance[msg.sender] = 0;
	        totalSupply -= value;
	        
	        msg.sender.transfer(value);
	        return true;
	    }
	    else {
	        return false;
	    }
	}
    
}
