pragma solidity ^0.4.19;

import "./MLSAG_Verify.sol";

contract RingCTToken is MLSAG_Verify {
    //Storage of Token Balances
	uint256 public totalSupply;
	
	//Mapping of EC Public Key to Pedersen Commitment of Value
	mapping (uint256 => uint256) public token_committed_balance;
	
	//Storage array of commitments which have been proven to be positive
	mapping (uint256 => bool) public balance_positive;
	
	//Storage array for key images which have been used
	mapping (uint256 => bool) public key_images;
    
    function RingCTToken() public {
        //Constructor Code
    }
    
    //Transaction Functions
	//Deposit Ether as CT tokens to the specified ETH address
	//NOTE: this deposited amount will NOT be confidential, initial blinding factor = 0
	function Deposit(uint256 dest_pub_key)
    	payable public
	{
    	//Incoming Value must be non-zero
    	require(msg.value > 0);
    	
    	//Destination Public Key must be unused
    	require(token_committed_balance[dest_pub_key] == 0);
    	
    	//Generate pedersen commitment and add to existing balance
    	token_committed_balance[dest_pub_key] = CompressPoint(ecMul(H, msg.value));
    	
    	//Update global token supply
    	totalSupply += msg.value;
	}
	
	//Deposit Ether as CT tokens to the specified ETH address
	//this function allows multiple deposits at onces
	//NOTE: this deposited amount will NOT be confidential, initial blinding factor = 0
	function Deposit(uint256[] dest_pub_keys, uint256[] values)
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
    	}
    	
    	//Update global token supply
    	totalSupply += msg.value;
    }
    
    //Send
    function Send(  uint256[] dest_pub_keys, uint256[] values, uint256[] dest_dhe_points,
                    uint256[] I, uint256[] input_pub_keys, uint256[] signature)
        public returns (bool success)
    {
        //Need at least one destination
        if (dest_pub_keys.length == 0) return false;
        if (dest_pub_keys.length % 2 != 0) return false;
        
        //Need same number of values and dhe points
        if (values.length != dest_pub_keys.length) return false;
        if (dest_dhe_points.length != dest_pub_keys.length) return false;
        
        //Check other array lengths
        if (I.length % 2 != 0) return false;
        
        MLSAGVariables memory v;
        v.m = I.length / 2;
        
        if (input_pub_keys.length % (2*v.m) != 0) return false;
        v.n = input_pub_keys.length / (2*v.m);
        
        //Verify key images are unused
        for (v.i = 0; v.i < v.m; v.i++) {
            v.keyImage[0] = CompressPoint([I[2*v.i], I[2*v.i+1]]);
            if (key_images[v.keyImage[0]]) return false;
        }
        
        //Verify output commitments have been proven positive
        for (v.i = 0; v.i < (values.length / 2); v.i++) {
            v.point1 = [values[2*v.i], values[2*v.i+1]];
            if (!balance_positive[CompressPoint(v.point1)]) return false;
        }
        
        //Transfer public key to new public key set for MLSAG
        uint256[] memory P = new uint256[](2*v.n*(v.m+1));
        for (v.i = 0; v.i < v.m; v.i++) {
            for (v.j = 0; v.j < v.n; v.j++) {
                v.index = 2*(v.m*v.j + v.i);
                (P[v.index + 2*v.j], P[v.index + 2*v.j + 1]) = (input_pub_keys[v.index], input_pub_keys[v.index+1]); 
            }
        }
        
        //Fill in last row of public key set
        //Calculate negative of total destination commitment
        v.point1 = [values[0], values[1]];
        for (v.i = 1; v.i < (values.length / 2); v.i++) {
            v.point1 = ecAdd(v.point1, [values[2*v.i], values[2*v.i+1]]);
        }
        v.point1[1] = PCurve - v.point1[1];
        
        //FINISH THIS
        
        //Verify key images are unused
        for (v.i = 0; v.i < v.m; v.i++) {
            v.keyImage[0] = CompressPoint([I[2*v.i], I[2*v.i+1]]);
            if (key_images[v.keyImage[0]]) return false;
        }
        
        //Verify ring signature (MLSAG)
        if (!VerifyMLSAG(HashTxMessage(dest_pub_keys, values), I, P, signature)) return false;
    
        //Store key images
    
        for (v.i = 0; v.i < (dest_pub_keys.length / 2); i++) {
            
        }
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
        public constant returns (bool success)
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
        temp1 = ecAdd(temp1, ecMul(H, offset));
        
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
        success = VerifyMSAG(bits, 0, P, signature);
    }
    
    //Utility Functions
    function HashTxMessage(uint256[] dest_pub_keys, uint256[] output_commitments)
        public pure returns (bytes32 msgHash)
    {
        msgHash = keccak256(Keccak256OfArray(dest_pub_keys), Keccak256OfArray(output_commitments));
    }
	
	function AddColumnsToArray(uint256[] baseArray, uint256 baseWidth, uint256[] newColumns, uint256 newWidth)
		public pure returns (uint256[] outArray)
	{
		//Check Array dimensions
		if (baseArray.length % baseWidth != 0) return;
		if (newColumns.length % newWidth != 0) return;
		
		uint256 n = baseArray.length / baseWidth;
		if ( (newColumns.length / newWidth) != n ) return;
		
		//Create output Array
		outArray = new uint256[](baseArray.length + newArray.length);
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
				outArray[outWidth*i + baseWidth + j] = newArray[newWidth*i + j];
			}
		}
	}
	
	function DropRightColumnsFromArray(uint256[] baseArray, uint256 baseWidth, uint256 colToDrop)
		public pure returns (uint256[] outArray)
	{
		//Check Array Dimensions
		if (baseArray.length % baseWidth != 0) return;
		if (colToDrop > baseWidth) return;
		
		uint256 n = baseArray.length / baseWidth;
		
		//Create Output Array
		outArray = new uint256[](baseArray.length - n*colToDrop);
		uint256 outWidth = baseWidth - colToDrop;
		
		//Assemble new array
		uint256 i;
		uint256 j;
		for (i = 0; i < n; i++) {
			for (j = 0; j < outWidth; j++) {
				//Copy only relevant elements over
				outArray[outWidth*i + j] = baseArray[baseWidth*i + j];
			}
		}
	}
}