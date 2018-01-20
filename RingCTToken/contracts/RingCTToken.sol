pragma solidity ^0.4.19;

import {MLSAG_Verify} from "github.com/solidblu1992/ethereum/RingCTToken/contracts/MLSAG_Verify.sol";
import {StealthTransaction} from "github.com/solidblu1992/ethereum/RingCTToken/contracts/StealthTransaction.sol";

contract RingCTToken is MLSAG_Verify, StealthTransaction {
    //Storage of Token Balances
	uint256 public totalSupply;
	
	//Mapping of EC Public Key to Pedersen Commitment of Value
	mapping (uint256 => uint256) public token_committed_balance;
	
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
    	
    	//Store DHE point 
    	stx_dhe_points[stx_dhe_point_count] = dhe_point;
    	stx_dhepoints_reverse[dhe_point] = true;
    	stx_dhe_point_count++;
    	
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
    
    //Send - sends tokens via the Ring CT protocol
	//Verifies an MLSAG ring signature over a set of public keys and the summation of their commitments and a set of output commitments.
	//If successful, a new set of public keys (UTXO's) will be generated with masked values (pedersen commitments).  Each of these
	//also has a DHE point so that the intended receiver is able to calculate the stealth address.
	//
	//dest_pub_keys		= set of expanded EC points representing new UTXO public keys
	//values			= set of pedersen commitments (expanded EC points) representing the new values (masked) for the above UTXO's
	//dest_dhe_points	= set of DHE points to be used by the receivers to calculate the new UTXO public keys with their stealth addresses
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
    function Send(  uint256[] dest_pub_keys, uint256[] values, uint256[] dest_dhe_points, uint256[] encrypted_data, uint128[] iv,
                    uint256[] I, uint256[] input_pub_keys, uint256[] signature)
        public returns (bool success)
    {
        //Need at least one destination
        if (dest_pub_keys.length == 0) return false;
        if (dest_pub_keys.length % 2 != 0) return false;
        
        //Need same number of values and dhe points
        if (values.length != dest_pub_keys.length) return false;
        if (dest_dhe_points.length != dest_pub_keys.length) return false;
		if (encrypted_data.length != dest_pub_keys.length*2) return false;
		if (iv.length != dest_pub_keys.length) return false;
        
        //Check other array lengths
        if (I.length % 2 != 0) return false;
        
        MLSAGVariables memory v;
        v.m = (I.length / 2);
		
		if (v.m < 2) return false;
		v.m = v.m - 1;
        
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
		
		//Verify key images are unused
        for (v.i = 0; v.i < v.m; v.i++) {
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
		P = AddColumnsToArray(input_pub_keys, v.m, P, 2);
        
        //Verify ring signature (MLSAG)
        if (!VerifyMLSAG(HashSendMsg(dest_pub_keys, values, dest_dhe_points, encrypted_data, iv), I, P, signature)) return false;
    
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
    			
    			stx_dhepoints_reverse[v.point3[0]] = true;
			}
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
						uint256[] dest_pub_keys, uint256[] values, uint256[] dest_dhe_points,
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
        v.m = (I.length / 2);
		
		if (v.m < 2) return false;
		v.m = v.m - 1;
        
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
		P = AddColumnsToArray(input_pub_keys, v.m, P, 2);
        
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
    			
    			stx_dhepoints_reverse[v.point3[0]] = true;
			}
		}
		
		//Send redeemed value
		redeem_eth_address.transfer(redeem_value);
		
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
        success = VerifyMSAG(bits, 0, P, signature);
    }
    
    //Utility Functions
    function HashSendMsg(uint256[] dest_pub_keys, uint256[] output_commitments, uint256[] dest_dhe_points, uint256[] encrypted_data, uint128[] iv)
        public pure returns (bytes32 msgHash)
    {
        msgHash = keccak256(Keccak256OfArray(dest_pub_keys), Keccak256OfArray(output_commitments), Keccak256OfArray(dest_dhe_points), Keccak256OfArray(encrypted_data),Keccak256OfArray(iv),);
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