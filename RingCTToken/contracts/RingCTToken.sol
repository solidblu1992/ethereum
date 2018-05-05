pragma solidity ^0.4.22;

import "./Debuggable.sol";
import "./ECMathInterface.sol";
import "./RingCTTxVerifyInterface.sol";

contract RingCTToken is RingCTTxVerifyInterface, ECMathInterface {
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ringCTVerifyAddr, address ecMathAddr) RingCTTxVerifyInterface(ringCTVerifyAddr) ECMathInterface(ecMathAddr) public { }
	
	event WithdrawalEvent(address indexed _to, uint256 _value);
	event DepositEvent (uint256 indexed _pub_key, uint256 indexed _dhe_point, uint256 _value);
	event SendEvent (uint256 indexed _pub_key, uint256 indexed _value, uint256 indexed _dhe_point, uint256[3] _encrypted_data);
	event PCRangeProvenEvent (uint256 indexed _commitment, uint256 _min, uint256 _max, uint256 _resolution);
	event StealthAddressPublishedEvent(address indexed addr, uint256 indexed pubviewkey, uint256 indexed pubspendkey);

	//Mapping of EC Public Key to Pedersen Commitment of Value
	mapping (uint256 => uint256) public token_committed_balance;
    
	//Storage array of commitments which have been proven to be positive
	mapping (uint256 => bool) public balance_positive;
	
	//Storage array for key images which have been used
	mapping (uint256 => bool) public key_images;
	
	//Stealth Address Function(s)
    //For a given msg.sender (ETH address) publish EC points for public spend and view keys
    //These EC points will be used to generate stealth addresses
    function PublishStealthAddress(uint256 stx_pubviewkey, uint256 stx_pubspendkey) public
    {
		emit StealthAddressPublishedEvent(msg.sender, stx_pubviewkey, stx_pubspendkey);
    }
    
    //Transaction Functions
	//Deposit Ether as CT tokens to the specified alt_bn_128 public key
	//NOTE: this deposited amount will NOT be confidential, initial blinding factor = 0
	function Deposit(uint256 dest_pub_key, uint256 dhe_point)
    	payable requireECMath public
	{
    	//Incoming Value must be non-zero
    	require(msg.value > 0);
    	
    	//Destination Public Key must be unused
    	require(token_committed_balance[dest_pub_key] == 0);
    	
    	//Generate pedersen commitment and add to existing balance
    	token_committed_balance[dest_pub_key] = ecMath.CompressPoint(ecMath.MultiplyH(msg.value));
    	
    	//Log new stealth transaction
    	emit DepositEvent(dest_pub_key, dhe_point, msg.value);
	}
	
	//Deposit Ether as CT tokens to the specified alt_bn_128 public keys
	//This function allows multiple deposits at onces
	//NOTE: this deposited amount will NOT be confidential, initial blinding factor = 0
	function DepositMultiple(uint256[] dest_pub_keys, uint256[] dhe_points, uint256[] values)
	    payable requireECMath public
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
        	token_committed_balance[dest_pub_keys[i]] = ecMath.CompressPoint(ecMath.MultiplyH(values[i]));
    	
    	    //Log new stealth transaction
			emit DepositEvent(dest_pub_keys[i], dhe_points[i], values[i]);
    	}
    }
    
    //Internal function for checking positive commitment proofs
    function CheckBalancePositive(UTXO.Output[] output_tx)
        internal view returns (bool)
    {
    	//Verify output commitments have been proven positive
		uint256 i;
        for (i = 0; i < output_tx.length; i++) {
            if (!balance_positive[ecMath.CompressPoint(output_tx[i].value)]) return false;
        }
    
        return true;
    }
    
    //Internal function for compiling input_value array
	function FetchCommittedValues(uint256[] input_pub_keys)
	    internal view returns (uint256[] input_values)
	{
	    require(input_pub_keys.length > 0);
	    require(input_pub_keys.length % 2 == 0);
	    
        uint256 i;
        uint256[2] memory point;
        //Fetch input values, verify that all balances are non-zero
		input_values = new uint256[](input_pub_keys.length);
		for (i = 0; i < (input_pub_keys.length / 2); i++) {
			point[0] = ecMath.CompressPoint([input_pub_keys[2*i], input_pub_keys[2*i+1]]);
			point[0] = token_committed_balance[point[0]];
			
			point = ecMath.ExpandPoint(point[0]);
			(input_values[2*i], input_values[2*i+1]) = (point[0], point[1]);
		}
	}
    
    //Internal function for checking key images
    function CheckKeyImages(uint256[] I)
        internal view returns (bool)
    {
        require(I.length > 0);
        require(I.length % 2 == 0);
    
        //Verify key images are unused
        uint256 i;
        uint256[2] memory point;
        for (i = 0; i < (I.length / 2); i++) {
            point[0] = ecMath.CompressPoint([I[2*i], I[2*i+1]]);
            if (key_images[point[0]]) return false;
        }
    
        return true;
    }
    
	//Marks UTXOs as spent by storing the key images and creates new UTXOs
	//Internal function only
	function ProcessRingCTTx(UTXO.Output[] output_tx, uint256[] I) internal requireECMath
	{
        //Store key images (point of no return, all returns need to be reverts after this point)
        uint256 i;
        uint256 pub_key;
        uint256 value;
        for (i = 0; i < (I.length / 2); i++) {
            key_images[ecMath.CompressPoint([I[2*i], I[2*i+1]])] = true;
        }
		
		//Generate new UTXO's
		for (i = 0; i < (output_tx.length); i++) {
			pub_key = ecMath.CompressPoint(output_tx[i].pub_key);
			value = ecMath.CompressPoint(output_tx[i].value);
			
			//Store output commitment and public key
			token_committed_balance[pub_key] = value;		
			
			//Unmark balance positive to free up space
			//Realistically there is no situation in which using the same output commitment will be useful
			balance_positive[value] = false;

			//Log new stealth transaction
			emit SendEvent(pub_key, value, ecMath.CompressPoint(output_tx[i].dhe_point), output_tx[i].encrypted_data);
		}
	}
	
	//VerifyPCRangeProof
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
    function VerifyPCRangeProof(uint256[2] total_commit, uint256 power10, uint256 offset, uint256[] bit_commits, uint256[] signature)
        public requireRingCTTxVerify returns (bool success)
    {
        VerifyPCRangeProofStruct.Data memory args = VerifyPCRangeProofStruct.Data(total_commit, power10, offset, bit_commits, signature);
		
		success = ringcttxverify.VerifyPCRangeProof(VerifyPCRangeProofStruct.Serialize(args));
		
		if (success) {
			balance_positive[ecMath.CompressPoint(total_commit)] = true;
			
			uint256[3] memory temp;
			temp[0] = (bit_commits.length / 2);         //Bits
			temp[1] = (10**power10);                    //Resolution
			temp[2] = (4**temp[0]-1)*temp[1]+offset;    //Max Value
			emit PCRangeProvenEvent(ecMath.CompressPoint(total_commit), offset, temp[2], temp[1]);
		}
	}
	
    //Send - sends tokens via the Ring CT protocol
	//Verifies an MLSAG ring signature over a set of public keys and the summation of their commitments and a set of output commitments.
	//If successful, a new set of public keys (UTXO's) will be generated with masked values (pedersen commitments).  Each of these
	//also has a DHE point so that the intended receiver is able to calculate the stealth address.
	//
	//dest_pub_keys			= set of expanded EC points representing new UTXO public keys
	//values				= set of pedersen commitments (expanded EC points) representing the new values (masked) for the above UTXO's
	//dest_dhe_points		= set of DHE points to be used by the receivers to calculate the new UTXO public keys with their stealth addresses
	//dest_encrypted_data	= uint256[3] for each output representing encrypted data which can be included.  The contract will not check this data,
	//                    	  but this can be an easy way to pass on the value and blinding factor of the new commitment to the receiver.
	//input_pub_keys		= public key set for the MLSAG, each point is expanded	{	P11x, P11y, P12x, P12y, ..., P1mx, P1my,
	//																					P21x, P21y, P22x, P22y, ..., P2mx, P2my,
	//																					...
	//																					Pn1x, Pn1y, Pn2x, Pn2y, ..., Pnmx, Pnmy	}
	//I						= key images for the MLSAG	{ I1x, I1y, I2x, I2y, ..., I(m+1)x, I(m+1)y }
	//signature				= signature for the MLSAG {	c1, s11, s12, ..., s1(m+1),
	//														s21, s22, ..., s2(m+1),
	//														...
	//														sn1, sn2, ..., sn(m+1)	}
	//
	//Note 1: m refers to the number of EC points in each public key vector (columns/2 of input_pub_keys).
	//		  n refers to the number of public key vectors (rows of input_pub_keys)
	//		  The actual MLSAG signs an array of n*(m+1) points as the last column is a summation of each public key in the vector
	//		  as well as each input commitment in the vector and the summation of all output commitments (sigma(Pj) + sigma(Cinj) - sigma(Couti))
	//Note 2: See https://eprint.iacr.org/2015/1098 for more details on RingCT
    function Send(ValidateRingCTTxStruct.Data args)
        internal requireECMath requireRingCTTxVerify returns (bool success)
    {
		//Verify output commitments have been proven positive
		if(!CheckBalancePositive(args.output_tx)) return false;
		
		//Verify key images are unused
        if (!CheckKeyImages(args.I)) return false;
		
		//Check Ring CT Tx for Validity
        if (!ringcttxverify.ValidateRingCTTx(ValidateRingCTTxStruct.Serialize(args))) return false;
		
		//Spend UTXOs and generate new UTXOs					
		ProcessRingCTTx(args.output_tx, args.I);
		
		return true;
    }
    
    function Send(  uint256[] dest_pub_keys, uint256[] dest_values, uint256[] dest_dhe_points, uint256[] dest_encrypted_data,
					uint256[] input_pub_keys,
                    uint256[] I, uint256[] signature)
        public requireECMath requireRingCTTxVerify returns (bool success)
    {
        UTXO.Output[] memory output_tx = UTXO.CreateOutputArray(dest_pub_keys, dest_values, dest_dhe_points, dest_encrypted_data); 
    
        uint256[] memory input_values = FetchCommittedValues(input_pub_keys);
        UTXO.Input[] memory input_tx = UTXO.CreateInputArray(input_pub_keys, input_values);
        
        ValidateRingCTTxStruct.Data memory args = ValidateRingCTTxStruct.Data(0, 0, input_tx, output_tx, I, signature);
        return Send(args);
    }
    
    //Withdraw - destorys tokens via RingCT and redeems them for ETH
	//Verifies an MLSAG ring signature over a set of public keys and the summation of their commitments and a set of output commitments.
	//If successful, a new set of public keys (UTXO's) will be generated with masked values (pedersen commitments).  Each of these
	//also has a DHE point so that the intended receiver is able to calculate the stealth address.  Additionally, the redeemed tokens
	//will be destoryed and sent to an ETH address for their ETH value
	//
	//redeem_eth_address		= ETH address to send ETH value of redeemed tokens to
	//redeem_eth_value			= total number of tokens to redeem, the rest is sent (or a commitment to zero) is sent new alt_bn_128 outputs
	//See Send(...) for other inputs
	//
	//Note: Every withdrawal must create at least one new masked UTXO, otherwise the privacy of all spent input public keys are compromised.
	//		(The network will know which key vector has been spent.)  At a minimum, one new UTXO may be created with a commitment to zero.
    function Withdraw(ValidateRingCTTxStruct.Data args)
        internal requireECMath requireRingCTTxVerify returns (bool success)
    {
		//Verify output commitments have been proven positive
		if(!CheckBalancePositive(args.output_tx)) return false;
		
		//Verify key images are unused
        if (!CheckKeyImages(args.I)) return false;
		
		//Check Ring CT Tx for Validity
        if (!ringcttxverify.ValidateRingCTTx(ValidateRingCTTxStruct.Serialize(args))) return false;
        
		//Spend UTXOs and generate new UTXOs					
		ProcessRingCTTx(args.output_tx, args.I);
		
		//Send redeemed value to ETH address
		//If ETH address is 0x0, redeem the ETH to sender of the transaction
		//This can be used to pay others to broadcast transactions for you
		if (args.redeem_eth_address == 0) {
			args.redeem_eth_address = msg.sender;
		}
		
		args.redeem_eth_address.transfer(args.redeem_eth_value);
		
		//Log Withdrawal
		emit WithdrawalEvent(args.redeem_eth_address, args.redeem_eth_value);
		
		return true;
    }
    
    function Withdraw(  address redeem_eth_address, uint256 redeem_eth_value,
						uint256[] dest_pub_keys, uint256[] dest_values, uint256[] dest_dhe_points, uint256[] dest_encrypted_data,
						uint256[] input_pub_keys, 
						uint256[] I, uint256[] signature)
        public requireECMath requireRingCTTxVerify returns (bool success)
    {
		 UTXO.Output[] memory output_tx = UTXO.CreateOutputArray(dest_pub_keys, dest_values, dest_dhe_points, dest_encrypted_data); 
    
        uint256[] memory input_values = FetchCommittedValues(input_pub_keys);
        UTXO.Input[] memory input_tx = UTXO.CreateInputArray(input_pub_keys, input_values);
        
        ValidateRingCTTxStruct.Data memory args = ValidateRingCTTxStruct.Data(redeem_eth_address, redeem_eth_value, input_tx, output_tx, I, signature);
        return Withdraw(args);
    }
}
