pragma solidity ^0.4.13;

contract BulletproofVerify {
    //Verify Bulletproof(s), can do multiple commitements and multiple proofs at once
    //This function's arguments are serialized into uint256[] array so it can be called externally w/o abi encoding
	function VerifyBulletproof(uint256[] argsSerialized) public view returns (bool);
}

contract Debuggable {
    //Debug Code
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier ownerOnly {
        if ( (msg.sender != owner) && (owner != 0) ) revert();
        _;
    }
    
	function Kill() public ownerOnly {
    	selfdestruct(msg.sender);
	}
	
	event DebugEvent(string marker, uint256 data);
	event DebugEvent2(string marker, uint256[] data);
}

contract BulletproofVerifyInterface is Debuggable {
    //Prerequisite Contract(s)
	BulletproofVerify bpVerify;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function BulletproofVerify_GetAddress() public constant returns (address) {
	    return address(bpVerify);
	}
	
	function BulletproofVerify_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = BulletproofVerify_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function BulletproofVerify_ChangeAddress(address bpVerifyAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//assert(BulletproofVerify_GetCodeSize() == 0);
		
		bpVerify = BulletproofVerify(bpVerifyAddr);
		emit ContractAddressChanged("BulletproofVerify", bpVerifyAddr);
	}
	
	modifier requireBulletproofVerify {
	    require(BulletproofVerify_GetCodeSize() > 0);
	    _;
	}
	
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address bpVerifyAddr) public {
	    BulletproofVerify_ChangeAddress(bpVerifyAddr);
	}
}

contract ECMath {
	//Base EC Parameters
	function GetG1() public view returns (uint256[2]);
	function GetH() public view returns (uint256[2]);
	function GetInfinity() public view returns (uint256[2]);
	function GetNCurve() public pure returns (uint256);
	function GetPCurve() public pure returns (uint256);
	function GetGiHi(uint256 N) public constant returns (uint256[], uint256[]);
	function GetGiHiLength() public view returns (uint256);
	
	//Base EC Functions
	function Negate(uint256[2] p1) public pure returns (uint256[2] p2);
	function Equals(uint256[2] p1, uint256[2] p2) public pure returns (bool);
	function Add(uint256[2] p0, uint256[2] p1) public constant returns (uint256[2] p2);
	function Subtract(uint256[2] p0, uint256[2] p1) public constant returns (uint256[2] p2);
	function Multiply(uint256[2] p0, uint256 s) public constant returns (uint256[2] p1);
	
	//Shortcut Functions
	function MultiplyG1(uint256 s) public constant returns (uint256[2] p0);
	function MultiplyH(uint256 s) public constant returns (uint256[2] p0);
    function AddMultiply(uint256[2] p_add, uint256[2] p_mul, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*p_mul
	function AddMultiplyG1(uint256[2] p_add, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*G1
    function AddMultiplyH(uint256[2] p_add, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*H
    function CommitG1H(uint256 s_G1, uint256 s_H) public constant returns (uint256[2] p0); //Returns s_G1*G1 + s_H*H
	
	//Vector Functions
	function VectorScale(uint256[] X, uint256 s) public constant returns (uint256[] Z);
	function VectorAdd(uint256[] X, uint256[] Y) public constant returns (uint256[] Z);
	function VectorMul(uint256[] X, uint256[] s) public constant returns (uint256[] Z);
	
	//Returns s0*P0 + s1*P1 + ... + sk*Pk
    function MultiExp(uint256[] P, uint256[] s, uint256 start, uint256 end) public constant returns (uint256[2] Pout);
	
	//Returns Pin + s0*P0 + s1*P1 + ... + sk*Pk
	function AddMultiExp(uint256[2] Pin, uint256[] P, uint256[] s, uint256 start, uint256 end) public constant returns (uint256[2] Pout);
	
	//Returns px = x[0]*X[0] + x[1]*X[1] + ... + x[n-1]*X[n-1]
    //    and py = y[0]*Y[0] + y[1]*Y[1] + ... + y[n-1]*Y[n-1]
    function CommitAB(uint256[] X, uint256[] Y, uint256[] x, uint256[] y) public constant returns (uint256[2] px, uint256[2] py);
        
	//Point Compression and Expansion Functions
	function CompressPoint(uint256[2] Pin) public pure returns (uint256 Pout);
	function EvaluateCurve(uint256 x) public constant returns (uint256 y, bool onCurve);
	function ExpandPoint(uint256 Pin) public constant returns (uint256[2] Pout);
	
	//Address Functions
	function GetAddress(uint256[2] PubKey) public pure returns (address addr);    
    function GetPublicKeyFromPrivateKey(uint256 privatekey) public constant returns (uint256[2] PubKey);    
    function GetAddressFromPrivateKey(uint256 privatekey) public constant returns (address addr);

    //Return H = keccak256(p)
    function HashOfPoint(uint256[2] point) public pure returns (uint256 h);
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[2] p) public constant returns (uint256[2] h);
}

contract ECMathInterface is Debuggable {
    //Prerequisite Contract(s)
	ECMath ecMath;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function ECMath_GetAddress() public constant returns (address) {
	    return address(ecMath);
	}
	
	function ECMath_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = ECMath_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function ECMath_ChangeAddress(address ecMathAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//assert(ECMath_GetCodeSize() == 0);
		
		ecMath = ECMath(ecMathAddr);
		emit ContractAddressChanged("ECMath", ecMathAddr);
	}
	
	modifier requireECMath {
	    require(ECMath_GetCodeSize() > 0);
	    _;
	}
	
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ecMathAddr) public {
	    ECMath_ChangeAddress(ecMathAddr);
	}
}

contract RingCTTxVerify {    
    //Serialized version of ValidateRingCTTx.  This version does not use structs so that it can be called publicly.
	function ValidateRingCTTx(uint256[] argsSerialized) public view returns (bool);
    
    //Serialized version of VerifyBorromeanRangeProof.  This version does not use structs so that it can be called publicly.
	function VerifyBorromeanRangeProof(uint256[] argsSerialized) public view returns (bool);
	
    //Utility Functions
	function HashSendMsg(uint256[] output_pub_keys, uint256[] output_values, uint256[] output_dhe_points, uint256[] output_encrypted_data)
							public pure returns (uint256 msgHash);		

	function HashWithdrawMsg(address ethAddress, uint256 value,
								uint256[] output_pub_keys, uint256[] output_values, uint256[] output_dhe_points, uint256[] output_encrypted_data)
								public pure returns (uint256 msgHash);
}

contract RingCTTxVerifyInterface is Debuggable {
    //Prerequisite Contract(s)
	RingCTTxVerify ringcttxverify;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function RingCTTxVerify_GetAddress() public constant returns (address) {
		return address(ringcttxverify);
	}
	
	function RingCTTxVerify_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = RingCTTxVerify_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function RingCTTxVerify_ChangeAddress(address ringCTTxVerifyAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//require(RingCTTxVerify_GetCodeSize() == 0);
		
		ringcttxverify = RingCTTxVerify(ringCTTxVerifyAddr);
		emit ContractAddressChanged("RingCTTxVerify", ringCTTxVerifyAddr);
	}
	
	modifier requireRingCTTxVerify {
	    require(RingCTTxVerify_GetCodeSize() > 0);
	    _;
	}

	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ringCTTxVerifyAddr) public {
	    RingCTTxVerify_ChangeAddress(ringCTTxVerifyAddr);
	}
}

contract RingCTToken is RingCTTxVerifyInterface, ECMathInterface, BulletproofVerifyInterface {
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ecMathAddr, address bpVerifyAddr, address ringCTVerifyAddr)
		ECMathInterface(ecMathAddr) BulletproofVerifyInterface(bpVerifyAddr) RingCTTxVerifyInterface(ringCTVerifyAddr) public
	{
		//Nothing left to do
	}
	
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
	
	//Verify Pedersen Commitment is positive using a Borromean Range Proof
    //Arguments are serialized to minimize stack depth.  See libBorromeanRangeProofStruct.sol
    function VerifyPCBorromeanRangeProof(uint256[] rpSerialized)
        public requireRingCTTxVerify returns (bool success)
    {
		//Verify Borromean Range Proof
		success = ringcttxverify.VerifyBorromeanRangeProof(rpSerialized);
		
		if (success) {
		    //Deserialize arguments
		    BorromeanRangeProofStruct.Data memory args = BorromeanRangeProofStruct.Deserialize(rpSerialized);
		    
			balance_positive[ecMath.CompressPoint(args.total_commit)] = true;
			
			uint256[3] memory temp;
			temp[0] = (args.bit_commits.length / 2);         //Bits
			temp[1] = (10**args.power10);                    //Resolution
			temp[2] = (4**temp[0]-1)*temp[1]+args.offset;    //Max Value
			emit PCRangeProvenEvent(ecMath.CompressPoint(args.total_commit), args.offset, temp[2], temp[1]);
		}
	}
	
	//Verify Pedersen Commitment is positive using Bullet Proof(s)
	//Arguments are serialized to minimize stack depth.  See libBulletproofStruct.sol
	function VerifyPCBulletProof(uint256[] bpSerialized, uint256[] power10, uint256[] offsets)
		public requireECMath requireBulletproofVerify returns (bool success)
	{
	    //Deserialize Bullet Proof
	    BulletproofStruct.Data[] memory args = BulletproofStruct.Deserialize(bpSerialized);
	    
	    //Check inputs for each proof
	    uint256 p;
	    uint256 i;
		uint256 offset_index = 0;
		
	    for (p = 0; p < args.length; p++) {
    		//Check inputs
    		if (args[p].V.length < 2) return false;
    		if (args[p].V.length % 2 != 0) return false;
			if (args[p].N > 64) return false;
    		
    		//Count number of committments
    		offset_index += (args[p].V.length / 2);
	    }
	    
	    //Check offsets and power10 length
	    if (offsets.length != offset_index) return false;
    	if (power10.length != offset_index) return false;
		
		//Limit power10, offsets, and N so that commitments do not overflow (even if "positive")		
		for (i = 0; i < offsets.length; i++) {
			if (offsets[i] > (ecMath.GetNCurve() / 4)) return false;
			if (power10[i] > 35) return false;
		}
		
		//Verify Bulletproof(s)
		success = bpVerify.VerifyBulletproof(bpSerialized);

		uint256[2] memory point;
		uint256[2] memory temp;
		if (success) {
			//Add known powers of 10 and offsets to committments and mark as positive
			//Note that multiplying the commitment by a power of 10 also affects the blinding factor as well
			offset_index = 0;
			
			for (p = 0; p < args.length; p++) {
				for (i = 0; i < args[p].V.length; i += 2) {
				    //Pull commitment
				    point = [args[p].V[i], args[p].V[i+1]];
				    
    				//Calculate (10^power10)*V = (10^power10)*(v*H + bf*G1) = v*(10^power10)*H + bf*(10^power10)*G1
    				if (power10[offset_index] != 0) {
    					point = ecMath.Multiply(point, 10**power10[offset_index]);
    				}
    			
    				//Calculate V + offset*H = v*H + bf*G1 + offset*H = (v + offset)*H + bf*G1
    				if (offsets[offset_index] != 0) {
    					point = ecMath.AddMultiplyH(point, offsets[offset_index]);
    				}
    				
    				//Mark balance as positive
    				point[0] = ecMath.CompressPoint(point);
    				balance_positive[point[0]] = true;
    				
    				//Emit event
    				temp[0] = (10**power10[offset_index]);                     //Resolution
    				temp[1] = (2**args[p].N-1)*temp[0]+offsets[offset_index];  //Max Value
    				emit PCRangeProvenEvent(point[0], offsets[offset_index], temp[1], temp[0]);
					
					//Increment indices
					offset_index++;
				}
			}
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
    function Send(RingCTTxStruct.Data args)
        internal requireECMath requireRingCTTxVerify returns (bool success)
    {
		//Verify output commitments have been proven positive
		if(!CheckBalancePositive(args.output_tx)) return false;
		
		//Verify key images are unused
        if (!CheckKeyImages(args.I)) return false;
		
		//Check Ring CT Tx for Validity
        if (!ringcttxverify.ValidateRingCTTx(RingCTTxStruct.Serialize(args))) return false;
		
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
        
        RingCTTxStruct.Data memory args = RingCTTxStruct.Data(0, 0, input_tx, output_tx, I, signature);
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
    function Withdraw(RingCTTxStruct.Data args)
        internal requireECMath requireRingCTTxVerify returns (bool success)
    {
		//Verify output commitments have been proven positive
		if(!CheckBalancePositive(args.output_tx)) return false;
		
		//Verify key images are unused
        if (!CheckKeyImages(args.I)) return false;
		
		//Check Ring CT Tx for Validity
        if (!ringcttxverify.ValidateRingCTTx(RingCTTxStruct.Serialize(args))) return false;
        
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
        
        RingCTTxStruct.Data memory args = RingCTTxStruct.Data(redeem_eth_address, redeem_eth_value, input_tx, output_tx, I, signature);
        return Withdraw(args);
    }
}

library BorromeanRangeProofStruct {
	//Structure for VerifyPCRangeProof() arguments
	struct Data {
		uint256[2] total_commit;
		uint256 power10;
		uint256 offset;
		uint256[] bit_commits;
		uint256[] signature;
	}
	
	//Creates Borromean Range Proof Args struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data args)
	{
		//Check input length, need at least 6 arguments - assuming all variable arrays are zero length and only store the size
		require(argsSerialized.length >= 6);
		
		//Deserialize
		uint256 i;
		uint256 index;
		uint256 length;
		args.total_commit = [argsSerialized[0], argsSerialized[1]];
		args.power10 = argsSerialized[2];
		args.offset = argsSerialized[3];
		
		//Initialize Arrays
		length = argsSerialized[4];
		if (length > 0) args.bit_commits = new uint256[](length);
		
		length = argsSerialized[5];
		if (length > 0) args.signature = new uint256[](length);
		
		//Check input length again
		require(argsSerialized.length >= (6 + args.bit_commits.length + args.signature.length));
		
		//Assemble the rest of args
		index = 6;
		for (i = 0; i < args.bit_commits.length; i++) {
			args.bit_commits[i] = argsSerialized[index+i];
		}
		index = index + args.bit_commits.length;
		
		for (i = 0; i < args.signature.length; i++) {
			args.signature[i] = argsSerialized[index+i];
		}
	}
	
	//Decomposes Borromean Range Proof Args struct into uint256 array
	function Serialize(Data args)
		internal pure returns (uint256[] argsSerialized)
	{
		argsSerialized = new uint256[](6 + args.bit_commits.length + args.signature.length);
		
		argsSerialized[0] = args.total_commit[0];
		argsSerialized[1] = args.total_commit[1];
		argsSerialized[2] = args.power10;
		argsSerialized[3] = args.offset;
		argsSerialized[4] = args.bit_commits.length;
		argsSerialized[5] = args.signature.length;
		
		uint256 i;
		uint256 index = 6;		
		for (i = 0; i < args.bit_commits.length; i++) {
		    argsSerialized[index+i] = args.bit_commits[i];
		}
		index = index + args.bit_commits.length;
		
		for (i = 0; i < args.signature.length; i++) {
		    argsSerialized[index+i] = args.signature[i];
		}
	}
	
	function EchoTest(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return Serialize(Deserialize(argsSerialized));
	}
}

library BulletproofStruct {
	//Structure for VerifyBulletproof() arguments
	struct Data {
		uint256[] V;
		uint256[2] A;
		uint256[2] S;
		uint256[2] T1;
		uint256[2] T2;
		uint256 taux;
		uint256 mu;
		uint256[] L;
		uint256[] R;
		uint256 a;
		uint256 b;
		uint256 t;
		uint256 N;
	}	

	//Creates Bullet Proof struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data[] args)
	{
		//Check input length, need at least 1 argument - assuming all variable arrays are zero length and only store the size
		require(argsSerialized.length >= 1);
		
		//Deserialize
		uint256 i;
		uint256 proof;
		uint256 index;
		uint256 length;
		
		//Get proof count
		length = argsSerialized[0];
		args = new Data[](length);
		
		index = 1;
		for (proof = 0; proof < args.length; proof++) {
		    //Initialize V, L, and R arrays
		    length = argsSerialized[index];
		    if (length > 0) args[proof].V = new uint256[](length);
		    
            length = argsSerialized[index+1];
    		if (length > 0) args[proof].L = new uint256[](length);
    		
    		length = argsSerialized[index+2];
    		if (length > 0) args[proof].R = new uint256[](length);
    		
    		//Check array length again
    		require(argsSerialized.length >= (index + 17 +
    		                                    args[proof].V.length +
    		                                    args[proof].L.length +
    		                                    args[proof].R.length));
    		index += 3;
		    
		    //Get V array
		    length = args[proof].V.length;
		    for (i = 0; i < length; i++) {
		        args[proof].V[i] = argsSerialized[index+i];
		    }
		    index += length;
		    
		    //Get A, S, T1, taux, an mu
    		args[proof].A = [argsSerialized[index], argsSerialized[index+1]];
    		args[proof].S = [argsSerialized[index+2], argsSerialized[index+3]];
    		args[proof].T1 = [argsSerialized[index+4], argsSerialized[index+5]];
    		args[proof].T2 = [argsSerialized[index+6], argsSerialized[index+7]];
    		args[proof].taux = argsSerialized[index+8];
    		args[proof].mu = argsSerialized[index+9];
    		index += 10;
    		
    		//Get L Array
    		length = args[proof].L.length;
    		for (i = 0; i < length; i++) {
    			args[proof].L[i] = argsSerialized[index+i];
    		}
    		index += length;
    		
    		length = args[proof].R.length;
    		for (i = 0; i < length; i++) {
    			args[proof].R[i] = argsSerialized[index+i];
    		}
    		index += length;
    		
    		args[proof].a = argsSerialized[index];
    		args[proof].b = argsSerialized[index+1];
    		args[proof].t = argsSerialized[index+2];
    		args[proof].N = argsSerialized[index+3];
    		index += 4;
		}
	}
	
	//Decomposes Bulletproof struct into uint256 array
	function Serialize(Data[] args)
		internal pure returns (uint256[] argsSerialized)
	{
	    //Calculate total args length
	    uint256 proof;
	    uint256 length = 1;
	    for (proof = 0; proof < args.length; proof++) {
	        length += 17 + args[proof].V.length + args[proof].L.length + args[proof].R.length;
	    }
		argsSerialized = new uint256[](length);
		
		//Store proof count
		argsSerialized[0] = args.length;
		
		//Assemble proofs
		uint256 i;
	    uint256 index = 1;
		for (proof = 0; proof < args.length; proof++) {
		    //Store V, L, and R sizes
		    argsSerialized[index] = args[proof].V.length;
		    argsSerialized[index+1] = args[proof].L.length;
		    argsSerialized[index+2] = args[proof].R.length;
		    index += 3;
		    
		    //Store V[]
		    length = args[proof].V.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].V[i];
		    }
		    index += length;
		    
		    //Store A, S, T1, T2, taux, mu, len(L), and len(R)
		    argsSerialized[index] = args[proof].A[0];
    		argsSerialized[index+1] = args[proof].A[1];
    		argsSerialized[index+2] = args[proof].S[0];
    		argsSerialized[index+3] = args[proof].S[1];
    		argsSerialized[index+4] = args[proof].T1[0];
    		argsSerialized[index+5] = args[proof].T1[1];
    		argsSerialized[index+6] = args[proof].T2[0];
    		argsSerialized[index+7] = args[proof].T2[1];
    		argsSerialized[index+8] = args[proof].taux;
    		argsSerialized[index+9] = args[proof].mu;
    		index += 10;
    		
    		//Store L[]
    		length = args[proof].L.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].L[i];
		    }
		    index += length;

    		//Store R[]
    		length = args[proof].R.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].R[i];
		    }
		    index += length;
		    
		    //Store a, b, t, and N
		    argsSerialized[index] = args[proof].a;
		    argsSerialized[index+1] = args[proof].b;
		    argsSerialized[index+2] = args[proof].t;
		    argsSerialized[index+3] = args[proof].N;
		    index += 4;
		}
	}
	
	function EchoTest(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return Serialize(Deserialize(argsSerialized));
	}
}

library RingCTTxStruct {
    //Structure for ValidateRingCTTx() arguments
    struct Data {
		address redeem_eth_address;
		uint256 redeem_eth_value;
		UTXO.Input[] input_tx;
		UTXO.Output[] output_tx;
		uint256[] I;
		uint256[] signature;
	}
    
    //Creates RingCT Tx Args struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data args)
	{
		//Check input length, need at least 8 arguments - assuming all arrays are zero length and only store the size
		require(argsSerialized.length >= 6);
		
		//Deserialize
		uint256 i;
		uint256 index;
		uint256 length;
		args.redeem_eth_address = address(argsSerialized[0]);
		args.redeem_eth_value = argsSerialized[1];
		
		//Initialize Arrays
		length = argsSerialized[2];
		if (length > 0) args.input_tx = new UTXO.Input[](length);
		
		length = argsSerialized[3];
		if (length > 0) args.output_tx = new UTXO.Output[](length);
		
		length = argsSerialized[4];
		if (length > 0) args.I = new uint256[](length);
		
		length = argsSerialized[5];
		if (length > 0) args.signature = new uint256[](length);
		
		//Check input length again
		require(argsSerialized.length >= (6 + args.input_tx.length*4 + args.output_tx.length*9 + args.I.length + args.signature.length));
		
		//Assemble the rest of args
		index = 6;
		for (i = 0; i < args.input_tx.length; i++) {
			args.input_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
			args.input_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
			index = index + 4;
		}

		for (i = 0; i < args.output_tx.length; i++) {
			args.output_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
			args.output_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
			args.output_tx[i].dhe_point = [argsSerialized[index+4], argsSerialized[index+5]];
			args.output_tx[i].encrypted_data = [argsSerialized[index+6], argsSerialized[index+7], argsSerialized[index+8]];
			index = index + 9;
		}
		
		for (i = 0; i < args.I.length; i++) {
			args.I[i] = argsSerialized[index+i];
		}
		index = index + args.I.length;
		
		for (i = 0; i < args.signature.length; i++) {
			args.signature[i] = argsSerialized[index+i];
		}
	}
	
	//Decomposes Ring CT Tx Args struct into uint256 array
	function Serialize(Data args)
		internal pure returns (uint256[] argsSerialized)
	{
		argsSerialized = new uint256[](6 + args.input_tx.length*4 + args.output_tx.length*9 + args.I.length + args.signature.length);
		
		argsSerialized[0] = uint256(args.redeem_eth_address);
		argsSerialized[1] = args.redeem_eth_value;
		argsSerialized[2] = args.input_tx.length;
		argsSerialized[3] = args.output_tx.length;
		argsSerialized[4] = args.I.length;
		argsSerialized[5] = args.signature.length;
		
		uint256 i;
		uint256 index = 6;
		for (i = 0; i < args.input_tx.length; i++) {
			argsSerialized[index] = args.input_tx[i].pub_key[0];
			argsSerialized[index+1] = args.input_tx[i].pub_key[1];
			argsSerialized[index+2] = args.input_tx[i].value[0];
			argsSerialized[index+3] = args.input_tx[i].value[1];
			index = index + 4;
		}
		
		for (i = 0; i < args.output_tx.length; i++) {
			argsSerialized[index] = args.output_tx[i].pub_key[0];
			argsSerialized[index+1] = args.output_tx[i].pub_key[1];
			argsSerialized[index+2] = args.output_tx[i].value[0];
			argsSerialized[index+3] = args.output_tx[i].value[1];
			argsSerialized[index+4] = args.output_tx[i].dhe_point[0];
			argsSerialized[index+5] = args.output_tx[i].dhe_point[1];
			argsSerialized[index+6] = args.output_tx[i].encrypted_data[0];
			argsSerialized[index+7] = args.output_tx[i].encrypted_data[1];
			argsSerialized[index+8] = args.output_tx[i].encrypted_data[2];
			index = index + 9;
		}
		
		for (i = 0; i < args.I.length; i++) {
		    argsSerialized[index+i] = args.I[i];
		}
		index = index + args.I.length;
		
		for (i = 0; i < args.signature.length; i++) {
		    argsSerialized[index+i] = args.signature[i];
		}
	}
	
	function EchoTest(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return Serialize(Deserialize(argsSerialized));
	}
}

library UTXO {
    //Represents an input unspent transaction output (candidate for spending)
    struct Input {
        uint256[2] pub_key;
        uint256[2] value;
    }
    
    //Represents an output unspent transaction output (new stealth transaction output)
    struct Output {
        uint256[2] pub_key;
        uint256[2] value;
        uint256[2] dhe_point;
        uint256[3] encrypted_data;
    }
    
    //Create UTXO.Input[] struct aray from uint256 array
	//Used so that public functions can deal with structures
    function DeserializeInputArray(uint256[] argsSerialized)
        internal pure returns (Input[] input_tx)
    {
        //Must at least specify length
        require(argsSerialized.length > 0);
        
        //Allocate array
        input_tx = new Input[](argsSerialized[0]);
        
        //Must have sufficient array size
        require(argsSerialized.length >= (1 + input_tx.length*4));
        
        //Fill in input_tx parameters
        uint256 i;
        uint256 index = 1;
        for (i = 0; i < input_tx.length; i++) {
            input_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
            input_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
            index = index + 4;
        }
    }
	
	//Convert UTXO.Input[] into uint256 array
	//Used so that public functions can deal with structures
    function SerializeInputArray(Input[] input_tx)
        internal pure returns (uint256[] argsSerialized)
    {
		//Allocate data
		argsSerialized = new uint256[](1 + input_tx.length*4);
		argsSerialized[0] = input_tx.length;
		
		//Serialize
		uint256 i;
		uint256 index = 1;
		for (i = 0; i < input_tx.length; i++) {
			argsSerialized[index] = input_tx[i].pub_key[0];
			argsSerialized[index+1] = input_tx[i].pub_key[1];
			argsSerialized[index+2] = input_tx[i].value[0];
			argsSerialized[index+3] = input_tx[i].value[1];
			index = index + 4;
		}
    }
	
	//Create UTXO.Output[] struct aray from uint256 array
	//Used so that public functions can deal with structures
	function DeserializeOutputArray(uint256[] argsSerialized)
        internal pure returns (Output[] output_tx)
    {
		//Must at least specify length
        require(argsSerialized.length > 0);
        
        //Allocate array
        output_tx = new Output[](argsSerialized[0]);
        
        //Must have sufficient array size
        require(argsSerialized.length >= (1 + output_tx.length*9));
        
        //Fill in output_tx parameters
        uint256 i;
        uint256 index = 1;
        for (i = 0; i < output_tx.length; i++) {
            output_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
            output_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
			output_tx[i].dhe_point = [argsSerialized[index+4], argsSerialized[index+5]];
			output_tx[i].encrypted_data = [argsSerialized[index+6], argsSerialized[index+7], argsSerialized[index+8]];
            index = index + 9;
        }
    }
	
	//Convert UTXO.Output[] into uint256 array
	//Used so that public functions can deal with structures
    function SerializeOutputArray(Output[] output_tx)
        internal pure returns (uint256[] argsSerialized)
    {
		//Allocate data
		argsSerialized = new uint256[](1 + output_tx.length*9);
		argsSerialized[0] = output_tx.length;
		
		//Serialize
		uint256 i;
		uint256 index = 1;
		for (i = 0; i < output_tx.length; i++) {
			argsSerialized[index] = output_tx[i].pub_key[0];
			argsSerialized[index+1] = output_tx[i].pub_key[1];
			argsSerialized[index+2] = output_tx[i].value[0];
			argsSerialized[index+3] = output_tx[i].value[1];
			argsSerialized[index+4] = output_tx[i].dhe_point[0];
			argsSerialized[index+5] = output_tx[i].dhe_point[1];
			argsSerialized[index+6] = output_tx[i].encrypted_data[0];
			argsSerialized[index+7] = output_tx[i].encrypted_data[1];
			argsSerialized[index+8] = output_tx[i].encrypted_data[2];
			index = index + 9;
		}
    }
    
    //Create UTXO.Input[] struct array from inputs
	//Used so that public functions can deal with structures
	function CreateInputArray(uint256[] input_pub_keys, uint256[] input_values)
		internal pure returns (Input[] input_tx)
	{
	    //Check input array lengths
	    require(input_pub_keys.length % 2 == 0);
	    require(input_values.length == input_pub_keys.length);
	    
	    //Create input_tx and output_tx
	    input_tx = new Input[](input_pub_keys.length / 2);
	    
	    uint256 i;
	    uint256 index;
	    for (i = 0; i < input_tx.length; i++) {
	        index = 2*i;
	        input_tx[i].pub_key[0] = input_pub_keys[index];
	        input_tx[i].pub_key[1] = input_pub_keys[index+1];
	        
	        input_tx[i].value[0] = input_values[index];
	        input_tx[i].value[1] = input_values[index+1];
	    }
	}
	
	//Create UTXO.Output[] struct array from inputs
	//Used so that public functions can deal with structures
	function CreateOutputArray(uint256[] output_pub_keys, uint256[] output_values, uint256[] output_dhe_points, uint256[] output_encrypted_data)
		internal pure returns (Output[] output_tx)
	{
		//Check output array lengths
	    require(output_pub_keys.length % 2 == 0);
	    require(output_values.length == output_pub_keys.length);
	    require(output_dhe_points.length == output_pub_keys.length);
	    require(output_encrypted_data.length == 3*(output_pub_keys.length / 2));
	    
	    //Create input_tx and output_tx
	    output_tx = new Output[](output_pub_keys.length / 2);
	    
	    uint256 i;
	    uint256 index;	    
	    for (i = 0; i < output_tx.length; i++) {
	        index = 2*i;
	        output_tx[i].pub_key[0] = output_pub_keys[index];
	        output_tx[i].pub_key[1] = output_pub_keys[index+1];
	        
	        output_tx[i].value[0] = output_values[index];
	        output_tx[i].value[1] = output_values[index+1];
	        
	        output_tx[i].dhe_point[0] = output_dhe_points[index];
	        output_tx[i].dhe_point[1] = output_dhe_points[index+1];
	        
	        index = 3*i;
	        output_tx[i].encrypted_data[0] = output_encrypted_data[index];
	        output_tx[i].encrypted_data[1] = output_encrypted_data[index+1];
	        output_tx[i].encrypted_data[2] = output_encrypted_data[index+2];
	    }
	}
	
	function EchoTestInput(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return SerializeInputArray(DeserializeInputArray(argsSerialized));
	}
	
	function EchoTestOutput(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return SerializeOutputArray(DeserializeOutputArray(argsSerialized));
	}
}

