pragma solidity ^0.4.17;

contract RingMixerV2 {
    //Debug Code
    address public owner;
    function RingMixerV2() public {
        //Debug Code
        owner = msg.sender;
        
        G1[0] = 1;
        G1[1] = 2;
        H = HashPoint(G1);
    }
    
    function Kill() public {
        if ( (msg.sender != owner) && (owner != 0) ) revert();

        selfdestruct(msg.sender);
    }
    
    //alt_bn128 constants
    uint256[2] public G1;
    uint256[2] public H;
    uint256 constant public N = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 constant public P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    //Used for Point Compression/Decompression
    uint256 constant public ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000;
    uint256 constant public a = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52; // (p+1)/4
    
    //Ring message - Standard interface for ring signatures
    struct RingMessage {
        address[] destination;
        uint256[] value;
    }
   
    //Storage of Spent Key Images
    mapping (uint256 => bool) public KeyImageUsed;
    
    //Storage of Token Balances
    mapping (address => uint256) public token_balance;
    
    //Convenience tables for looking up acceptable mix-in keys
    mapping (uint256 => uint256[]) public lookup_pubkey_by_balance;
    mapping (uint256 => bool) public lookup_pubkey_by_balance_populated;
    mapping (uint256 => uint256) public lookup_pubkey_by_balance_count;
    
    //Transaction Functions
    //Deposit Ether as RingMixer tokens to the specified RingMixer address
    function Deposit(address destination)
        payable public returns (bool success)
    {
        //Address must have a zero balance (never used)
        require(token_balance[destination] == 0);
        
        //Incoming Value must be non-zero
        require(msg.value > 0);
        
        //Add tokens to balance corrosponding to the amount of Ether
        token_balance[destination] = msg.value;
        success = true;
    }
    
    //Equally distribute Ether as RingMixer tokens to the specified RingMixer addresses
    function DepositN(address[] destination)
        payable public returns (bool success)
    {
        //Must have more than one address specified
        require(destination.length > 0);
        
        //Incoming Value must be non-zero
        require(msg.value > 0);
            
        uint256 value = msg.value / destination.length;
        for (uint i = 0; i < destination.length; i++) {
            //Address must have a zero balance (never used)
            require(token_balance[destination[i]] == 0);
            
            //Add tokens to balance corrosponding to the amount of Ether
            token_balance[destination[i]] = value;
        }
        
        success = true;
    }
    
    //=== RingVerifyN ===
    //Inputs:
    //  destination (address[]) - list of payable ETH addresses
    //  value (uint256[]) - list of values corrosponding to the destination
    //  signature (uint256[2*N+2]) - ring signature
    //      signature[0] - keyimage for private key (compressed)
    //      signature[1] - c0 - start of ring signature - scaler for PublicKey[0]
    //      signature[2     ... 2+(N-1)] - s0...s[N-1], scalar for G1
    //      signature[2+N   ... 2*N+1  ] - Public Keys (compressed) - total of N Public Keys
    //      signature[2*N+2 ... 31     ] - Padding (0)
    //      e.g. N=3; signature = { Ik, c0, s0, s1, s2, PubKey0, PubKey1, PubKey2 }
    //Outputs:
    //  success (bool) - true/false indicating if signature is valid on message
    function Withdraw(address[] destination, uint256[] value, uint256[] signature)
        public returns (bool success) 
    {
        //Check Array Bounds
        require(destination.length == value.length);
        
        //Check for new key Image
        require(!KeyImageUsed[signature[0]]);
        
        //Get Ring Size
        uint256 ring_size = (signature.length - 2) / 2;
        
        //Check Values of Addresses - Must Match
        uint256 i;
        address addr;
        uint256 txValue;
        uint256 temp;
        for (i = 0; i < ring_size; i++) {
            temp = signature[2+ring_size+i];
            addr = GetAddress(temp);
            
            //On first i, fetch value
            if (i == 0) {
                txValue = token_balance[addr];
            }
            //Values must match first address
            else {
                require(txValue == token_balance[addr]);
            }
            
            //Update Lookup By Balance Table for Convenient Mix-ins
            if (!lookup_pubkey_by_balance_populated[temp]) {
                lookup_pubkey_by_balance[txValue].push(temp);
                lookup_pubkey_by_balance_populated[temp] = true;
                lookup_pubkey_by_balance_count[txValue]++;
            }
        }
        
        //Verify that the value to be sent spends the exact amount
        temp = 0;
        for (i = 0; i < value.length; i++) {
            if (value[i] > txValue) return false; //Check for crafty overflows
            temp += value[i];
        }
        if (temp != txValue) return false;
        
        //Check Ring for Validity
        success = RingVerify(RingMessage(destination, value), signature);
        
        //Pay out balance
        if (success) {
            KeyImageUsed[signature[0]] = true;
            for (i = 0; i < destination.length; i++) {
                destination[i].transfer(value[i]);
            }
        }
    }
    
    //Address Functions - Convert compressed public key into RingMixer address
    function GetAddress(uint256 PubKey)
        public constant returns (address addr)
    {
        uint256[2] memory temp;
        temp = ExpandPoint(PubKey);
        addr = address( keccak256(temp[0], temp[1]) );
    }
    
    //Base EC Functions
    function ecAdd(uint256[2] p0, uint256[2] p1)
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
    
    function ecMul(uint256[2] p0, uint256 s)
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
        uint256 y_squared = mulmod(x,x, P);
        y_squared = mulmod(y_squared, x, P);
        y_squared = addmod(y_squared, 3, P);
        
        uint256 p_local = P;
        uint256 a_local = a;
        
        assembly {
            //Get Free Memory Pointer
            let p := mload(0x40)
            
            //Store Data for Big Int Mod Exp Call
            mstore(p, 0x20)                 //Length of Base
            mstore(add(p, 0x20), 0x20)      //Length of Exponent
            mstore(add(p, 0x40), 0x20)      //Length of Modulus
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
        onCurve = (y_squared == mulmod(y, y, P));
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
                    Pout[1] = P - y;
                }
            }
            //Use Negative Y
            else {
                if ((y & 0x1) == 0x1) {
                    Pout[1] = P - y;
                } else {
                    Pout[1] = y;
                }
            }
        }
    }
    
    //=====Ring Signature Functions=====
    function HashFunction(RingMessage message, uint256[2] left, uint256[2] right)
        internal pure returns (uint256 h)
    {
        return (uint256(keccak256(message.destination, message.value, left[0], left[1], right[0], right[1])) % N);
    }
    
    //Return H = alt_bn128 evaluated at keccak256(p)
    function HashPoint(uint256[2] p)
        internal constant returns (uint256[2] h)
    {
        bool onCurve;
        h[0] = uint256(keccak256(p[0], p[1])) % N;
        
        while(!onCurve) {
            (h[1], onCurve) = EvaluateCurve(h[0]);
            h[0]++;
        }
        h[0]--;
    }

    function KeyImage(uint256 xk, uint256[2] Pk)
        internal constant returns (uint256[2] Ix)
    {
        //Ix = xk * HashPoint(Pk)
        Ix = HashPoint(Pk);
        Ix = ecMul(Ix, xk);
    }
    
    function RingStartingSegment(RingMessage message, uint256 alpha, uint256[2] P0)
        internal constant returns (uint256 c0)
    {
        //Memory Registers
        uint256[2] memory left;
        uint256[2] memory right;
        
        right = HashPoint(P0);
        right = ecMul(right, alpha);
        left = ecMul(G1, alpha);
        
        c0 = HashFunction(message, left, right);
    }
    
    function RingSegment(RingMessage message, uint256 c0, uint256 s0, uint256[2] P0, uint256[2] Ix)
        internal constant returns (uint256 c1)
    {
        //Memory Registers
        uint256[2] memory temp;
        uint256[2] memory left;
        uint256[2] memory right;
        
        //Deserialize Point
        (left[0], left[1]) = (P0[0], P0[1]);
        right = HashPoint(left);
        
        //Calculate left = c*P0 + s0*G1)
        left = ecMul(left, c0);
        temp = ecMul(G1, s0);
        left = ecAdd(left, temp);
        
        //Calculate right = s0*H(P0) + c*Ix
        right = ecMul(right, s0);
        temp = ecMul(Ix, c0);
        right = ecAdd(right, temp);
        
        c1 = HashFunction(message, left, right);
    }
    
    //SubMul = (alpha - c*xk) % N
    function SubMul(uint256 alpha, uint256 c, uint256 xk)
        internal pure returns (uint256 s)
    {
        s = mulmod(c, xk, N);
        s = N - s;
        s = addmod(alpha, s, N);        
    }
    
    //=== RingSignatureN ===
    //Inputs:
    //  message (RingMessage) - to be signed by the ring signature
    //  data (uint256[2*N+2]) - required data to form the signature where N is the number of Public Keys (ring size)
    //      data[0] - index from 0 to (N-1) specifying which Public Key has a known private key
    //      data[1] - corrosponding private key for PublicKey[k]
    //      data[2   ... 2+(N-1)] - Random Numbers - total of N random numbers
    //      data[2+N ... 2*N+1  ] - Public Keys (compressed) - total of N Public Keys
    //      e.g. N=3; data = {k, PrivateKey_k, random0, random1, random2, PubKey0, PubKey1, PubKey2 }
    //
    //Outputs:
    //  signature (uint256[32]) - resulting signature
    //      signature[0] - keyimage for private key (compressed)
    //      signature[1] - c0 - start of ring signature - scaler for PublicKey[0]
    //      signature[2     ... 2+(N-1)] - s0...s[N-1], scalar for G1
    //      signature[2+N   ... 2*N+1  ] - Public Keys (compressed) - total of N Public Keys
    //      signature[2*N+2 ... 31     ] - Padding (0)
    //      e.g. N=3; signature = { Ik, c0, s0, s1, s2, PubKey0, PubKey1, PubKey2 }
    function RingSign(RingMessage message, uint256[] data)
        internal constant returns (uint256[32] signature)
    {
        //Check Array Lengths
        require( data.length >= 6 ); //Minimum size (2 PubKeys) = (2*2+2) = 6
        require( data.length <= 32); //Max size - will only output 32 uint256's
        require( (data.length % 2) == 0 ); //data.length must be even
        uint256 ring_size = (data.length - 2) / 2;
        uint i;
        
        //Copy Random Numbers (most will become s-values) and Public Keys
        for (i = 2; i < data.length; i++) {
            signature[i] = data[i];
        }
        
        //Memory Registers
        uint256[2] memory pubkey;
        uint256[2] memory keyimage;
        uint256 c;
        
        //Setup Indices
        i = (data[0] + 1) % ring_size;
        
        //Calculate Key Image
        pubkey = ExpandPoint(data[2+ring_size+data[0]]);
        keyimage = KeyImage(data[1], pubkey);
        signature[0] = CompressPoint(keyimage);
        
        //Calculate Starting c = hash( message, alpha*G1, alpha*HashPoint(Pk) )
        c = RingStartingSegment(message, data[2+data[0]], pubkey);
        if (i == 0) {
            signature[1] = c;
        }
        
        for (; i != data[0];) {
            //Deserialize Point and calculate next Ring Segment
            pubkey = ExpandPoint(data[2+ring_size+i]);
            
            c = RingSegment(message, c, data[2+i], pubkey, keyimage);
    
            //Increment Counters
            i = i + 1;
            
            // Roll counters over
            if (i == ring_size) {
                i = 0;
                signature[1] = c;
            }
        }
        
        //Calculate s s.t. alpha*G1 = c1*P1 + s1*G1 = (c1*x1 + s1) * G1
        //s = alpha - c1*x1
        signature[2+data[0]] = SubMul(data[2+data[0]], c, data[1]);
    }
    
    function RingSign_User(address[] destination, uint256[] value, uint256[] data)
        public constant returns (uint256[32] signature)
    {
        return RingSign(RingMessage(destination, value), data);
    }
    
    //=== RingVerifyN ===
    //Inputs:
    //  message (RingMessage) - signed by the ring signature
    //  signature (uint256[2*N+2]) - ring signature
    //      signature[0] - keyimage for private key (compressed)
    //      signature[1] - c0 - start of ring signature - scaler for PublicKey[0]
    //      signature[2     ... 2+(N-1)] - s0...s[N-1], scalar for G1
    //      signature[2+N   ... 2*N+1  ] - Public Keys (compressed) - total of N Public Keys
    //      signature[2*N+2 ... 31     ] - Padding (0)
    //      e.g. N=3; signature = { Ik, c0, s0, s1, s2, PubKey0, PubKey1, PubKey2 }
    //Outputs:
    //  success (bool) - true/false indicating if signature is valid on message
    function RingVerify(RingMessage message, uint256[] signature)
        internal constant returns (bool success)
    {
        //Check Array Lengths
        require( signature.length >= 6 ); //Minimum size (2 PubKeys) = (2*2+2) = 6
        require( (signature.length % 2) == 0 ); //data.length must be even
        
        //Memory Registers
        uint256[2] memory pubkey;
        uint256[2] memory keyimage;
        uint256 c = signature[1];
        
        //Expand Key Image
        keyimage = ExpandPoint(signature[0]);
        
        //Verify Ring
        uint i = 0;
        uint256 ring_size = (signature.length - 2) / 2;
        for (; i < ring_size;) {
            //Deserialize Point and calculate next Ring Segment
            pubkey = ExpandPoint(signature[2+ring_size+i]);
            c = RingSegment(message, c, signature[2+i], pubkey, keyimage);
            
            //Increment Counters
            i = i + 1;
        }

        success = (c == signature[1]);
    }
    
    function RingVerify_User(address[] destination, uint256[] value, uint256[] signature)
        public constant returns (bool success)
    {
        return RingVerify(RingMessage(destination, value), signature);
    }
}
