pragma solidity ^0.4.22;

import "./Debuggable.sol";
import "./ECMathInterface.sol";

contract InnerProductVerify is ECMathInterface {
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor() public { }
	
	//Inner Product Proof Tuple
	struct InnerProductProof {
	    uint256[2] Cx;
	    uint256[2] Cy;
	    uint256[2] Cz;
	    uint256[2] C0;
	    uint256[2] C1;
	    uint256 rx;
	    uint256 sy;
	    uint256 tz;
	    uint256[] fx;
	    uint256[] fy;
	}
	
	//Internal Functions
	function hf(uint256 scalar)
	    internal constant returns (uint256)
	{
	    scalar = scalar % ecMath.GetNCurve();
	    return uint256(keccak256(scalar)) % ecMath.GetNCurve();    
	}
	
	function hf(uint256[2] p)
	    internal constant returns (uint256)
	{
	    return uint256(keccak256(p[0], p[1])) % ecMath.GetNCurve();    
	}
	
	function hf(uint256 prevHash, uint256 nextScalar)
	    internal constant returns (uint256)
	{
	    nextScalar = nextScalar % ecMath.GetNCurve();
	    return uint256(keccak256(prevHash, nextScalar)) % ecMath.GetNCurve();    
	}
	
	function hf(uint256 prevHash, uint256[2] p)
	    internal constant returns (uint256)
	{
	    return uint256(keccak256(prevHash, p[0], p[1])) % ecMath.GetNCurve();
	}
	
	//Internal Scalar Functions
	function sNegate(uint256 a)
	    internal constant returns (uint256)
	{
	    if (a >= ecMath.GetNCurve()) {
	        a = a % ecMath.GetNCurve();
	    }
	    
		return ecMath.GetNCurve() - a;
	}
	
	function sAdd(uint256 a, uint256 b)
		internal constant returns (uint256)
	{
		return addmod(a, b, ecMath.GetNCurve());
	}
	
	function sSub(uint256 a, uint256 b)
		internal constant returns (uint256)
	{
	    if (b >= ecMath.GetNCurve()) {
	        b = b % ecMath.GetNCurve();
	    }
		return addmod(a, sNegate(b), ecMath.GetNCurve());
	}
	
	function sMul(uint256 a, uint256 b)
		internal constant returns (uint256)
	{
		return mulmod(a, b, ecMath.GetNCurve());
	}
	
	function sSq(uint256 a)
		internal constant returns (uint256)
	{
		return mulmod(a, a, ecMath.GetNCurve());
	}
	
	function sPow(uint256 a, uint256 p)
		internal constant returns (uint256 out)
	{
	    if (p == 0) return 1;
	    
	    out = a;
	    for (uint256 i = 1; i < p; i++) {
	        out = mulmod(out, a, ecMath.GetNCurve());
	    }
	    
		return out;
	}
	
	function sModInv(uint256 a)
	    internal constant returns (uint256 out)
	{
	    if (a >= ecMath.GetNCurve()) {
	        a = a % ecMath.GetNCurve();
	    }
	    
	    require(a > 0);
	    
	    int256 t1;
        int256 t2 = 1;
        uint256 r1 = ecMath.GetNCurve();
        uint256 r2 = a;
        uint256 q;
        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int256(q) * t2, r2, r1 - q * r2);
        }
        
        if (t1 < 0) {
            return (ecMath.GetNCurve() - uint256(-t1));
		}
        else {
			return uint256(t1);
		}
    }
	
	//Internal Vector Functions
	function vector_const(uint256 s, uint256 size)
		internal pure returns (uint256[] vec)
	{
		vec = new uint256[](size);
		
		if (s > 0) {
			for (uint256 i = 0; i < vec.length; i++) {
				vec[i] = s;
			}
		}
	}
	
	function vector_sum(uint256[] vec1)
		internal pure returns (uint256 out)
	{
		for (uint256 i = 0; i < vec1.length; i++) {
			out = out + vec1[i];
		}
	}
	
	function vector_add(uint256[] vec1, uint256[] vec2)
		internal constant returns (uint256[] vec3)
	{
		require(vec1.length == vec2.length);
		
		vec3 = new uint256[](vec1.length);
		for (uint256 i = 0; i < vec1.length; i++) {
			vec3[i] = sAdd(vec1[i], vec2[i]);
		}
	}
	
	function vector_sub(uint256[] vec1, uint256[] vec2)
		internal constant returns (uint256[] vec3)
	{
		require(vec1.length == vec2.length);
		
		vec3 = new uint256[](vec1.length);
		for (uint256 i = 0; i < vec1.length; i++) {
			vec3[i] = sSub(vec1[i], vec2[i]);
		}
	}
	
	function vector_scale(uint256[] vec1, uint256 s)
	    internal constant returns (uint256[])
	{
	    
	    if (s == 0) return vector_const(0, vec1.length);
	    if (s == 1) return vec1;
	    
	    uint256[] memory vec2 = new uint256[](vec1.length);
	    for (uint256 i = 0; i < vec1.length; i++) {
	        vec2[i] = sMul(vec1[i], s);
	    }
	    return vec2;
	}
	
	function vector_powers(uint256 s, uint256 size)
	    internal pure returns (uint256[] vec)
	{
	    uint256 i;
	    uint256 temp;
	    vec = new uint256[](size);
	    
	    if (s == 0) {
	        //Do nothing, intialization is sufficient
	    }
	    else if (s == 1) {
	        vec = vector_const(1, size); //vec = [1, 1, 1, ..., 1]
	    }
	    else {
	        vec[0] = 1;
	        
	        temp = s;
	        if (size > 1) vec[1] = temp;
	        
	        for (i = 2; i < size; i++) {
	            temp = temp * s;
	            vec[i] = temp;
	        }
	    }
	}
	
	function vector_multiply(uint256[] vec1, uint256[] vec2)
	    internal constant returns (uint256[] vec3)
	{
	    assert(vec1.length == vec2.length);
	    
	    vec3 = new uint256[](vec1.length);
	    for (uint256 i = 0; i < vec1.length; i++) {
	        vec3[i] = sMul(vec1[i], vec2[i]);
	    }
	}
	
	function vector_inner_product(uint256[] vec1, uint256[] vec2)
	    internal constant returns (uint256 sum)
	{
	    assert(vec1.length == vec2.length);

	    for (uint256 i = 0; i < vec1.length; i++) {
	        sum = sAdd(sum, sMul(vec1[i], vec2[i]));
	    }
	}
	
	//Verification Function
	struct VerifyVariables {
	    uint256 x;
	    uint256 y;
	    uint256 z;
	    uint256 x_ip;
	    uint256 k;
	    uint256 i;
	    uint256 index;
	    uint256 rounds;
	    uint256[2] P1;
	    uint256[2] P2;
	    uint256[2] P3;
	    uint256[] w;
	    uint256[] y_powers;
	}
	
	function Verify(InnerProductProof p) internal constant returns (bool) {
	    //Memory storage for stack variables - reduces stack size
	    VerifyVariables memory vv;
	    
	    
	}
	
	function Verify_User(uint256[10] points,	//Cxx, Cxy, Cyx, Cyy, Czx, Czy, C0x, C0y, C1x, C1y
							uint256[3] scalars,	//rx, sy, tz
							uint256[] fx, uint256[] fy)
	    public constant returns (bool)
	{
	    return Verify(BulletProof(	[points[0], points[1]],				//Cx
									[points[2], points[3]],				//Cy
									[points[4], points[5]],				//Cz
									[points[6], points[7]],				//C0
									[points[8], points[9]],				//C1
									scalars[0], scalars[1], scalars[2],	//rx, sy, tz
									fx, fy));
	}
}

