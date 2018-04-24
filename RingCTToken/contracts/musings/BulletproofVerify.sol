pragma solidity ^0.4.22;

import "./Debuggable.sol";
import "./ECMathInterface.sol";

contract BulletProofVerify is ECMathInterface {
    //Scalar Modulo - Used to reduce calls to ecMath
    uint256 scalar_modulo;
    
    function UpdateScalarModulo() public {
		//Reassign scalar_modulo
		scalar_modulo = ecMath.GetNCurve();
	}
    
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor() public { }
	
	//BulletProof Tuple
	struct BulletProof {
	    uint256[2] V;
	    uint256[2] A;
	    uint256[2] S;
	    uint256[2] T1;
	    uint256[2] T2;
	    uint256 taux;
	    uint256 mu;
	    uint256 a;
	    uint256 b;
	    uint256 t;
	    uint256[] L;
	    uint256[] R;
	}
	
	//Internal Functions
	function hf(uint256 scalar)
	    internal constant returns (uint256)
	{
	    scalar = scalar % scalar_modulo;
	    return uint256(keccak256(scalar)) % scalar_modulo;    
	}
	
	function hf(uint256[2] p)
	    internal constant returns (uint256)
	{
	    return uint256(keccak256(p[0], p[1])) % scalar_modulo;    
	}
	
	function hf(uint256 prevHash, uint256 nextScalar)
	    internal constant returns (uint256)
	{
	    nextScalar = nextScalar % scalar_modulo;
	    return uint256(keccak256(prevHash, nextScalar)) % scalar_modulo;    
	}
	
	function hf(uint256 prevHash, uint256[2] p)
	    internal constant returns (uint256)
	{
	    return uint256(keccak256(prevHash, p[0], p[1])) % scalar_modulo;
	}
	
	//Internal Scalar Functions
	function sNegate(uint256 a)
	    internal constant returns (uint256)
	{
	    if (a >= scalar_modulo) {
	        a = a % scalar_modulo;
	    }
	    
		return scalar_modulo - a;
	}
	
	function sAdd(uint256 a, uint256 b)
		internal constant returns (uint256)
	{
		return addmod(a, b, scalar_modulo);
	}
	
	function sSub(uint256 a, uint256 b)
		internal constant returns (uint256)
	{
	    if (b >= scalar_modulo) {
	        b = b % scalar_modulo;
	    }
		return addmod(a, sNegate(b), scalar_modulo);
	}
	
	function sMul(uint256 a, uint256 b)
		internal constant returns (uint256)
	{
		return mulmod(a, b, scalar_modulo);
	}
	
	function sSq(uint256 a)
		internal constant returns (uint256)
	{
		return mulmod(a, a, scalar_modulo);
	}
	
	function sPow(uint256 a, uint256 p)
		internal constant returns (uint256 out)
	{
	    if (p == 0) return 1;
	    
	    out = a;
	    for (uint256 i = 1; i < p; i++) {
	        out = mulmod(out, a, scalar_modulo);
	    }
	    
		return out;
	}
	
	function sModInv(uint256 a)
	    internal constant returns (uint256 out)
	{
	    if (a >= scalar_modulo) {
	        a = a % scalar_modulo;
	    }
	    
	    require(a > 0);
	    
	    int256 t1;
        int256 t2 = 1;
        uint256 r1 = scalar_modulo;
        uint256 r2 = a;
        uint256 q;
        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int256(q) * t2, r2, r1 - q * r2);
        }
        
        if (t1 < 0) {
            return (scalar_modulo - uint256(-t1));
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
	
	function Verify(BulletProof bp, uint256 N) internal constant requireECMath returns (bool) {
	    //Check for scalar modulo, if zero scalar_modulo must be initialied first
	    require(scalar_modulo > 0);
	    
	    //Memory storage for stack variables - reduces stack size
	    VerifyVariables memory vv;
	    
	    //Calculate Reconstruct Challenges
	    vv.y = hf( hf( hf(bp.V), bp.A ), bp.S );
	    vv.z = hf(vv.y);
	    vv.x = hf( hf( hf(vv.z, vv.z), bp.T1 ), bp.T2 );
	    
	    //Construct Left and Right Points, P1 and P2
	    vv.P1 = ecMath.CommitG1H(bp.taux, bp.t);
	
	    vv.y_powers = vector_powers(vv.y, N);
        vv.k = sNegate( sAdd (
                sMul( sSq(vv.z),   vector_sum( vv.y_powers ) ),
                sMul( sPow(vv.z, 3), vector_sum( vector_powers(2, N) ) )
        ));
        
        vv.P2 = ecMath.MultiplyH(sAdd(vv.k, sMul(vv.z, vector_sum(vv.y_powers))));
        vv.P2 = ecMath.AddMultiply(vv.P2, bp.V, sSq(vv.z));
        vv.P2 = ecMath.AddMultiply(vv.P2, bp.T1, vv.x);
        vv.P2 = ecMath.AddMultiply(vv.P2, bp.T2, sSq(vv.x));
        
        //P1 must equal P2
        if (!ecMath.Equals(vv.P1, vv.P2)) return false;
        
        //Compute inner product challenges
        vv.rounds = bp.L.length;
        vv.w = new uint256[](vv.rounds);
        vv.w[0] = vv.x;
        if (vv.rounds > 1) {
            for (vv.i = 0; vv.i < vv.rounds; vv.i++) {
                vv.w[vv.i] = hf( hf(vv.w[vv.i-1], bp.L[vv.i]), bp.R[vv.i]);
            }
        }
        
        //Rounds
        vv.P1 = ecMath.AddMultiply(bp.A, bp.S, vv.x);
        for (vv.i = 0; vv.i < N; vv.i++) {
            vv.index = vv.i;
        }
	}
	
	function Verify_User(uint256[10] points,	//Vx, Vy, Ax, Ay, Sx, Sy, T1x, T1y, T2x, T2y
							uint256[6] scalars,	//taux, mu, a, b, t
							uint256 N,          //Vector length - # of bits
							uint256[] L, uint256[] R)
	    public constant returns (bool)
	{
	    return Verify(BulletProof(	[points[0], points[1]],				//V
									[points[2], points[3]],				//A
									[points[4], points[5]],				//S
									[points[6], points[7]],				//T1
									[points[8], points[9]],				//T2
									scalars[0], scalars[1],				//taux, mu
									scalars[2], scalars[3], scalars[4], //a, b, t
									L, R), N);
	}
}

