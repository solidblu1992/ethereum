pragma solidity ^0.4.22;

import "./Debuggable.sol";
import "./ECMathInterface.sol";
import "./libBulletproofStruct.sol";

contract BulletproofVerify is ECMathInterface {
    uint256 public maxN;
	uint256 private NCurve;

	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address _ecMathAddr) ECMathInterface(_ecMathAddr) public {
	    RefreshECMathParameters();
	}
	
	function RefreshECMathParameters() ownerOnly requireECMath public {
	    NCurve = ecMath.GetNCurve();
	}
    
	//Verify single bullet proof
	struct Variables {
		uint256 x;
		uint256 y;
		uint256 z;
		uint256 k;
		uint256 x_ip;
		uint256 logN;
		uint256 N;
		uint256[] vp2;
		uint256[] vpy;
		uint256[] vpyi;
		uint256[] w;
		uint256[] Gi;
		uint256[] Hi;
		uint256[2] Left;
		uint256[2] Right;
	}
	
	function VerifyBulletproof(BulletproofStruct.Data bp)
	    internal constant requireECMath returns (bool) {
		//Check input array lengths
		if(bp.L.length < 2) return false;
		if(bp.L.length % 2 != 0) return false;
		if(bp.R.length != bp.L.length) return false;
		
		Variables memory v;
		v.logN = bp.L.length / 2;
		v.N = 2**(v.logN);
		if(v.N > ecMath.GetGiHiLength()) return false;
		
		//Start hashing for Fiat-Shamir
		v.y = uint256(keccak256(	bp.V[0], bp.V[1],
									bp.A[0], bp.A[1],
									bp.S[0], bp.S[1]	)) % NCurve;
											
		v.z = uint256(keccak256(	v.y	)) % NCurve;
		
		v.x = uint256(keccak256(	v.z,
									bp.T1[0], bp.T1[1],
									bp.T2[0], bp.T2[1]	)) % NCurve;
											
		v.x_ip = uint256(keccak256(	v.x,
									bp.taux, bp.mu, bp.t	)) % NCurve;
		
		//Check V, T1, T2, taux, and t
		v.vp2 = vPow(2, v.N);
		v.vpy = vPow(v.y, v.N);
		v.vpyi = vPow(sInv(v.y), v.N);
		v.k = sAdd(sMul(sSq(v.z), vSum(v.vpy)), sMul(sPow(v.z,3), vSum(v.vp2)));
        v.k = sNeg(v.k);				
		
		v.Left = ecMath.CommitG1H(bp.taux, bp.t);
		v.Right = ecMath.MultiplyH(sAdd(v.k, sMul(v.z, vSum(v.vpy))));
		v.Right = ecMath.AddMultiply(v.Right, bp.V, sSq(v.z));
		v.Right = ecMath.AddMultiply(v.Right, bp.T1, v.x);
		v.Right = ecMath.AddMultiply(v.Right, bp.T2, sSq(v.x));
		
		if (!ecMath.Equals(v.Left, v.Right)) return false;
		
		//Generate w challenges
		uint256 i;
		uint256 index;
		v.w = new uint256[](v.logN);
		v.w[0] = uint256(keccak256(	v.x_ip,
									bp.L[0], bp.L[1],
									bp.R[0], bp.R[1])) % NCurve;
									
		for (i = 1; i < v.logN; i++) {
		    index = 2*i;
		    v.w[i] = uint256(keccak256(	v.w[i-1],
									    bp.L[index], bp.L[index+1],
									    bp.R[index], bp.R[index+1])) % NCurve;
		}
		
		//Fetch Gi and Hi base points
		(v.Gi, v.Hi) = ecMath.GetGiHi(v.N);
		
		return (v.Gi[2*v.N-1] == v.Gi[2*v.N-1]);
	}
	
	function VerifyBulletproof(uint256[] argsSerialized) public returns (bool) {
		return VerifyBulletproof(BulletproofStruct.Deserialize(argsSerialized));
	}
	
	//Low level helper functions
	function sNeg(uint256 a) internal view returns (uint256 out) {
		out = NCurve - (a % NCurve);
	}
	
	function sAdd(uint256 a, uint256 b) internal view returns (uint256 out) {
		out = addmod(a, b, NCurve);
	}
	
	function sSub(uint256 a, uint256 b) internal view returns (uint256 out) {
		out = addmod(a, sNeg(b), NCurve);
	}
	
	function sMul(uint256 a, uint256 b) internal view returns (uint256 out) {
		out = mulmod(a, b, NCurve);
	}
	
	function sSq(uint256 a) internal view returns (uint256 out) {
		out = mulmod(a, a, NCurve);
	}
	
	function sPow(uint256 a, uint256 p) internal view returns (uint256 out) {
		out = a;
		for (uint256 i = 1; i < p; i++) {
			out = mulmod(out, a, NCurve);
		}
	}
	
	function sInv(uint256 a) internal view returns (uint256 out) {
		a = a % NCurve;
		require(a > 0);
			
        int256 t1;
        int256 t2 = 1;
        uint256 r1 = NCurve;
        uint256 r2 = a;
        uint256 q;
        
		while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
        }
		
        if (t1 < 0)
			out = (NCurve - uint256(-t1));
		else
			out = uint256(t1);
		
		if (sMul(a, out) != 1) revert();
		
        return out;
    }
	
	function vPow(uint256 x, uint256 N) internal view returns (uint256[] out) {
		out = new uint256[](N);
		
		if (x > 0) {
			out[0] = 1;
			for (uint256 i = 1; i < N; i++) {
				out[i] = sMul(out[i-1], x); 
			}
		}
	}
	
	function vSum(uint256[] a) internal view returns (uint256 out) {
		require(a.length > 0);
		
		out = a[0];
		for (uint256 i = 1; i < a.length; i++) {
			out = sAdd(out, a[i]);
		}
	}
	
	function vAdd(uint256[] a, uint256[] b) internal view returns (uint256[] out) {
		require(a.length > 0);
		require(a.length == b.length);
		
		out = new uint256[](a.length);

		for (uint256 i = 0; i < a.length; i++) {
			out[i] = sAdd(a[i], b[i]);
		}
	}
	
	function vSub(uint256[] a, uint256[] b) internal view returns (uint256[] out) {
		require(a.length > 0);
		require(a.length == b.length);
		
		out = new uint256[](a.length);

		for (uint256 i = 0; i < a.length; i++) {
			out[i] = sSub(a[i], b[i]);
		}
	}
	
	function vMul(uint256[] a, uint256[] b) internal view returns (uint256[] out) {
		require(a.length > 0);
		require(a.length == b.length);
		
		out = new uint256[](a.length);

		for (uint256 i = 0; i < a.length; i++) {
			out[i] = sMul(a[i], b[i]);
		}
	}
	
	function vScale(uint256[] a, uint256 s) internal view returns (uint256[] out) {
		require(a.length > 0);
		
		out = new uint256[](a.length);

		for (uint256 i = 0; i < a.length; i++) {
			out[i] = sMul(a[i], s);
		}
	}
	
	function vDot(uint256[] a, uint256[] b) internal view returns (uint256 out) {
		require(a.length > 0);
		require(a.length == b.length);

		out = sMul(a[0], b[0]);
		for (uint256 i = 1; i < a.length; i++) {
			out = sAdd(out, sMul(a[i], b[i]));
		}
	}
	
	function vSlice(uint256[] a, uint256 start, uint256 end) internal pure returns (uint256[] out) {
		require(a.length > 0);
		require(end > start);
		require(end <= a.length);
		
		out = new uint256[](end-start);
		
		for (uint256 i = start; i < end; i++) {
			out[i-start] = a[i];
		}
	}
	
	function pvSlice(uint256[] A, uint256 start, uint256 end) internal pure returns (uint256[] out) {
	    require(A.length > 1);
	    require(A.length % 2 == 0);
	    require(end > start);
		
		start = 2*start;
		end = 2*end;
		require(end <= A.length);
	
		out = new uint256[](end-start);
		for (uint256 i = start; i < end; i += 2) {
		    (out[i-start], out[i-start+1]) = (A[i], A[i+1]);
		}
	}
}

