pragma solidity ^0.4.22;

import "./Debuggable.sol";

contract ElipticCurve is Debuggable {
    //secp256k1
    //uint256 public constant Acurve = 0;
    //uint256 public constant Bcurve = 7;
    //uint256 public constant Ncurve = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    //uint256 public constant Pcurve = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
    
    //alt_bn128
    uint256 public constant Acurve = 0;
    uint256 public constant Bcurve = 3;
    uint256 public constant Ncurve = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 public constant Pcurve = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    
    constructor() public { }
    
    //Elliptic Curve Math
    function modinv(uint256 a)
	    internal pure returns (uint256 out)
	{
	    if (a >= Pcurve) {
	        a = a % Pcurve;
	    }
	    
	    require(a > 0);
	    
	    int256 t1;
        int256 t2 = 1;
        uint256 r1 = Pcurve;
        uint256 r2 = a;
        uint256 q;
        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int256(q) * t2, r2, r1 - q * r2);
        }
        
        if (t1 < 0) {
            return (Pcurve - uint256(-t1));
		}
        else {
			return uint256(t1);
		}
    }
    
    function negate(uint256 a)
        internal pure returns (uint256 out)
    {
        if (a >= Pcurve) {
            a = a % Pcurve;    
        }
        
        return (Pcurve - a);
    }
    
    function add(uint256 a, uint256 b)
        internal pure returns (uint256 out)
    {
        return addmod(a, b, Pcurve);
    }
    
    function sub(uint256 a, uint256 b)
        internal pure returns (uint256 out)
    {
        return addmod(a, negate(b), Pcurve);
    }
    
    function mul(uint256 a, uint256 b)
        internal pure returns (uint256 out)
    {
        return mulmod(a, b, Pcurve);
    }
    
    function div(uint256 a, uint256 b)
        internal pure returns (uint256 out)
    {
        return mulmod(a, modinv(b), Pcurve);
    }
    
    function pIsInfinity(uint256[2] p1)
        public pure returns (bool)
    {
        return (p1[0] == 0) && (p1[1] == 0);
    }
    
    function pEquals(uint256[2] p1, uint256[2] p2)
        public pure returns (bool)
    {
        return (p1[0] == p2[0]) && (p1[1] == p2[1]);
    }
    
    function pNegate(uint256[2] p1)
        public pure returns (uint256[2])
    {
        if (pIsInfinity(p1)) return p1;
        return [p1[0], Pcurve - p1[1]];
    }
    
    function pAdd(uint256[2] p1, uint256[2] p2)
        public pure returns (uint256[2] p3)
    {
        if (pIsInfinity(p1)) {
            return p2;
        }
        else if (pIsInfinity(p2)) {
            return p1;
        }
        
        uint256 lambda = div(sub(p2[1], p1[1]), sub(p2[0], p1[0]));
        
        p3[0] = sub(sub(mul(lambda, lambda),p1[0]),p2[0]);
        p3[1] = sub(mul(sub(p1[0],p3[0]),lambda),p1[1]);
    }
    
    function pDouble(uint256[2] p1)
        public pure returns (uint256[2] p3)
    {
        if (pIsInfinity(p1)) {
            return p1;
        }
        
        uint256 lambda;
        if (Acurve == 0) {
            lambda = div(mul(mul(p1[0], p1[0]), 3), mul(p1[1], 2));
        }
        else {
            lambda = div(add(mul(mul(p1[0], p1[0]), 3), Acurve), mul(p1[1], 2));
        }
        
        p3[0] = sub(mul(lambda, lambda),mul(p1[0],2));
        p3[1] = sub(mul(sub(p1[0],p3[0]),lambda),p1[1]);
    }
    
    //Addition and Multiplication
    function pMultiplyMontgomery(uint256[2] p1, uint256 s)
        public pure returns (uint256[2] p3)
    {
        if (s > Ncurve) s = s % Ncurve;
        
        uint256 i;
        uint256 m = 0x8000000000000000000000000000000000000000000000000000000000000000;
        for (i = 0; i < 256; i++) {
            if ((s & m) == 0) {
                p1 = pAdd(p1, p3);
                p3 = pDouble(p3);
            }
            else {
                p3 = pAdd(p1, p3);
                p1 = pDouble(p1);
            }
            
            //Shift m
            m = m >> 1;
        }
    }
    
    function pMultiply(uint256[2] p1, uint256 s)
        public pure returns (uint256[2] p3)
    {
        if (s > Ncurve) s = s % Ncurve;
        
        uint256 i;
        uint256 m = 1;
        for (i = 0; i < 256; i++) {
            if ((s & m) != 0) {
                p3 = pAdd(p3, p1);
            }
            
            p1 = pDouble(p1);
            
            //Shift m
            m = m << 1;
        }
    }
    
    function MultiplyGasTest(uint256[2] p1, uint256 s)
        public returns (uint256[2] p3)
    {
        return pMultiply(p1, s);
    }
}