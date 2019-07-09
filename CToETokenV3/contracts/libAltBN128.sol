pragma solidity ^0.5.9;

library AltBN128 {
    //Scalar Functions
	function GetN() internal pure returns (uint) {
		return 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
	}
	
	function GetP() internal pure returns (uint) {
		return 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
	}
	
	function GetCompressedPointSignFlag() internal pure returns (uint) {
	    return 0x8000000000000000000000000000000000000000000000000000000000000000;
	}
	
	function NegateFQ(uint fq) internal pure returns (uint) {
		return GetP() - (fq % GetP());
	}
	
	function NegateScalar(uint s) internal pure returns (uint) {
		return GetN() - (s % GetN());
	}
	
	//Point Functions
	function GetG1() internal pure returns (uint G1x, uint G1y) {
	    return (1, 2);
	}
	
	//Checks to see if point is zero
	function IsZero(uint Px, uint Py) internal pure returns (bool) {
	    return (Px == 0 && Py == 0);
	}
	
	function CompressPoint(uint Px, uint Py) internal pure returns (uint x_compressed) {
	    x_compressed = Px;
        
        if (Py & 1 != 0) {
            x_compressed |= GetCompressedPointSignFlag();
        }
	}
	
	function ExpandPoint(uint x_compressed) internal view returns (uint Px, uint Py) {
        //Check bit flag
        bool odd = (x_compressed & GetCompressedPointSignFlag() != 0);
        
        //Remove bit flag
        if (odd) {
            x_compressed &= ~GetCompressedPointSignFlag();
        }
        
        //Get y-coord
        (Px, Py) = G1PointFromX(x_compressed);
        
        //Check sign, correct if necessary
        if (odd) {
            if (Py & 1 == 0) {
                Py = NegateFQ(Py);
            }
        }
        else {
            if (Py & 1 == 1) {
                Py = NegateFQ(Py);
            }
        }
    }
	
	//Calculates G1 Point addition using precompile
	function AddPoints(uint Ax, uint Ay, uint Bx, uint By) internal view returns (uint Cx, uint Cy)	{
	    //Trivial Cases, no precompile call required
	    if (IsZero(Ax, Ay)) return (Bx, By);
	    if (IsZero(Bx, By)) return (Ax, Ay);
	    
	    uint[] memory data = new uint[](4);
	    data[0] = Ax;
	    data[1] = Ay;
	    data[2] = Bx;
	    data[3] = By;
	    
	    assembly {
	        //Call ECAdd
        	let success := staticcall(sub(gas, 2000), 0x06, add(data, 0x20), 0x80, add(data, 0x20), 0x40)
       	 
        	// Use "invalid" to make gas estimation work
         	switch success case 0 { revert(data, 0x80) }
	    }
	    
	    (Cx, Cy) = (data[0], data[1]);
	}
	
	//Check to see if G1Point is on curve
	function IsOnCurve(uint Px, uint Py) internal pure returns (bool) {
	    //(y^2 == x^3 + 3) % p
	    uint p = GetP();
	    uint left = mulmod(Py, Py, p);
	    uint right = addmod(mulmod(mulmod(Px, Px, p), Px, p), 3, p);
	    
	    return (left == right);
	}	
	
    //Get G1Point from desired x coordinate (increment x if not on curve)
	function G1PointFromX(uint x) internal view returns (uint Px, uint Py) {
	    uint p = GetP();
	    x = x % p;
	    
	    uint[] memory data = new uint[](6);
	    data[0] = 0x20;
	    data[1] = 0x20;
	    data[2] = 0x20;
	    //data[3] = 0;
	    data[4] = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;  // (p+1)/4
	    data[5] = p;
	    
        bool onCurve = false;
        while(!onCurve) {
            //Get y coordinate
    	    data[3] = addmod(mulmod(mulmod(x, x, p), x, p), 3, p);
    	    
    	    assembly {
    	        //Call Big Int Mod Exp: (y_squared)^a % p, store y in data[3]
        	    let success := staticcall(sub(gas, 2000), 0x05, add(data, 0x20), 0xC0, add(data, 0x80), 0x20)
    	    }
    	    
    	    //Check y coordinate
    	    onCurve = IsOnCurve(x, data[3]);
    	    if (!onCurve) {
    	        x = addmod(x, 1, p);
    	    }
        }
        
        (Px, Py) = (x, data[3]);
	}
	
	//Get G1Point from input address
	function G1PointFromAddress(address addr) internal view returns (uint Px, uint Py) {
	    uint x = uint(keccak256(abi.encodePacked(addr)));
	    return G1PointFromX(x);
	}
}