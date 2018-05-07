pragma solidity ^0.4.22;

library BulletproofStruct {
	//Structure for VerifyBulletproof() arguments
	struct Data {
		uint256[2] V;
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
	}
	
	//Creates Bullet Proof struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data args)
	{
		//Check input length, need at least 17 arguments - assuming all variable arrays are zero length and only store the size
		require(argsSerialized.length >= 17);
		
		//Deserialize
		uint256 i;
		uint256 index;
		uint256 length;
		args.V = [argsSerialized[0], argsSerialized[1]];
		args.A = [argsSerialized[2], argsSerialized[3]];
		args.S = [argsSerialized[4], argsSerialized[5]];
		args.T1 = [argsSerialized[6], argsSerialized[7]];
		args.T2 = [argsSerialized[8], argsSerialized[9]];
		args.taux = argsSerialized[10];
		args.mu = argsSerialized[11];
		
		//Initialize Arrays
		length = argsSerialized[12];
		if (length > 0) args.L = new uint256[](length);
		
		length = argsSerialized[13];
		if (length > 0) args.R = new uint256[](length);
		
		//Check input length again
		require(argsSerialized.length >= (17 + args.L.length + args.R.length));
		
		//Assemble the rest of args
		index = 14;
		for (i = 0; i < args.L.length; i++) {
			args.L[i] = argsSerialized[index+i];
		}
		index = index + args.L.length;
		
		for (i = 0; i < args.R.length; i++) {
			args.R[i] = argsSerialized[index+i];
		}
		index = index + args.R.length;
		
		args.a = argsSerialized[index];
		args.b = argsSerialized[index+1];
		args.t = argsSerialized[index+2];
	}
	
	//Decomposes Bulletproof struct into uint256 array
	function Serialize(Data args)
		internal pure returns (uint256[] argsSerialized)
	{
		argsSerialized = new uint256[](17 + args.L.length + args.R.length);
		
		argsSerialized[0] = args.V[0];
		argsSerialized[1] = args.V[1];
		argsSerialized[2] = args.A[0];
		argsSerialized[3] = args.A[1];
		argsSerialized[4] = args.S[0];
		argsSerialized[5] = args.S[1];
		argsSerialized[6] = args.T1[0];
		argsSerialized[7] = args.T1[1];
		argsSerialized[8] = args.T2[0];
		argsSerialized[9] = args.T2[1];
		argsSerialized[10] = args.taux;
		argsSerialized[11] = args.mu;
		argsSerialized[12] = args.L.length;
		argsSerialized[13] = args.R.length;
		
		uint256 i;
		uint256 index = 14;		
		for (i = 0; i < args.L.length; i++) {
		    argsSerialized[index+i] = args.L[i];
		}
		index = index + args.L.length;
		
		for (i = 0; i < args.R.length; i++) {
		    argsSerialized[index+i] = args.R[i];
		}
		index = index + args.R.length;
		
		argsSerialized[index] = args.a;
		argsSerialized[index+1] = args.b;
		argsSerialized[index+1] = args.t;
	}
}