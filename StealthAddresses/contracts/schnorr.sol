pragma solidity ^0.8.18;
import "./libaltbn128.sol";

contract SchnorrVerifier {
    constructor() {}

    function Verify(bytes32 message_hash, uint s, uint e, uint Yx, uint Yy) public view returns (bool) {
        //Basic Assertions
        require(s > 0);
        require(e > 0);
        require(!AltBN128.IsZero(Yx, Yy));
        require(AltBN128.IsOnCurve(Yx, Yy));
        
        //Perform Elliptic Curve Math
        uint Rvx;
        uint Rvy;
        {
            uint Sx;
            uint Sy;
            (Sx, Sy) = AltBN128.MultiplyG1(s);

            uint EYx;
            uint EYy;
            (EYx, EYy) = AltBN128.MultiplyPoint(Yx, Yy, e);
            (Rvx, Rvy) = AltBN128.AddPoints(Sx, Sy, EYx, EYy);
        }

        //Compute Hash
        uint ev = uint(sha256(abi.encodePacked(Rvx, Rvy, message_hash, Yx, Yy))) % AltBN128.GetN();

        return (ev == e);
    }

    function VerifyMulti(bytes32 message_hash, uint s, uint e, uint[] calldata Yx, uint[] calldata Yy) public view returns (bool) {
        //Basic Assertions
        require(s > 0);
        require(e > 0);
        require(Yx.length > 0);
        require(Yx.length == Yy.length);

        for (uint i = 0; i < Yx.length; i++) {
            require(!AltBN128.IsZero(Yx[i], Yy[i]));
            require(AltBN128.IsOnCurve(Yx[i], Yy[i]));
        }
        
        //Perform Elliptic Curve Math
        uint Rvx;
        uint Rvy;
        {
            uint Sx;
            uint Sy;
            (Sx, Sy) = AltBN128.MultiplyG1(s);

            uint EYx = Yx[0];
            uint EYy = Yy[0];
            for (uint i = 1; i < Yx.length; i++) {
                (EYx, EYy) = AltBN128.AddPoints(EYx, EYy, Yx[i], Yy[i]);
            }
            (EYx, EYy) = AltBN128.MultiplyPoint(EYx, EYy, e);
            (Rvx, Rvy) = AltBN128.AddPoints(Sx, Sy, EYx, EYy);
        }

        //Compute Hash
        uint[] memory pub_keys = new uint[](Yx.length + Yy.length);

        for (uint i = 0; i < Yx.length; i++) {
            pub_keys[2*i] = Yx[i];
            pub_keys[2*i+1] = Yy[i];
        }
        uint ev = uint(sha256(abi.encodePacked(Rvx, Rvy, message_hash, pub_keys))) % AltBN128.GetN();

        return (ev == e);
    }
}
