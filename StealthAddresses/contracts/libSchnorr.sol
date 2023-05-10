pragma solidity ^0.8.18;
import "./libAltBN128.sol";

library Schnorr {
    struct Signature {
        bytes message;
        uint s;
        uint e;
        uint[] Y;
    }

    function UnpackMessage(bytes calldata message) public pure
        returns (uint op_code, uint[] memory _amountFrom, address[] memory _to, uint[] memory _amountTo) {
        //Message = uint256(op_code) + N*(bytes20(_amountFrom)) + N*(uint256(_to) + uint256(_amountTo)) = 32 + N*84 bytes
        require(message.length >= 116);
        require((message.length - 32) % 84 == 0);
        uint message_count = (message.length - 32) / 84;

        //Unpack Message
        op_code = uint(bytes32(message[0:32]));
        require(op_code == 1 || op_code == 2);

        _amountFrom = new uint[](message_count);
        _to = new address[](message_count);
        _amountTo = new uint[](message_count);
        for (uint i = 0; i < message_count; i++) {
            uint a = 32+i*20;
            uint b = a + 32;
            _amountFrom[i] = uint(bytes32(message[a:b]));

            a = 32 + 20*message_count;
            b = a + 20;
            uint c = b + 32;
            _to[i] = address(bytes20(message[a:b]));
            _amountTo[i] = uint(bytes32(message[b:c]));
        }
    }

    function Verify(Signature calldata sig) public view returns (bool) {
        //Basic Assertions
        require(sig.s > 0);
        require(sig.e > 0);
        require(sig.Y.length > 0);
        require(sig.Y.length % 2 == 0);

        uint[] memory Yx = new uint[](sig.Y.length / 2);
        uint[] memory Yy = new uint[](Yx.length);

        for (uint i = 0; i < Yx.length; i++) {
            (Yx[i], Yy[i]) = (sig.Y[2*i], sig.Y[2*i+1]);
            require(!AltBN128.IsZero(Yx[i], Yy[i]));
            require(AltBN128.IsOnCurve(Yx[i], Yy[i]));
        }
        
        //Perform Elliptic Curve Math
        uint Rvx;
        uint Rvy;
        {
            uint Sx;
            uint Sy;
            (Sx, Sy) = AltBN128.MultiplyG1(sig.s);

            uint EYx = Yx[0];
            uint EYy = Yy[0];
            for (uint i = 1; i < Yx.length; i++) {
                (EYx, EYy) = AltBN128.AddPoints(EYx, EYy, Yx[i], Yy[i]);
            }
            (EYx, EYy) = AltBN128.MultiplyPoint(EYx, EYy, sig.e);
            (Rvx, Rvy) = AltBN128.AddPoints(Sx, Sy, EYx, EYy);
        }

        //Compute Hash
        uint[] memory pub_keys = new uint[](Yx.length + Yy.length);

        for (uint i = 0; i < Yx.length; i++) {
            pub_keys[2*i] = Yx[i];
            pub_keys[2*i+1] = Yy[i];
        }
        uint ev = uint(sha256(abi.encodePacked(Rvx, Rvy, sig.message, pub_keys))) % AltBN128.GetN();

        return (ev == sig.e);
    }

    function PubKeyToAddress(uint[] calldata Y) public pure returns (address _addr) {
        //Calculate Address Hash of Public Key
        _addr = address(uint160(bytes20(keccak256(abi.encodePacked(Y[0], Y[1])))));
    }
}
