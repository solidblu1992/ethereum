pragma solidity ^0.5.9;

contract StealthTxRegistry {
    constructor() public {}
    
    event StealthTx (
        address indexed _addr,
        byte _point_compressed_sign,
        bytes32 _point_compressed_x
    );
    
    function LogStealthTx(address _addr, byte _point_compressed_sign, bytes32 _point_compressed_x) public {
        require(_point_compressed_sign == 0x02 || _point_compressed_sign == 0x03);
        emit StealthTx(_addr, _point_compressed_sign, _point_compressed_x);
    }
}