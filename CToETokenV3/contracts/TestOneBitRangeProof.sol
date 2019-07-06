pragma solidity ^0.5.9;

import "./libOneBitRangeProof.sol";

contract TestOneBitRangeProof {
    address private debugOwner;
    
    constructor() public {
        debugOwner = msg.sender;
    }
    
    function DebugKill() public {
        require(msg.sender == debugOwner);
        selfdestruct(msg.sender);
    }
    
    function GetProof(bytes memory b, uint index) public view returns (uint Cx, uint Cy, uint c0, uint s0, uint s1) {
        OneBitRangeProof.Data memory p = OneBitRangeProof.FromBytes(b, index);
        (Cx, Cy, c0, s0, s1) = (p.Cx, p.Cy, p.c0, p.s0, p.s1);
    }
    
    function VerifyProof(bytes memory b, uint index, address asset_address) public view returns (bool) {
        OneBitRangeProof.Data memory p = OneBitRangeProof.FromBytes(b, index);
        uint Hx;
        uint Hy_neg;
        (Hx, Hy_neg) = OneBitRangeProof.CalcNegAssetH(asset_address);
        
        return OneBitRangeProof.Verify(p, Hx, Hy_neg);
    }
    
    function GetProof_GT(bytes memory b, uint index) public returns (uint Cx, uint Cy, uint c0, uint s0, uint s1) {
        return GetProof(b, index);
    }
    
    function VerifyProof_GT(bytes memory b, uint index, address asset_address) public returns (bool) {
        return VerifyProof(b, index, asset_address);
    }
}