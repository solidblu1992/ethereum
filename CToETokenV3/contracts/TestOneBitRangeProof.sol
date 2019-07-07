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
    
    function GetProof(bytes memory b, uint index) public view returns (address asset_address, uint Cx, uint Cy, uint c0, uint s0, uint s1) {
        OneBitRangeProof.Data memory p = OneBitRangeProof.FromBytes(b, index);
        (asset_address, Cx, Cy, c0, s0, s1) = (p.asset_address, p.Cx, p.Cy, p.c0, p.s0, p.s1);
    }
    
    function GetProofAll(bytes memory b, uint index) public view returns (address asset_address, uint Cx, uint Cy, uint c0, uint s0, uint s1) {
        OneBitRangeProof.Data[] memory p = OneBitRangeProof.FromBytesAll(b);
        (asset_address, Cx, Cy, c0, s0, s1) = (p[index].asset_address, p[index].Cx, p[index].Cy, p[index].c0, p[index].s0, p[index].s1);
    }
    
    function VerifyProof(bytes memory b, uint index) public view returns (bool) {
        OneBitRangeProof.Data memory p = OneBitRangeProof.FromBytes(b, index);
        uint Hx;
        uint Hy_neg;
        (Hx, Hy_neg) = OneBitRangeProof.CalcNegAssetH(p.asset_address);
        
        return OneBitRangeProof.Verify(p, Hx, Hy_neg);
    }
    
    function GetProof_GT(bytes memory b, uint index) public returns (address asset_address, uint Cx, uint Cy, uint c0, uint s0, uint s1) {
        return GetProof(b, index);
    }
    
    function GetProofAll_GT(bytes memory b, uint index) public returns (address asset_address, uint Cx, uint Cy, uint c0, uint s0, uint s1) {
        return GetProofAll(b, index);
    }
    
    function VerifyProof_GT(bytes memory b, uint index) public returns (bool) {
        return VerifyProof(b, index);
    }
}