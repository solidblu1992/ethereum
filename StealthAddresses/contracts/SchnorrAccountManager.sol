pragma solidity ^0.8.18;
import "./libSchnorr.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract SchnorrAccountManager {
    //Global Data
    struct AccountData {
        uint balance;
    }
    mapping(address => AccountData) public accounts;
    constructor () {}

    //Public Functions
    //Add funds to desired address
    event DepositEvent(address indexed _to, uint _amount);
    function Deposit(address _addr) public payable {
        bool success;
        uint newBalance;
        (success, newBalance) = SafeMath.tryAdd(accounts[_addr].balance, msg.value);
        require(success);
        accounts[_addr].balance = newBalance;
        emit DepositEvent(_addr, newBalance);
    }

    event TransferEvent(address[] indexed _from, uint[] _amountFrom, address[] indexed _to, uint[] _amountTo);
    event WithdrawalEvent(address[] indexed _from, uint[] _amountFrom, address[] indexed _to, uint[] _amountTo);
    function Execute(Schnorr.Signature calldata sig) public {
        //Verify Schnorr Sig is Correct
        require(Schnorr.Verify(sig));
        
        //Unpack Message
        uint op_code;
        uint[] memory _amountFrom;
        address[] memory _to;
        uint[] memory _amountTo;
        (op_code, _amountFrom, _to, _amountTo) = Schnorr.UnpackMessage(sig.message);

        //Get Sending Addresses
        address[] memory _from = new address[](_amountFrom.length);
        for (uint i = 0; i < _amountFrom.length*2; i += 2) {
            _from[i] = Schnorr.PubKeyToAddress(sig.Y[i:i+1]);
        }

        //Verify that sum of outgoing funds equals sum of incoming funds
        bool success;
        uint newBalance;
        uint balance = 0;
        for (uint i = 0; i < _amountFrom.length; i++) {
            (success, newBalance) = SafeMath.tryAdd(balance, _amountFrom[i]);
            require(success);
            balance = newBalance;
        }
        for (uint i = 0; i < _amountTo.length; i++) {
            (success, newBalance) = SafeMath.trySub(balance, _amountTo[i]);
            require(success);
            balance = newBalance;
        }
        require(balance == 0);

        //Take funds away from senders
        for (uint i = 0; i < _from.length; i++) {
            (success, newBalance) = SafeMath.trySub(accounts[_from[i]].balance, _amountFrom[i]);
            require(success);
            accounts[_from[i]].balance = newBalance;
        }

        //Give funds to receivers
        if (op_code == 1) {
            for (uint i = 0; i < _to.length; i++) {
                (success, newBalance) = SafeMath.tryAdd(accounts[_to[i]].balance, _amountTo[i]);
                require(success);
                accounts[_to[i]].balance = newBalance;
            }

            emit TransferEvent(_from, _amountFrom, _to, _amountTo);
        }
        else {
            for (uint i = 0; i < _to.length; i++) {
                payable(_to[i]).transfer(_amountTo[i]);
            }

            emit WithdrawalEvent(_from, _amountFrom, _to, _amountTo);
        }
    }
}
