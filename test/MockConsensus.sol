// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

contract MockConsensus {
    address immutable beaconDepositContract;
    
    constructor(address _beaconDepositContract) {
        beaconDepositContract = _beaconDepositContract;
    }

    // Simulate consensus layer sending funds to withdrawal address
    function simulateValidatorWithdrawal(bytes memory pubkey, uint256 amount) external {
        // Get withdrawal credentials from beacon deposit contract
        (bool success, bytes memory data) = beaconDepositContract.staticcall(
            abi.encodeWithSignature("getWithdrawalCredentials(bytes)", pubkey)
        );
        require(success, "Failed to get withdrawal credentials");
        
        bytes32 credentials = abi.decode(data, (bytes32));
        // Extract withdrawal address from credentials (skip first 12 bytes)
        address withdrawalAddress = address(uint160(uint256(credentials)));
        
        // Send ETH to withdrawal address
        (success,) = withdrawalAddress.call{value: amount}("");
        require(success, "Withdrawal failed");
    }

    receive() external payable {}
}
