// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Test } from "test/setup/Test.sol";
import { Vm } from "forge-std/Vm.sol";

import { BatchAuthenticator } from "src/L1/BatchAuthenticator.sol";
import { IProxy } from "interfaces/universal/IProxy.sol";
import { IProxyAdmin } from "interfaces/universal/IProxyAdmin.sol";
import { IEspressoTEEVerifier } from "@espresso-tee-contracts/interface/IEspressoTEEVerifier.sol";
import { IEspressoNitroTEEVerifier } from "@espresso-tee-contracts/interface/IEspressoNitroTEEVerifier.sol";
import { EspressoTEEVerifierMock } from "@espresso-tee-contracts/mocks/EspressoTEEVerifier.sol";
import { EspressoNitroTEEVerifierMock } from "@espresso-tee-contracts/mocks/EspressoNitroTEEVerifierMock.sol";

import { DeployUtils } from "scripts/libraries/DeployUtils.sol";
import { ISystemConfig } from "interfaces/L1/ISystemConfig.sol";

/// @notice Minimal SystemConfig mock exposing a settable batcherHash() (fallback-batcher path).
contract MockSystemConfig {
    bytes32 private _batcherHash;

    function setBatcherHash(bytes32 val) external {
        _batcherHash = val;
    }

    function batcherHash() external view returns (bytes32) {
        return _batcherHash;
    }

    function paused() external pure returns (bool) {
        return false;
    }
}

/// @notice Stand-in for a smart-contract batcher (e.g. a Safe multisig). It has no private key,
///         so it can never *originate* an L1 transaction — it can only be *called* by an EOA that
///         relays through it. When it forwards a call to BatchAuthenticator, the authenticator sees
///         `msg.sender == address(this)` (the multisig) while `tx.origin` remains the relaying EOA.
contract MockMultisigBatcher {
    address public lastSeenMsgSender;
    address public lastSeenTxOrigin;

    function forwardAuthenticate(BatchAuthenticator _auth, bytes32 _commitment, bytes calldata _sig) external {
        // Record the distinction the Go node cares about, from this contract's frame.
        lastSeenMsgSender = msg.sender; // the relaying EOA
        lastSeenTxOrigin = tx.origin; // also the relaying EOA
        _auth.authenticateBatchInfo(_commitment, _sig);
    }
}

/// @notice Demonstrates the contract-side half of the multisig-batcher liveness constraint:
///         when a smart-contract batcher authenticates a batch, the emitted `caller` is the
///         CONTRACT address (msg.sender), which can never equal the EOA `tx.origin` that
///         op-node recovers from the batch-inbox transaction. This is the exact condition that
///         makes the Go node's `sender != authCaller` check reject the batch.
///
///         NOTE: this is reachable only via governance misconfiguration (setting the batcher to a
///         contract) and is recoverable by governance; it is NOT attacker-triggerable. The test
///         proves the emission behavior, not an exploit.
contract BatchAuthenticatorDoS_Test is Test {
    address public proxyAdminOwner = address(0xBEEF);
    address public relayingEOA = address(0xE0A); // the EOA that drives the multisig and signs L1 txs

    MockSystemConfig public mockSystemConfig;
    EspressoTEEVerifierMock public teeVerifier;
    EspressoNitroTEEVerifierMock public nitroVerifier;
    BatchAuthenticator public implementation;
    IProxyAdmin public proxyAdmin;
    MockMultisigBatcher public multisig;

    // keccak256("BatchInfoAuthenticated(bytes32,address)") — the topic op-node matches on.
    bytes32 internal constant AUTH_EVENT_SIG = keccak256("BatchInfoAuthenticated(bytes32,address)");

    function setUp() public {
        mockSystemConfig = new MockSystemConfig();
        nitroVerifier = new EspressoNitroTEEVerifierMock();
        teeVerifier = new EspressoTEEVerifierMock(IEspressoNitroTEEVerifier(address(nitroVerifier)));
        implementation = new BatchAuthenticator();
        multisig = new MockMultisigBatcher();

        bytes memory _code = DeployUtils.getCode("forge-artifacts/ProxyAdmin.sol/ProxyAdmin.json");
        bytes memory _initCode = abi.encodePacked(_code, abi.encode(proxyAdminOwner));
        address _addr;
        assembly {
            _addr := create(0, add(_initCode, 0x20), mload(_initCode))
        }
        proxyAdmin = IProxyAdmin(_addr);
    }

    function _newProxy(address _admin) internal returns (IProxy) {
        bytes memory initCode =
            abi.encodePacked(DeployUtils.getCode("src/universal/Proxy.sol:Proxy"), abi.encode(_admin));
        address payable proxyAddr;
        assembly {
            proxyAddr := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(proxyAddr != address(0), "proxy deployment failed");
        return IProxy(proxyAddr);
    }

    /// @notice Deploy the authenticator in FALLBACK mode (no TEE signature needed) with the
    ///         multisig contract configured as the batcher.
    function _deploy() internal returns (BatchAuthenticator) {
        IProxy proxy = _newProxy(address(proxyAdmin));
        vm.prank(proxyAdminOwner);
        proxyAdmin.setProxyType(address(proxy), IProxyAdmin.ProxyType.ERC1967);

        bytes memory initData = abi.encodeCall(
            BatchAuthenticator.initialize,
            (
                IEspressoTEEVerifier(address(teeVerifier)),
                address(0x1234), // some espressoBatcher; unused in fallback mode
                ISystemConfig(address(mockSystemConfig)),
                proxyAdminOwner,
                false // start in fallback mode
            )
        );
        vm.prank(proxyAdminOwner);
        proxyAdmin.upgradeAndCall(payable(address(proxy)), address(implementation), initData);
        return BatchAuthenticator(address(proxy));
    }

    /// @notice A smart-contract batcher's authentication emits the CONTRACT as `caller`, which
    ///         differs from the relaying EOA (tx.origin) — the Go node recovers the latter from
    ///         the batch-inbox tx, so the two never match and the batch would be rejected.
    function test_contractBatcher_emitsContractAsCaller_notTxOrigin_succeeds() external {
        BatchAuthenticator auth = _deploy();

        // Configure the fallback batcher to be the MULTISIG CONTRACT.
        mockSystemConfig.setBatcherHash(bytes32(uint256(uint160(address(multisig)))));

        bytes32 commitment = keccak256("some batch commitment");

        // The relaying EOA drives the multisig. vm.prank(sender, origin) sets BOTH msg.sender and
        // tx.origin for the outer call, so inside the authenticator tx.origin == relayingEOA while
        // msg.sender == address(multisig).
        vm.recordLogs();
        vm.prank(relayingEOA, relayingEOA);
        multisig.forwardAuthenticate(auth, commitment, "");

        // Find the BatchInfoAuthenticated event and decode its indexed caller (Topics[1]).
        Vm.Log[] memory logs = vm.getRecordedLogs();
        address emittedCaller;
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length >= 2 && logs[i].topics[0] == AUTH_EVENT_SIG && logs[i].emitter == address(auth)) {
                emittedCaller = address(uint160(uint256(logs[i].topics[1])));
                found = true;
                break;
            }
        }
        assertTrue(found, "BatchInfoAuthenticated not emitted");

        // The emitted caller is the multisig CONTRACT ...
        assertEq(emittedCaller, address(multisig));
        // ... and the multisig observed the relaying EOA as tx.origin ...
        assertEq(multisig.lastSeenTxOrigin(), relayingEOA);
        // ... so the on-chain `caller` differs from the EOA tx.origin op-node would recover.
        assertTrue(emittedCaller != multisig.lastSeenTxOrigin());

        // This inequality is precisely op-node's `sender != authCaller` reject condition:
        //   authCaller      == emittedCaller       == address(multisig)
        //   tx.From of inbox == a signing EOA       != address(multisig)  (a contract can't sign a tx)
        // Hence a contract batcher's batches are never authenticated.
    }

    /// @notice Sanity baseline: an EOA batcher emits itself as caller, and that address CAN equal
    ///         the inbox tx's tx.From — so EOA batchers authenticate correctly. Contrast with the
    ///         contract-batcher case above.
    function test_eoaBatcher_emitsSelfAsCaller_succeeds() external {
        BatchAuthenticator auth = _deploy();

        mockSystemConfig.setBatcherHash(bytes32(uint256(uint160(relayingEOA))));

        bytes32 commitment = keccak256("eoa batch commitment");

        vm.recordLogs();
        vm.prank(relayingEOA, relayingEOA);
        auth.authenticateBatchInfo(commitment, "");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        address emittedCaller;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length >= 2 && logs[i].topics[0] == AUTH_EVENT_SIG && logs[i].emitter == address(auth)) {
                emittedCaller = address(uint160(uint256(logs[i].topics[1])));
                break;
            }
        }
        // For an EOA batcher, caller == the EOA == the address that signs the inbox tx. Matches.
        assertEq(emittedCaller, relayingEOA);
    }
}
