// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Test } from "test/setup/Test.sol";

import { NativeAssetLiquidity } from "src/L2/NativeAssetLiquidity.sol";
import { LiquidityController } from "src/L2/LiquidityController.sol";
import { L2ToL1MessagePasserCGT } from "src/L2/L2ToL1MessagePasserCGT.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";
import { IL1Block } from "interfaces/L2/IL1Block.sol";

/// @notice Exercises the CGT (custom gas token) native-liquidity + withdrawal flow for the
///         drain / brick / stuck-funds scenarios. Conclusion (asserted below): the fund-custody
///         path is gated by hard access-control checks and is balance-bounded, so an unprivileged
///         actor can neither mint native liquidity, move it out of NativeAssetLiquidity, nor strand
///         value in the CGT message passer.
contract CGTBridgeWithdraw_Test is Test {
    NativeAssetLiquidity internal nal;
    LiquidityController internal lc;
    L2ToL1MessagePasserCGT internal passer;

    address internal attacker = address(0xBAD);
    address internal honestRecipient = address(0xC0FFEE);

    function setUp() public {
        nal = new NativeAssetLiquidity();
        lc = new LiquidityController(); // constructor disables initializers; mint only reads `minters`
        passer = new L2ToL1MessagePasserCGT();
    }

    // ----------------------------------------------------------------------------------
    // NativeAssetLiquidity: the contract that actually custodies the native liquidity.
    // ----------------------------------------------------------------------------------

    /// @notice Only the LiquidityController predeploy may withdraw native liquidity.
    ///         An attacker calling withdraw() is rejected — cannot drain.
    function test_nal_withdraw_nonController_reverts() external {
        vm.deal(address(nal), 100 ether);

        vm.prank(attacker);
        vm.expectRevert(NativeAssetLiquidity.NativeAssetLiquidity_Unauthorized.selector);
        nal.withdraw(1 ether);

        // Balance untouched.
        assertEq(address(nal).balance, 100 ether);
    }

    /// @notice Only the LiquidityController predeploy may deposit (lock) native liquidity.
    function test_nal_deposit_nonController_reverts() external {
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        vm.expectRevert(NativeAssetLiquidity.NativeAssetLiquidity_Unauthorized.selector);
        nal.deposit{ value: 1 ether }();
    }

    /// @notice Even the authorized controller cannot withdraw more than the locked balance:
    ///         the call reverts cleanly (funds are NOT drained, no partial state). This is the
    ///         "insufficient liquidity" case — a mint that outruns backing simply reverts.
    function test_nal_withdraw_insufficientBalance_reverts() external {
        vm.deal(address(nal), 100 ether);

        vm.prank(Predeploys.LIQUIDITY_CONTROLLER);
        vm.expectRevert(NativeAssetLiquidity.NativeAssetLiquidity_InsufficientBalance.selector);
        nal.withdraw(200 ether);

        // Nothing moved; the shortfall is a clean revert, not a corrupted/stuck state.
        assertEq(address(nal).balance, 100 ether);
    }

    /// @notice The legitimate path: the controller withdraws within the locked balance and
    ///         receives exactly that amount. Confirms the gate permits the real flow.
    function test_nal_withdraw_controller_succeeds() external {
        vm.deal(address(nal), 100 ether);
        uint256 controllerBefore = Predeploys.LIQUIDITY_CONTROLLER.balance;

        vm.prank(Predeploys.LIQUIDITY_CONTROLLER);
        nal.withdraw(40 ether);

        assertEq(address(nal).balance, 60 ether);
        assertEq(Predeploys.LIQUIDITY_CONTROLLER.balance, controllerBefore + 40 ether);
    }

    // ----------------------------------------------------------------------------------
    // LiquidityController: minting is gated to authorized minters only.
    // ----------------------------------------------------------------------------------

    /// @notice An unprivileged attacker cannot mint native tokens: mint() checks
    ///         `minters[msg.sender]` first, which is false for everyone by default.
    function test_lc_mint_nonMinter_reverts() external {
        vm.prank(attacker);
        vm.expectRevert(LiquidityController.LiquidityController_Unauthorized.selector);
        lc.mint(attacker, 1_000_000 ether);
    }

    /// @notice An unprivileged attacker cannot burn (lock) via the controller either.
    function test_lc_burn_nonMinter_reverts() external {
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        vm.expectRevert(LiquidityController.LiquidityController_Unauthorized.selector);
        lc.burn{ value: 1 ether }();
    }

    // ----------------------------------------------------------------------------------
    // L2ToL1MessagePasserCGT: native value cannot be stranded in a CGT-mode withdrawal.
    // ----------------------------------------------------------------------------------

    /// @notice In CGT mode, initiating a withdrawal with native value reverts up front, so a user
    ///         can never lock msg.value into an un-withdrawable message (no stuck funds).
    function test_passer_valueInCGTMode_reverts() external {
        // Mock L1Block.isCustomGasToken() => true.
        vm.mockCall(
            Predeploys.L1_BLOCK_ATTRIBUTES,
            abi.encodeWithSelector(IL1Block.isCustomGasToken.selector),
            abi.encode(true)
        );

        vm.deal(address(this), 1 ether);
        vm.expectRevert(L2ToL1MessagePasserCGT.L2ToL1MessagePasserCGT_NotAllowedOnCGTMode.selector);
        passer.initiateWithdrawal{ value: 1 ether }(honestRecipient, 100_000, hex"");
    }
}
