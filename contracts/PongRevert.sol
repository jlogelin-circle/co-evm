// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CrossEvmLib.sol";

/// @notice Interface for PingRevert contract on parent EVM
interface IPingRevert {
    function three() external returns (uint256);
    function five() external returns (uint256);
    function seven() external returns (uint256);
}

/// @title PongRevert - Demonstrates revert handling in cross-EVM calls
/// @notice Similar to Pong, but six() will revert to show rollback behavior
contract PongRevert {
    uint256 public counter;
    address public pingAddress;

    event Step(uint256 step, uint256 counter);

    constructor(address _pingAddress) {
        pingAddress = _pingAddress;
    }

    /// @notice Step 2: Continue the ping-pong chain
    function two() public returns (uint256) {
        counter++;
        emit Step(2, counter);
        return IPingRevert(CrossEvmLib.other(pingAddress)).three();
    }

    /// @notice Step 4: Continue the ping-pong chain
    function four() public returns (uint256) {
        counter++;
        emit Step(4, counter);
        return IPingRevert(CrossEvmLib.other(pingAddress)).five();
    }

    /// @notice Step 6: INTENTIONALLY REVERTS to demonstrate rollback
    /// @dev This revert should prevent step 6 from updating state
    function six() public returns (uint256) {
        // DON'T increment counter - we want to revert before any state changes
        // counter++; // <-- Commented out to show pure revert

        // Revert immediately to demonstrate rollback behavior
        revert(
            "INTENTIONAL REVERT: Step 6 failed to demonstrate cross-EVM error handling"
        );
    }
}
