// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CrossEvmLib.sol";

/// @notice Interface for Ping contract on parent EVM
interface IPing {
    function three() external returns (uint256);
    function five() external returns (uint256);
    function seven() external returns (uint256);
}

/// @title Pong - Child EVM side of the ping-pong cross-EVM demonstration
/// @notice Demonstrates cross-EVM call chains with functions two(), four(), six()
contract Pong {
    uint256 public counter;
    address public pingAddress;

    event Step(uint256 step, uint256 counter);

    constructor(address _pingAddress) {
        pingAddress = _pingAddress;
    }

    /// @notice Step 2: Continue the ping-pong chain
    /// @dev Called by Ping.one(), calls Ping.three() on parent EVM
    function two() public returns (uint256) {
        counter++;
        emit Step(2, counter);

        // Call Ping.three() on parent EVM
        return IPing(CrossEvmLib.other(pingAddress)).three();
    }

    /// @notice Step 4: Continue the ping-pong chain
    /// @dev Called by Ping.three(), calls Ping.five() on parent EVM
    function four() public returns (uint256) {
        counter++;
        emit Step(4, counter);

        // Call Ping.five() on parent EVM
        return IPing(CrossEvmLib.other(pingAddress)).five();
    }

    /// @notice Step 6: Continue the ping-pong chain
    /// @dev Called by Ping.five(), calls Ping.seven() on parent EVM
    function six() public returns (uint256) {
        counter++;
        emit Step(6, counter);

        // Call Ping.seven() on parent EVM
        return IPing(CrossEvmLib.other(pingAddress)).seven();
    }
}
