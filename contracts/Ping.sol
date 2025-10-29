// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CrossEvmLib.sol";

/// @notice Interface for Pong contract on child EVM
interface IPong {
    function two() external returns (uint256);
    function four() external returns (uint256);
    function six() external returns (uint256);
}

/// @title Ping - Parent EVM side of the ping-pong cross-EVM demonstration
/// @notice Demonstrates cross-EVM call chains with functions one(), three(), five(), seven()
contract Ping {
    uint256 public counter;
    address public pongAddress;

    event Step(uint256 step, uint256 counter);

    constructor(address _pongAddress) {
        pongAddress = _pongAddress;
    }

    /// @notice Step 1: Start the ping-pong chain
    /// @dev Calls Pong.two() on the child EVM
    function one() public returns (uint256) {
        counter++;
        emit Step(1, counter);

        // Call Pong.two() on child EVM
        return IPong(CrossEvmLib.other(pongAddress)).two();
    }

    /// @notice Step 3: Continue the ping-pong chain
    /// @dev Called by Pong.two(), calls Pong.four()
    function three() public returns (uint256) {
        counter++;
        emit Step(3, counter);

        // Call Pong.four() on child EVM
        return IPong(CrossEvmLib.other(pongAddress)).four();
    }

    /// @notice Step 5: Continue the ping-pong chain
    /// @dev Called by Pong.four(), calls Pong.six()
    function five() public returns (uint256) {
        counter++;
        emit Step(5, counter);

        // Call Pong.six() on child EVM
        return IPong(CrossEvmLib.other(pongAddress)).six();
    }

    /// @notice Step 7: Final step in the ping-pong chain
    /// @dev Called by Pong.six(), returns the final counter value
    function seven() public returns (uint256) {
        counter++;
        emit Step(7, counter);

        // Return the final counter value
        return counter;
    }
}
