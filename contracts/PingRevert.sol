// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./CrossEvmLib.sol";

/// @notice Interface for PongRevert contract on child EVM
interface IPongRevert {
    function two() external returns (uint256);
    function four() external returns (uint256);
    function six() external returns (uint256);
}

/// @title PingRevert - Demonstrates revert handling in cross-EVM calls
/// @notice Similar to Ping, but PongRevert.six() will revert to show rollback behavior
contract PingRevert {
    uint256 public counter;
    address public pongAddress;

    event Step(uint256 step, uint256 counter);

    constructor(address _pongAddress) {
        pongAddress = _pongAddress;
    }

    /// @notice Step 1: Start the ping-pong chain
    function one() public returns (uint256) {
        counter++;
        emit Step(1, counter);
        return IPongRevert(CrossEvmLib.other(pongAddress)).two();
    }

    /// @notice Step 3: Continue the ping-pong chain
    function three() public returns (uint256) {
        counter++;
        emit Step(3, counter);
        return IPongRevert(CrossEvmLib.other(pongAddress)).four();
    }

    /// @notice Step 5: Continue the ping-pong chain
    /// @dev This will call PongRevert.six() which will REVERT
    function five() public returns (uint256) {
        counter++;
        emit Step(5, counter);
        return IPongRevert(CrossEvmLib.other(pongAddress)).six();
    }

    /// @notice Step 7: This should never be reached due to revert at step 6
    function seven() public returns (uint256) {
        counter++;
        emit Step(7, counter);
        return counter;
    }
}
