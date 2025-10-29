// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CrossEvmLib.sol";

/**
 * @title ITestCounter
 * @notice Interface for TestCounter contract
 */
interface ITestCounter {
    function count() external view returns (uint256);
    function increment() external;
    function incrementOther(address otherCounterAddr) external;
}

/**
 * @title TestCounter
 * @notice Universal counter that works on BOTH parent and child EVMs!
 * @dev Uses the universal CrossEvmLib - same code works everywhere!
 */
contract TestCounter {
    uint256 public count;

    function increment() public {
        count++;
    }

    /**
     * @notice Increment a counter on the OTHER EVM
     * @param otherCounterAddr The address of the TestCounter on the other EVM
     *
     */
    function incrementOther(address otherCounterAddr) public {
        // This is exactly what you wanted!
        ITestCounter(CrossEvmLib.other(otherCounterAddr)).increment();
    }
}
