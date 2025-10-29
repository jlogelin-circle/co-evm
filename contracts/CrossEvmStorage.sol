// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CrossEvmStorage {
    uint256 public number;
    address public otherStorage;

    constructor(address _otherStorage) {
        otherStorage = _otherStorage;
    }

    function retrieve() public view returns (uint256) {
        return number;
    }

    function store(uint256 num) public {
        number = num;
    }

    function incrementOther() public returns (bool) {
        // This would call the other storage contract
        // For demo purposes, just return true
        return true;
    }
}
