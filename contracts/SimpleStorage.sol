// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 public number;

    function retrieve() public view returns (uint256) {
        return number;
    }

    function store(uint256 num) public {
        number = num;
    }

    function increment() public {
        number++;
    }
}
