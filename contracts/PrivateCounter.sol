// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title PrivateCounter
 * @notice A private counter that runs in an enclave (child EVM)
 *
 * All state changes are private - only the user who made the transaction
 * can see the results. The count itself remains visible on-chain, but
 * function calls and their responses are encrypted end-to-end.
 *
 * This demonstrates the power of encrypted smart contracts:
 * - Transactions are encrypted before being sent to the enclave
 * - Enclave decrypts, executes, and encrypts responses
 * - Only the sender can decrypt the response
 * - On-chain observers see only encrypted blobs
 */
contract PrivateCounter {
    uint256 public count;

    /**
     * @notice Increment the counter (public function, private execution)
     * When called via encrypted router, this executes privately in the enclave
     */
    function increment() public {
        count++;
    }

    /**
     * @notice Get the current count (public function, private execution)
     * When called via encrypted router, the response is encrypted for the caller
     */
    function getCount() public view returns (uint256) {
        return count;
    }

    /**
     * @notice Add a specific value to the counter
     * @param value The value to add
     */
    function add(uint256 value) public {
        count += value;
    }

    /**
     * @notice Set the counter to a specific value
     * @param value The new value
     */
    function set(uint256 value) public {
        count = value;
    }
}
