// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CrossEvmLib
 * @notice Universal library for making cross-EVM calls with the cleanest possible syntax
 * @dev Works from BOTH parent and child EVMs using a single router address!
 *
 * Key insight: Each EVM only needs to route to the "other" EVM, so we only need ONE address.
 * - Parent EVM: ROUTER routes to child
 * - Child EVM: ROUTER routes to parent
 *
 * Uses CREATE2 for deterministic proxy addresses - same target always gets same proxy!
 * Proxies are deployed once and reused automatically.
 *
 * Usage:
 *   ICounter(CrossEvmLib.other(targetAddr)).setNumber(42);
 */
library CrossEvmLib {
    // Single router address that works for both directions!
    address constant ROUTER = address(0xC0);

    /**
     * @notice Get a proxy to call a contract on the OTHER EVM
     * @param target The address on the other EVM to call
     * @return proxy A deterministic proxy address that routes calls to the other EVM
     *
     * Uses CREATE2 for deterministic deployment:
     * - First call: deploys proxy at deterministic address
     * - Subsequent calls: returns existing proxy (no redeployment!)
     * - Same target always gets same proxy address
     *
     * Usage:
     *   ICounter(CrossEvmLib.other(targetAddr)).setNumber(42);
     *
     * This works from BOTH parent and child EVMs!
     */
    function other(address target) internal returns (address proxy) {
        // Deterministic salt based on target address
        bytes32 salt = bytes32(uint256(uint160(target)));

        // Calculate deterministic proxy address
        bytes memory bytecode = type(Proxy).creationCode;
        bytes memory initCode = abi.encodePacked(bytecode, abi.encode(target));
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(initCode)
            )
        );
        proxy = address(uint160(uint256(hash)));

        // Check if proxy already exists (has code)
        uint256 size;
        assembly {
            size := extcodesize(proxy)
        }

        // Deploy only if proxy doesn't exist yet
        if (size == 0) {
            assembly {
                proxy := create2(0, add(initCode, 0x20), mload(initCode), salt)
            }
            require(proxy != address(0), "Proxy deployment failed");
        }

        return proxy;
    }
}

/**
 * @title Proxy
 * @notice Inline proxy deployed by CrossEvmLib.other()
 * @dev Deployed once per target using CREATE2, then reused forever
 */
contract Proxy {
    address immutable target;
    address constant ROUTER = address(0xC0);

    constructor(address _target) {
        target = _target;
    }

    fallback() external payable {
        bytes memory input = abi.encodePacked(target, msg.data);
        (bool success, bytes memory result) = ROUTER.call(input);
        require(success, "Cross-EVM call failed");

        assembly {
            return(add(result, 0x20), mload(result))
        }
    }
}
