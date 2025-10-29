// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title SimplePrivateERC20
 * @notice Simplified private ERC20 that runs in enclave WITHOUT cross-EVM calls
 *
 * This version removes the cross-EVM calls from deposit/withdraw to avoid re-entrancy.
 * The bridge coordinator handles the cross-chain operations atomically.
 *
 * Privacy guarantees:
 * - All function calls are encrypted
 * - Balances are only known to token holders
 * - Transfer amounts are encrypted
 * - Bridge operations coordinated externally
 */
contract SimplePrivateERC20 {
    string public name = "Private Token";
    string public symbol = "PRIV";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    /**
     * @notice Transfer private tokens (encrypted)
     */
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @notice Approve spender (encrypted)
     */
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @notice Transfer from (encrypted)
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(
            allowance[from][msg.sender] >= amount,
            "Insufficient allowance"
        );

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;

        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * @notice Mint tokens (called by bridge coordinator via encrypted call)
     * @param to Recipient address
     * @param amount Amount to mint
     */
    function mint(address to, uint256 amount) public returns (bool) {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
        return true;
    }

    /**
     * @notice Burn tokens from a specific address (for bridge operations)
     * @param from Address to burn from
     * @param amount Amount to burn
     */
    function burn(address from, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");

        balanceOf[from] -= amount;
        totalSupply -= amount;

        emit Transfer(from, address(0), amount);
        return true;
    }

    /**
     * @notice Get caller's private balance (encrypted - only user can decrypt)
     */
    function getBalance() public view returns (uint256) {
        return balanceOf[msg.sender];
    }
}
