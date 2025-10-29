// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./CrossEvmLib.sol";

/// @notice Interface for PublicERC20 contract on parent EVM
interface IPublicERC20 {
    function burn(address from, uint256 amount) external;
    function mint(address to, uint256 amount) external;
}

/**
 * @title PrivateERC20
 * @notice Private ERC20 token running in secure enclave with cross-EVM bridge
 *
 * This token runs entirely in the enclave, with all balances and transfers private.
 * It bridges to PublicERC20 on the parent EVM for deposits and withdrawals.
 *
 * Privacy guarantees:
 * - All function calls are encrypted
 * - Balances are only known to token holders
 * - Transfer amounts are encrypted
 * - Only deposit/withdraw events are visible on parent chain (amounts encrypted)
 *
 * Bridge mechanics:
 * - deposit(): Burns public tokens on parent, mints private tokens in enclave
 * - withdraw(): Burns private tokens in enclave, mints public tokens on parent
 */
contract PrivateERC20 {
    string public name = "Private Token";
    string public symbol = "PRIV";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Address of the PublicERC20 contract on parent EVM
    address public publicToken;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor(address _publicToken) {
        publicToken = _publicToken;
    }

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
     * @notice Deposit: Burn public tokens on parent, mint private tokens in enclave
     *
     * This is called by users who want to move their public tokens into the private realm.
     * The function calls the parent EVM to burn public tokens and then mints private tokens.
     *
     * Flow:
     * 1. User calls this function (encrypted) with amount
     * 2. Enclave calls PublicERC20.burn(user, amount) on parent EVM
     * 3. If successful, mint private tokens for user in enclave
     */
    function deposit(uint256 amount) public returns (bool) {
        // Call parent EVM to burn public tokens
        IPublicERC20(CrossEvmLib.other(publicToken)).burn(msg.sender, amount);

        // Mint private tokens in enclave
        balanceOf[msg.sender] += amount;
        totalSupply += amount;

        emit Transfer(address(0), msg.sender, amount);
        emit Deposit(msg.sender, amount);

        return true;
    }

    /**
     * @notice Withdraw: Burn private tokens in enclave, mint public tokens on parent
     *
     * This is called by users who want to exit the private realm back to public tokens.
     * The function burns private tokens and calls parent EVM to mint public tokens.
     *
     * Flow:
     * 1. User calls this function (encrypted) with amount
     * 2. Burn private tokens in enclave
     * 3. Enclave calls PublicERC20.mint(user, amount) on parent EVM
     * 4. User receives public tokens on parent EVM
     */
    function withdraw(uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        // Burn private tokens first
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;

        emit Transfer(msg.sender, address(0), amount);

        // Call parent EVM to mint public tokens
        IPublicERC20(CrossEvmLib.other(publicToken)).mint(msg.sender, amount);

        emit Withdrawal(msg.sender, amount);

        return true;
    }

    /**
     * @notice Get user's private balance (encrypted - only user can decrypt)
     */
    function getBalance() public view returns (uint256) {
        return balanceOf[msg.sender];
    }

    /**
     * @notice Internal mint function (used for initial supply or testing)
     */
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
}
