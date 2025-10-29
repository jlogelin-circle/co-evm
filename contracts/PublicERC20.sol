// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title PublicERC20
 * @notice Public ERC20 token on parent EVM (L1) that bridges to PrivateERC20 in enclave
 *
 * This is the public-facing token that users hold on L1. When users want privacy,
 * they burn their public tokens and mint equivalent private tokens in the enclave.
 *
 * Flow:
 * - Deposit (Public → Private): User burns public tokens, enclave mints private tokens
 * - Withdraw (Private → Public): Enclave burns private tokens, mints public tokens for user
 */
contract PublicERC20 {
    string public name = "Public Token";
    string public symbol = "PUB";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Address of the bridge controller (child EVM can call this)
    address public bridge;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor(uint256 initialSupply) {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }

    /**
     * @notice Set the bridge address (one-time setup)
     */
    function setBridge(address _bridge) public {
        require(bridge == address(0), "Bridge already set");
        bridge = _bridge;
    }

    /**
     * @notice Transfer tokens
     */
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @notice Approve spender
     */
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @notice Transfer from (with allowance)
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
     * @notice Deposit: Burn public tokens to mint private tokens in enclave
     * User calls this to move tokens into the private realm
     */
    function deposit(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        // Burn public tokens
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;

        emit Transfer(msg.sender, address(0), amount);
        emit Deposit(msg.sender, amount);

        // Note: The enclave monitors Deposit events and mints private tokens
        // In a real system, there would be an oracle or the enclave would process this
    }

    /**
     * @notice Withdraw: Mint public tokens (called by bridge from enclave)
     * The enclave calls this when user burns private tokens
     */
    function withdraw(address user, uint256 amount) public {
        require(msg.sender == bridge, "Only bridge can withdraw");

        // Mint public tokens
        balanceOf[user] += amount;
        totalSupply += amount;

        emit Transfer(address(0), user, amount);
        emit Withdrawal(user, amount);
    }

    /**
     * @notice Mint tokens (only bridge/admin)
     * Used by the bridge when private tokens are burned
     */
    function mint(address to, uint256 amount) public {
        require(msg.sender == bridge, "Only bridge can mint");

        balanceOf[to] += amount;
        totalSupply += amount;

        emit Transfer(address(0), to, amount);
    }

    /**
     * @notice Burn tokens from an address (only bridge)
     * Used by the bridge when depositing to private side
     */
    function burn(address from, uint256 amount) public {
        require(msg.sender == bridge, "Only bridge can burn");
        require(balanceOf[from] >= amount, "Insufficient balance");

        balanceOf[from] -= amount;
        totalSupply -= amount;

        emit Transfer(from, address(0), amount);
    }
}
