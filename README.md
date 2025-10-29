# Co-EVM Experiments

A dual EVM architecture implementation demonstrating cooperative execution between parent and child EVM instances with support for encrypted smart contracts.

## Overview

Co-EVM (Cooperative EVM) is a proof-of-concept implementation that enables:

- **Dual EVM Architecture**: Seamless communication between parent (L1) and child (enclave) EVM instances
- **Cross-EVM Calls**: Type-safe message passing between EVMs using custom router precompiles
- **Encrypted Smart Contracts**: End-to-end encryption for private contract execution
- **Transaction Coordination**: Atomic operations across both EVM instances with two-phase commit support

## Key Features

### Cross-EVM Communication

The system uses router precompiles at fixed addresses to enable cross-EVM calls:

- **0xC0**: Unencrypted router for transparent cross-EVM calls (~10,000 gas)
- **0xC1**: Encrypted router for private contract execution (~50,000 gas)

### Cryptography

- **Key Exchange**: X25519 (Curve25519 Diffie-Hellman)
- **Encryption**: ChaCha20-Poly1305 AEAD cipher
- **Authentication**: Poly1305 MAC with 128-bit authentication tags

### Architecture Components

1. **Parent EVM**: Public blockchain instance that processes regular transactions and routes calls
2. **Child EVM**: Secure enclave instance that executes private smart contracts
3. **Transaction Coordinator**: Manages atomicity and state consistency across both EVMs
4. **Custom Precompiles**: Router implementations for encrypted and unencrypted cross-EVM calls

## Examples

The repository includes several demonstration programs:

- **test_counter**: Basic cross-EVM counter increments (unencrypted)
- **private_counter**: Encrypted counter with end-to-end privacy
- **ping_pong**: Bidirectional message passing between EVMs
- **ping_pong_revert**: Demonstrates revert handling across EVMs
- **private_erc20_crossevm**: Private ERC20 token with encrypted transfers
- **atomic_demo**: Atomic transaction coordination between EVMs

## Quick Start

### Prerequisites

- Rust (latest stable)
- Cargo

### Build

```bash
cargo build --release
```

### Run Examples

```bash
# Basic cross-EVM counter
cargo run --bin test_counter

# Encrypted private counter
cargo run --bin private_counter

# Ping-pong message passing
cargo run --bin ping_pong

# Atomic operations demo
cargo run --bin atomic_demo

# Ping pong demo
cargo run --bin ping_pong

# Ping pong with revert demo
cargo run --bin ping_pong_revert

# Public/Private ERC20 bridged
cargo run --bin private_erc20_crossevm
```

### Run Tests

```bash
# All tests
cargo test

# Cryptography tests
cargo test crypto::tests

# Specific example tests
cargo test --bin test_counter
```

## Smart Contracts

The `contracts/` directory includes example Solidity contracts:

- **TestCounter.sol**: Simple counter with cross-EVM increment support
- **PrivateCounter.sol**: Encrypted counter contract
- **PrivateERC20.sol** / **SimplePrivateERC20.sol**: Private token implementations
- **PublicERC20.sol**: Standard ERC20 for comparison
- **Ping.sol** / **Pong.sol**: Message passing demonstration contracts
- **CrossEvmLib.sol**: Library for type-safe cross-EVM calls

