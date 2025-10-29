//! Co-EVM: Cross-EVM Communication Example
//!
//! This library demonstrates cross-EVM communication patterns between a parent EVM
//! and a child EVM (enclave). It showcases:
//!
//! - Message passing architecture to avoid reentrancy issues
//! - Atomic transactions using checkpoint-based two-phase commit
//! - Encrypted communication between EVMs
//! - Token bridging between public and private chains
//! - Custom precompiles for cross-EVM calls

/// Child EVM implementation with encrypted execution support
pub mod child_evm;

/// Cryptographic utilities for encrypted cross-EVM communication
pub mod crypto;

/// Custom handler that defers transaction commits for atomic cross-EVM operations
pub mod custom_handler;

/// Parent EVM implementation with standard execution
pub mod parent_evm;

/// Custom precompiles for cross-EVM communication
pub mod precompiles;

/// Transaction coordinator for atomic cross-EVM transactions using checkpoints
pub mod transaction_coordinator;
