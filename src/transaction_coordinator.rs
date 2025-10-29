//! Transaction Coordinator for Atomic Cross-EVM Operations
//!
//! Manages checkpoints across parent and child EVMs to provide atomic transaction semantics.
//! When a transaction spans both EVMs, all changes commit together or revert together.

use parking_lot::Mutex;
use revm::context_interface::journaled_state::JournalCheckpoint;
use std::sync::Arc;

/// Coordinates atomic transactions across parent and child EVMs using Journal checkpoints
///
/// # Architecture
///
/// When a transaction starts on one EVM and makes cross-EVM calls:
/// 1. Create checkpoints on BOTH EVMs at transaction start
/// 2. Execute transaction (may involve multiple cross-EVM calls)
/// 3. At the end: either commit all changes or revert all changes atomically
///
/// # Example
///
/// ```rust,ignore
/// let coordinator = TransactionCoordinator::new();
///
/// // Begin atomic transaction
/// let (parent_cp, child_cp) = coordinator.begin_transaction(
///     &mut parent_evm,
///     &mut child_evm,
/// );
///
/// // Execute transaction (may call child, which may call back to parent)
/// let result = parent_evm.execute_deferred(...)?;
///
/// // Commit or revert atomically based on result
/// if result.is_success() && !coordinator.has_error() {
///     coordinator.commit_transaction(&mut parent_evm, &mut child_evm);
/// } else {
///     coordinator.revert_transaction(
///         &mut parent_evm,
///         &mut child_evm,
///         parent_cp,
///         child_cp,
///     );
/// }
/// ```
#[derive(Clone, Debug)]
pub struct TransactionCoordinator {
    /// Transaction nesting depth (0 = no active transaction)
    depth: Arc<Mutex<usize>>,

    /// Track if any cross-EVM call failed
    has_error: Arc<Mutex<bool>>,

    /// Which EVM initiated the outer transaction
    initiator: Arc<Mutex<Option<EvmSide>>>,
}

/// Identifies which EVM a transaction is executing on
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmSide {
    /// Parent EVM (public chain)
    Parent,
    /// Child EVM (secure enclave)
    Child,
}

impl Default for TransactionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionCoordinator {
    /// Create a new transaction coordinator
    pub fn new() -> Self {
        Self {
            depth: Arc::new(Mutex::new(0)),
            has_error: Arc::new(Mutex::new(false)),
            initiator: Arc::new(Mutex::new(None)),
        }
    }

    /// Begin an atomic cross-EVM transaction
    ///
    /// Creates checkpoints on both EVMs. Returns the checkpoint handles that must be
    /// provided to `commit_transaction()` or `revert_transaction()`.
    ///
    /// # Type Parameters
    ///
    /// The generic parameters allow this to work with different EVM context types.
    pub fn begin_transaction<ParentJournal, ChildJournal>(
        &self,
        parent_journal: &mut ParentJournal,
        child_journal: &mut ChildJournal,
        initiator: EvmSide,
    ) -> (JournalCheckpoint, JournalCheckpoint)
    where
        ParentJournal: revm::context_interface::JournalTr,
        ChildJournal: revm::context_interface::JournalTr,
    {
        let mut depth = self.depth.lock();

        // Only create checkpoints at the outermost transaction level
        if *depth == 0 {
            *self.initiator.lock() = Some(initiator);
            *self.has_error.lock() = false;

            let parent_checkpoint = parent_journal.checkpoint();
            let child_checkpoint = child_journal.checkpoint();

            *depth = 1;

            (parent_checkpoint, child_checkpoint)
        } else {
            // Nested call - increment depth but don't create new checkpoints
            *depth += 1;
            // Return dummy checkpoints (won't be used)
            (
                JournalCheckpoint {
                    log_i: 0,
                    journal_i: 0,
                },
                JournalCheckpoint {
                    log_i: 0,
                    journal_i: 0,
                },
            )
        }
    }

    /// Increment call depth (for nested cross-EVM calls)
    pub fn enter_cross_evm_call(&self) {
        *self.depth.lock() += 1;
    }

    /// Decrement call depth (returning from a cross-EVM call)
    pub fn exit_cross_evm_call(&self) {
        let mut depth = self.depth.lock();
        *depth = depth.saturating_sub(1);
    }

    /// Mark that an error occurred during execution
    ///
    /// This will cause the transaction to revert when `end_transaction` is called.
    pub fn mark_error(&self) {
        *self.has_error.lock() = true;
    }

    /// Check if any error has occurred
    pub fn has_error(&self) -> bool {
        *self.has_error.lock()
    }

    /// Get current transaction depth
    pub fn depth(&self) -> usize {
        *self.depth.lock()
    }

    /// Check if we're currently in a transaction
    pub fn in_transaction(&self) -> bool {
        *self.depth.lock() > 0
    }

    /// Get which EVM initiated the transaction
    pub fn initiator(&self) -> Option<EvmSide> {
        *self.initiator.lock()
    }

    /// Commit the atomic transaction on both EVMs
    ///
    /// This commits the checkpoints and finalizes the transaction journals.
    /// All changes on both EVMs become permanent.
    pub fn commit_transaction<ParentJournal, ChildJournal>(
        &self,
        parent_journal: &mut ParentJournal,
        child_journal: &mut ChildJournal,
    ) where
        ParentJournal: revm::context_interface::JournalTr,
        ChildJournal: revm::context_interface::JournalTr,
    {
        let mut depth = self.depth.lock();

        if *depth == 1 {
            // We're at the outermost transaction - commit both EVMs

            // Commit checkpoints (this just decrements depth in the journal)
            parent_journal.checkpoint_commit();
            child_journal.checkpoint_commit();

            // Finalize transactions (clears journal, marks changes as permanent)
            parent_journal.commit_tx();
            child_journal.commit_tx();

            // Reset coordinator state
            *depth = 0;
            *self.initiator.lock() = None;
            *self.has_error.lock() = false;
        } else if *depth > 1 {
            // Nested call - just decrement depth
            *depth -= 1;
        }
    }

    /// Revert the atomic transaction on both EVMs
    ///
    /// This reverts all changes made since the checkpoints were created,
    /// effectively undoing all work done in both EVMs.
    pub fn revert_transaction<ParentJournal, ChildJournal>(
        &self,
        parent_journal: &mut ParentJournal,
        child_journal: &mut ChildJournal,
        parent_checkpoint: JournalCheckpoint,
        child_checkpoint: JournalCheckpoint,
    ) where
        ParentJournal: revm::context_interface::JournalTr,
        ChildJournal: revm::context_interface::JournalTr,
    {
        let mut depth = self.depth.lock();

        if *depth == 1 {
            // We're at the outermost transaction - revert both EVMs

            // Revert to checkpoints (undoes all state changes)
            parent_journal.checkpoint_revert(parent_checkpoint);
            child_journal.checkpoint_revert(child_checkpoint);

            // Discard transactions (clears journal)
            parent_journal.discard_tx();
            child_journal.discard_tx();

            // Reset coordinator state
            *depth = 0;
            *self.initiator.lock() = None;
            *self.has_error.lock() = false;
        } else if *depth > 1 {
            // Nested call - just decrement depth
            // The outer transaction will handle the actual revert
            *depth -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_depth_tracking() {
        let coordinator = TransactionCoordinator::new();

        assert_eq!(coordinator.depth(), 0);
        assert!(!coordinator.in_transaction());

        coordinator.enter_cross_evm_call();
        assert_eq!(coordinator.depth(), 1);
        assert!(coordinator.in_transaction());

        coordinator.enter_cross_evm_call();
        assert_eq!(coordinator.depth(), 2);

        coordinator.exit_cross_evm_call();
        assert_eq!(coordinator.depth(), 1);

        coordinator.exit_cross_evm_call();
        assert_eq!(coordinator.depth(), 0);
        assert!(!coordinator.in_transaction());
    }

    #[test]
    fn test_error_tracking() {
        let coordinator = TransactionCoordinator::new();

        assert!(!coordinator.has_error());

        coordinator.mark_error();
        assert!(coordinator.has_error());
    }

    #[test]
    fn test_initiator_tracking() {
        let coordinator = TransactionCoordinator::new();

        assert_eq!(coordinator.initiator(), None);

        // Simulate beginning a transaction (depth tracking only)
        coordinator.enter_cross_evm_call();
        *coordinator.initiator.lock() = Some(EvmSide::Parent);

        assert_eq!(coordinator.initiator(), Some(EvmSide::Parent));

        coordinator.exit_cross_evm_call();
        *coordinator.initiator.lock() = None;

        assert_eq!(coordinator.initiator(), None);
    }
}
