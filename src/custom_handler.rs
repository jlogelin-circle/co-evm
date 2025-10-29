//! Custom Handler that doesn't auto-commit transactions
//!
//! This handler is identical to MainnetHandler except it does NOT call
//! `commit_tx()` at the end of execution. This allows us to manage transaction
//! atomicity across multiple EVMs using checkpoints.

use revm::{
    context::{result::ExecutionResult, LocalContextTr},
    context_interface::{result::HaltReason, ContextError, ContextTr, JournalTr},
    handler::{post_execution, EvmTr, EvmTrError, FrameResult, FrameTr, Handler},
    interpreter::interpreter_action::FrameInit,
    state::EvmState,
};

/// Handler that defers transaction commit to allow atomic cross-EVM operations
///
/// This is a wrapper around the default Handler implementation that skips the
/// automatic `commit_tx()` call in `execution_result()`. All other behavior is
/// identical to the default handler.
#[derive(Debug, Clone, Default)]
pub struct DeferredCommitHandler<CTX, ERROR, FRAME> {
    /// Phantom data to hold the generic type parameters
    pub _phantom: core::marker::PhantomData<(CTX, ERROR, FRAME)>,
}

impl<EVM, ERROR, FRAME> Handler for DeferredCommitHandler<EVM, ERROR, FRAME>
where
    EVM: EvmTr<Context: ContextTr<Journal: JournalTr<State = EvmState>>, Frame = FRAME>,
    ERROR: EvmTrError<EVM>,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = HaltReason;

    /// Override execution_result to NOT call commit_tx()
    ///
    /// This is the ONLY method we override from the default Handler implementation.
    /// Everything else (validation, pre_execution, execution, post_execution) uses
    /// the default implementations.
    #[inline]
    fn execution_result(
        &mut self,
        evm: &mut Self::Evm,
        result: <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        // Check for context errors
        match core::mem::replace(evm.ctx().error(), Ok(())) {
            Err(ContextError::Db(e)) => return Err(e.into()),
            Err(ContextError::Custom(e)) => return Err(Self::Error::from_string(e)),
            Ok(()) => (),
        }

        // Convert result to execution result
        let exec_result = post_execution::output(evm.ctx(), result);

        // ⭐ KEY DIFFERENCE: We do NOT call commit_tx() here!
        // The transaction coordinator will handle commits/reverts using checkpoints.
        //
        // Original default implementation (REMOVED):
        // evm.ctx().journal_mut().commit_tx();

        // Still clean up local context and frame stack
        evm.ctx().local_mut().clear();
        evm.frame_stack().clear();

        Ok(exec_result)
    }

    // All other Handler methods use the default implementations
    // (validate, pre_execution, execution, post_execution, etc.)
}
