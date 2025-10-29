use crate::precompiles::{CrossEvmCall, ParentPrecompileProvider};
use revm::{
    context::{
        BlockEnv, CfgEnv, Context, ContextError, ContextSetters, ContextTr, Evm, FrameStack,
        Journal, LocalContext, TxEnv,
    },
    context_interface::result::ExecutionResult,
    database::InMemoryDB,
    handler::{
        evm::{EvmTr, FrameTr},
        instructions::EthInstructions,
        EthFrame, FrameInitOrResult, ItemOrResult,
    },
    inspector::{InspectorEvmTr, JournalExt},
    interpreter::interpreter::EthInterpreter,
    primitives::{hardfork::SpecId, Address, Bytes, TxKind},
    Database, Inspector,
};
use std::{cell::RefCell, rc::Rc};

// Type alias for the context we're using
type EvmContext =
    Context<BlockEnv, TxEnv, CfgEnv, InMemoryDB, Journal<InMemoryDB>, (), LocalContext>;

/// Parent EVM with custom precompiles for calling child
#[derive(Debug)]
pub struct ParentEvm<CTX, INSP> {
    /// The underlying EVM instance with custom precompiles
    pub evm: Evm<
        CTX,
        INSP,
        EthInstructions<EthInterpreter, CTX>,
        ParentPrecompileProvider,
        EthFrame<EthInterpreter>,
    >,
}

impl<CTX, INSP> ParentEvm<CTX, INSP>
where
    CTX: ContextTr<Cfg: revm::context::Cfg<Spec = SpecId>>,
{
    /// Create a new parent EVM with cross-EVM communication capabilities
    ///
    /// # Arguments
    /// * `ctx` - The EVM context
    /// * `inspector` - The EVM inspector
    /// * `cross_evm_handler` - Handler for cross-EVM calls to the child
    pub fn new(
        ctx: CTX,
        inspector: INSP,
        cross_evm_handler: Rc<RefCell<dyn CrossEvmCall>>,
    ) -> Self {
        Self {
            evm: Evm {
                ctx,
                inspector,
                instruction: EthInstructions::new_mainnet(),
                precompiles: ParentPrecompileProvider::new(SpecId::CANCUN, cross_evm_handler),
                frame_stack: FrameStack::new(),
            },
        }
    }
}

impl ParentEvm<EvmContext, ()> {
    /// Execute a transaction directly (for testing/demonstration)
    pub fn call_contract(
        &mut self,
        to: Address,
        data: Bytes,
        nonce: u64,
    ) -> anyhow::Result<ExecutionResult> {
        use revm::{
            context::result::InvalidTransaction,
            context_interface::result::EVMError,
            handler::{Handler, MainnetHandler},
        };

        self.evm.ctx.set_tx(
            TxEnv::builder()
                .kind(TxKind::Call(to))
                .data(data)
                .gas_limit(1_000_000)
                .nonce(nonce)
                .build()
                .unwrap(),
        );

        type MyError = EVMError<core::convert::Infallible, InvalidTransaction>;
        let result: Result<ExecutionResult, MyError> = MainnetHandler::default().run(&mut self.evm);
        Ok(result?)
    }

    /// Execute a transaction with a specified caller address
    ///
    /// This allows simulating transactions from specific addresses, useful for
    /// cross-EVM calls where the caller needs to be preserved.
    pub fn call_contract_from(
        &mut self,
        from: Address,
        to: Address,
        data: Bytes,
        nonce: u64,
    ) -> anyhow::Result<ExecutionResult> {
        use revm::{
            context::result::InvalidTransaction,
            context_interface::result::EVMError,
            handler::{Handler, MainnetHandler},
        };

        self.evm.ctx.set_tx(
            TxEnv::builder()
                .caller(from)
                .kind(TxKind::Call(to))
                .data(data)
                .gas_limit(1_000_000)
                .nonce(nonce)
                .build()
                .unwrap(),
        );

        type MyError = EVMError<core::convert::Infallible, InvalidTransaction>;
        let result: Result<ExecutionResult, MyError> = MainnetHandler::default().run(&mut self.evm);
        Ok(result?)
    }
}

impl<CTX, INSP> EvmTr for ParentEvm<CTX, INSP>
where
    CTX: ContextTr<Cfg: revm::context::Cfg<Spec = SpecId>>,
{
    type Context = CTX;
    type Instructions = EthInstructions<EthInterpreter, CTX>;
    type Precompiles = ParentPrecompileProvider;
    type Frame = EthFrame<EthInterpreter>;

    #[inline]
    fn all(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
    ) {
        self.evm.all()
    }

    #[inline]
    fn all_mut(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
    ) {
        self.evm.all_mut()
    }

    #[inline]
    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.evm.frame_init(frame_input)
    }

    #[inline]
    fn frame_run(
        &mut self,
    ) -> Result<
        FrameInitOrResult<Self::Frame>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.evm.frame_run()
    }

    #[inline]
    fn frame_return_result(
        &mut self,
        frame_result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<
        Option<<Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.evm.frame_return_result(frame_result)
    }
}

impl<CTX, INSP> InspectorEvmTr for ParentEvm<CTX, INSP>
where
    CTX: ContextSetters<Cfg: revm::context::Cfg<Spec = SpecId>, Journal: JournalExt>,
    INSP: Inspector<CTX, EthInterpreter>,
{
    type Inspector = INSP;

    fn all_inspector(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
        &Self::Inspector,
    ) {
        self.evm.all_inspector()
    }

    fn all_mut_inspector(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
        &mut Self::Inspector,
    ) {
        self.evm.all_mut_inspector()
    }
}
