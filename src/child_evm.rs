use crate::{
    crypto::{EnclaveKeyPair, EnclaveKeys},
    precompiles::{ChildPrecompileProvider, CrossEvmCall},
};
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

/// Child enclave EVM with custom precompiles for calling parent
/// This EVM runs inside a secure enclave and has encryption keys for private execution
///
/// Generic over:
/// - `CTX`: The EVM context
/// - `INSP`: The inspector (for debugging/tracing)
/// - `EK`: The enclave key pair type (implements `EnclaveKeyPair`)
#[derive(Debug)]
pub struct ChildEvm<CTX, INSP, EK = EnclaveKeys>
where
    EK: EnclaveKeyPair,
{
    /// The underlying EVM instance with custom precompiles
    pub evm: Evm<
        CTX,
        INSP,
        EthInstructions<EthInterpreter, CTX>,
        ChildPrecompileProvider,
        EthFrame<EthInterpreter>,
    >,
    /// Enclave cryptographic keys for encrypted communication
    pub enclave_keys: EK,
}

impl<CTX, INSP, EK> ChildEvm<CTX, INSP, EK>
where
    CTX: ContextTr<Cfg: revm::context::Cfg<Spec = SpecId>>,
    EK: EnclaveKeyPair,
{
    /// Create a new child EVM with generated enclave keys
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
                precompiles: ChildPrecompileProvider::new(SpecId::CANCUN, cross_evm_handler),
                frame_stack: FrameStack::new(),
            },
            enclave_keys: EK::generate(),
        }
    }

    /// Create a new child EVM with provided enclave keys (for testing or custom crypto schemes)
    pub fn with_keys(
        ctx: CTX,
        inspector: INSP,
        cross_evm_handler: Rc<RefCell<dyn CrossEvmCall>>,
        enclave_keys: EK,
    ) -> Self {
        Self {
            evm: Evm {
                ctx,
                inspector,
                instruction: EthInstructions::new_mainnet(),
                precompiles: ChildPrecompileProvider::new(SpecId::CANCUN, cross_evm_handler),
                frame_stack: FrameStack::new(),
            },
            enclave_keys,
        }
    }

    /// Get the enclave's public key (safe to share publicly)
    pub fn public_key(&self) -> Vec<u8> {
        self.enclave_keys.public_key_bytes()
    }
}

impl<EK> ChildEvm<EvmContext, (), EK>
where
    EK: EnclaveKeyPair,
{
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

    /// Execute an encrypted transaction (decrypts, executes, encrypts response)
    ///
    /// This is the main entry point for private smart contract execution.
    /// The encrypted_data should be in format: [nonce][user_public_key][encrypted_call_data]
    pub fn call_contract_encrypted(
        &mut self,
        to: Address,
        encrypted_data: Bytes,
        nonce: u64,
    ) -> anyhow::Result<Bytes> {
        use revm::{
            context::result::InvalidTransaction,
            context_interface::result::EVMError,
            handler::{Handler, MainnetHandler},
        };

        // Step 1: Decrypt the incoming transaction data
        let decrypted_data = self.enclave_keys.decrypt(&encrypted_data)?;

        // Extract user's public key from the encrypted payload for response encryption
        // The user's public key is at bytes [12..44] in the encrypted payload
        if encrypted_data.len() < 44 {
            return Err(anyhow::anyhow!("Encrypted payload missing user public key"));
        }
        let user_public_key_bytes: [u8; 32] = encrypted_data[12..44]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid user public key"))?;

        // Step 2: Execute the transaction with decrypted data
        self.evm.ctx.set_tx(
            TxEnv::builder()
                .kind(TxKind::Call(to))
                .data(Bytes::from(decrypted_data))
                .gas_limit(1_000_000)
                .nonce(nonce)
                .build()
                .unwrap(),
        );

        type MyError = EVMError<core::convert::Infallible, InvalidTransaction>;
        let result: Result<ExecutionResult, MyError> = MainnetHandler::default().run(&mut self.evm);
        let execution_result = result?;

        // Step 3: Extract the output and encrypt it for the user
        let output_data = match execution_result {
            ExecutionResult::Success { output, .. } => match output {
                revm::context_interface::result::Output::Call(data) => data.to_vec(),
                revm::context_interface::result::Output::Create(data, _) => data.to_vec(),
            },
            _ => vec![],
        };

        // Encrypt response for the user
        let encrypted_response = self
            .enclave_keys
            .encrypt_response(&output_data, &user_public_key_bytes)?;

        Ok(Bytes::from(encrypted_response))
    }

    /// Execute an encrypted transaction with a specified caller address
    ///
    /// This is similar to `call_contract_encrypted` but allows specifying the caller,
    /// which is essential for preserving user identity in cross-EVM calls.
    pub fn call_contract_encrypted_from(
        &mut self,
        from: Address,
        to: Address,
        encrypted_data: Bytes,
        nonce: u64,
    ) -> anyhow::Result<Bytes> {
        use revm::{
            context::result::InvalidTransaction,
            context_interface::result::EVMError,
            handler::{Handler, MainnetHandler},
        };

        // Step 1: Decrypt the incoming transaction data
        let decrypted_data = self.enclave_keys.decrypt(&encrypted_data)?;

        // Extract user's public key from the encrypted payload for response encryption
        // The user's public key is at bytes [12..44] in the encrypted payload
        if encrypted_data.len() < 44 {
            return Err(anyhow::anyhow!("Encrypted payload missing user public key"));
        }
        let user_public_key_bytes: [u8; 32] = encrypted_data[12..44]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid user public key"))?;

        // Step 2: Execute the transaction with decrypted data and specified caller
        self.evm.ctx.set_tx(
            TxEnv::builder()
                .caller(from)
                .kind(TxKind::Call(to))
                .data(Bytes::from(decrypted_data))
                .gas_limit(1_000_000)
                .nonce(nonce)
                .build()
                .unwrap(),
        );

        type MyError = EVMError<core::convert::Infallible, InvalidTransaction>;
        let result: Result<ExecutionResult, MyError> = MainnetHandler::default().run(&mut self.evm);
        let execution_result = result?;

        // Step 3: Extract the output and encrypt it for the user
        let output_data = match execution_result {
            ExecutionResult::Success { output, .. } => match output {
                revm::context_interface::result::Output::Call(data) => data.to_vec(),
                revm::context_interface::result::Output::Create(data, _) => data.to_vec(),
            },
            ExecutionResult::Revert { output, .. } => {
                // Even reverts should be encrypted
                output.to_vec()
            }
            ExecutionResult::Halt { .. } => {
                // Return empty encrypted response for halts
                vec![]
            }
        };

        // Encrypt response for the user
        let encrypted_response = self
            .enclave_keys
            .encrypt_response(&output_data, &user_public_key_bytes)?;

        Ok(Bytes::from(encrypted_response))
    }
}

impl<CTX, INSP, EK> EvmTr for ChildEvm<CTX, INSP, EK>
where
    CTX: ContextTr<Cfg: revm::context::Cfg<Spec = SpecId>>,
    EK: EnclaveKeyPair,
{
    type Context = CTX;
    type Instructions = EthInstructions<EthInterpreter, CTX>;
    type Precompiles = ChildPrecompileProvider;
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

impl<CTX, INSP, EK> InspectorEvmTr for ChildEvm<CTX, INSP, EK>
where
    CTX: ContextSetters<Cfg: revm::context::Cfg<Spec = SpecId>, Journal: JournalExt>,
    INSP: Inspector<CTX, EthInterpreter>,
    EK: EnclaveKeyPair,
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
