use crate::transaction_coordinator::TransactionCoordinator;
use revm::{
    context::Cfg,
    context_interface::{ContextTr, LocalContextTr},
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
    precompile::PrecompileOutput,
    primitives::{address, hardfork::SpecId, Address, Bytes},
};
use std::{cell::RefCell, rc::Rc, sync::Arc};

/// Router address for cross-EVM calls (unencrypted)
/// This single address works for both directions:
/// - Parent EVM: routes calls to child EVM
/// - Child EVM: routes calls to parent EVM
///
/// Use this in Solidity with the proxy pattern for clean syntax:
/// ```solidity
/// ICounter(proxy).setNumber(42);
/// ```
pub const ROUTER_ADDRESS: Address = address!("00000000000000000000000000000000000000C0");

/// Encrypted router address for private smart contract calls
/// This address routes encrypted calls to the child EVM (enclave)
/// - Parent EVM: routes encrypted calls to child EVM (child decrypts, executes, encrypts response)
/// - NOT available from child EVM (child can only receive encrypted calls)
///
/// Format: [20 bytes target][encrypted_payload]
/// where encrypted_payload = [12 bytes nonce][32 bytes user_pubkey][ciphertext]
pub const ENCRYPTED_ROUTER_ADDRESS: Address = address!("00000000000000000000000000000000000000C1");

/// Shared interface for cross-EVM communication
pub trait CrossEvmCall: std::fmt::Debug {
    /// Execute a call in the child EVM from the parent
    /// Note: For encrypted communication, the input should already be encrypted
    fn call_child(&self, target: Address, input: &Bytes) -> Result<Bytes, &'static str>;

    /// Execute a call in the parent EVM from the child
    fn call_parent(&self, target: Address, input: &Bytes) -> Result<Bytes, &'static str>;

    /// Execute an encrypted call in the child EVM from the parent
    /// The input will be decrypted by the child, executed, and the response will be encrypted
    fn call_child_encrypted(
        &self,
        target: Address,
        encrypted_input: &Bytes,
    ) -> Result<Bytes, &'static str>;
}

/// Custom precompile provider for parent EVM
#[derive(Clone)]
pub struct ParentPrecompileProvider {
    inner: EthPrecompiles,
    spec: SpecId,
    handler: Rc<RefCell<dyn CrossEvmCall>>,
    /// Optional coordinator for atomic cross-EVM transactions
    coordinator: Option<Arc<TransactionCoordinator>>,
}

impl std::fmt::Debug for ParentPrecompileProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParentPrecompileProvider")
            .field("spec", &self.spec)
            .field("has_coordinator", &self.coordinator.is_some())
            .finish()
    }
}

impl ParentPrecompileProvider {
    /// Create a new parent precompile provider
    ///
    /// # Arguments
    /// * `spec` - The EVM specification ID
    /// * `handler` - Handler for cross-EVM calls to the child
    pub fn new(spec: SpecId, handler: Rc<RefCell<dyn CrossEvmCall>>) -> Self {
        Self {
            inner: EthPrecompiles::default(),
            spec,
            handler,
            coordinator: None,
        }
    }

    /// Create a new parent precompile provider with atomic transaction support
    ///
    /// # Arguments
    /// * `spec` - The EVM specification ID
    /// * `handler` - Handler for cross-EVM calls to the child
    /// * `coordinator` - Transaction coordinator for atomic cross-EVM operations
    pub fn new_with_coordinator(
        spec: SpecId,
        handler: Rc<RefCell<dyn CrossEvmCall>>,
        coordinator: Arc<TransactionCoordinator>,
    ) -> Self {
        Self {
            inner: EthPrecompiles::default(),
            spec,
            handler,
            coordinator: Some(coordinator),
        }
    }
}

impl<CTX> PrecompileProvider<CTX> for ParentPrecompileProvider
where
    CTX: ContextTr<Cfg: Cfg<Spec = SpecId>>,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        if spec == self.spec {
            return false;
        }
        self.spec = spec;
        self.inner = EthPrecompiles::default();
        true
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        // Check if this is our custom router precompile (unencrypted)
        if inputs.bytecode_address == ROUTER_ADDRESS {
            return Ok(Some(run_call_child_precompile(
                &self.handler,
                &self.coordinator,
                context,
                inputs,
            )?));
        }

        // Check if this is the encrypted router precompile
        if inputs.bytecode_address == ENCRYPTED_ROUTER_ADDRESS {
            return Ok(Some(run_call_child_encrypted_precompile(
                &self.handler,
                &self.coordinator,
                context,
                inputs,
            )?));
        }

        // Otherwise, delegate to standard Ethereum precompiles
        self.inner.run(context, inputs)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        let mut addresses = vec![ROUTER_ADDRESS, ENCRYPTED_ROUTER_ADDRESS];
        addresses.extend(self.inner.warm_addresses());
        Box::new(addresses.into_iter())
    }

    fn contains(&self, address: &Address) -> bool {
        *address == ROUTER_ADDRESS
            || *address == ENCRYPTED_ROUTER_ADDRESS
            || self.inner.contains(address)
    }
}

/// Custom precompile provider for child EVM
#[derive(Clone)]
pub struct ChildPrecompileProvider {
    inner: EthPrecompiles,
    spec: SpecId,
    handler: Rc<RefCell<dyn CrossEvmCall>>,
    /// Optional coordinator for atomic cross-EVM transactions
    coordinator: Option<Arc<TransactionCoordinator>>,
}

impl std::fmt::Debug for ChildPrecompileProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildPrecompileProvider")
            .field("spec", &self.spec)
            .field("has_coordinator", &self.coordinator.is_some())
            .finish()
    }
}

impl ChildPrecompileProvider {
    /// Create a new child precompile provider
    ///
    /// # Arguments
    /// * `spec` - The EVM specification ID
    /// * `handler` - Handler for cross-EVM calls to the parent
    pub fn new(spec: SpecId, handler: Rc<RefCell<dyn CrossEvmCall>>) -> Self {
        Self {
            inner: EthPrecompiles::default(),
            spec,
            handler,
            coordinator: None,
        }
    }

    /// Create a new child precompile provider with atomic transaction support
    ///
    /// # Arguments
    /// * `spec` - The EVM specification ID
    /// * `handler` - Handler for cross-EVM calls to the parent
    /// * `coordinator` - Transaction coordinator for atomic cross-EVM operations
    pub fn new_with_coordinator(
        spec: SpecId,
        handler: Rc<RefCell<dyn CrossEvmCall>>,
        coordinator: Arc<TransactionCoordinator>,
    ) -> Self {
        Self {
            inner: EthPrecompiles::default(),
            spec,
            handler,
            coordinator: Some(coordinator),
        }
    }
}

impl<CTX> PrecompileProvider<CTX> for ChildPrecompileProvider
where
    CTX: ContextTr<Cfg: Cfg<Spec = SpecId>>,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        if spec == self.spec {
            return false;
        }
        self.spec = spec;
        self.inner = EthPrecompiles::default();
        true
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        // Check if this is our custom router precompile
        if inputs.bytecode_address == ROUTER_ADDRESS {
            return Ok(Some(run_call_parent_precompile(
                &self.handler,
                &self.coordinator,
                context,
                inputs,
            )?));
        }

        // Otherwise, delegate to standard Ethereum precompiles
        self.inner.run(context, inputs)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        let mut addresses = vec![ROUTER_ADDRESS];
        addresses.extend(self.inner.warm_addresses());
        Box::new(addresses.into_iter())
    }

    fn contains(&self, address: &Address) -> bool {
        *address == ROUTER_ADDRESS || self.inner.contains(address)
    }
}

/// Runs the call_child precompile
fn run_call_child_precompile<CTX: ContextTr>(
    handler: &Rc<RefCell<dyn CrossEvmCall>>,
    coordinator: &Option<Arc<TransactionCoordinator>>,
    context: &mut CTX,
    inputs: &CallInputs,
) -> Result<InterpreterResult, String> {
    let input_bytes = match &inputs.input {
        revm::interpreter::CallInput::SharedBuffer(range) => {
            if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                slice.to_vec()
            } else {
                vec![]
            }
        }
        revm::interpreter::CallInput::Bytes(bytes) => bytes.0.to_vec(),
    };

    // Input format: [20 bytes address][remaining bytes data]
    if input_bytes.len() < 20 {
        return Err("Input too short, need at least 20 bytes for address".to_string());
    }

    let target_address = Address::from_slice(&input_bytes[0..20]);
    let call_data = Bytes::from(input_bytes[20..].to_vec());

    // Notify coordinator of cross-EVM call (if using atomic transactions)
    if let Some(coord) = coordinator {
        coord.enter_cross_evm_call();
    }

    // Call the child EVM
    let result = match handler.borrow().call_child(target_address, &call_data) {
        Ok(output) => {
            let precompile_output = PrecompileOutput::new(10000, output);
            let mut interpreter_result = InterpreterResult {
                result: InstructionResult::Return,
                gas: Gas::new(inputs.gas_limit),
                output: precompile_output.bytes,
            };
            let underflow = interpreter_result
                .gas
                .record_cost(precompile_output.gas_used);
            if !underflow {
                interpreter_result.result = InstructionResult::PrecompileOOG;
            }
            Ok(interpreter_result)
        }
        Err(e) => {
            // Mark error for atomic transaction rollback
            if let Some(coord) = coordinator {
                coord.mark_error();
            }
            Err(format!("Error calling child: {}", e))
        }
    };

    // Exit cross-EVM call
    if let Some(coord) = coordinator {
        coord.exit_cross_evm_call();
    }

    result
}

/// Runs the call_parent precompile
fn run_call_parent_precompile<CTX: ContextTr>(
    handler: &Rc<RefCell<dyn CrossEvmCall>>,
    coordinator: &Option<Arc<TransactionCoordinator>>,
    context: &mut CTX,
    inputs: &CallInputs,
) -> Result<InterpreterResult, String> {
    let input_bytes = match &inputs.input {
        revm::interpreter::CallInput::SharedBuffer(range) => {
            if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                slice.to_vec()
            } else {
                vec![]
            }
        }
        revm::interpreter::CallInput::Bytes(bytes) => bytes.0.to_vec(),
    };

    // Input format: [20 bytes address][remaining bytes data]
    if input_bytes.len() < 20 {
        return Err("Input too short, need at least 20 bytes for address".to_string());
    }

    let target_address = Address::from_slice(&input_bytes[0..20]);
    let call_data = Bytes::from(input_bytes[20..].to_vec());

    // Notify coordinator of cross-EVM call (if using atomic transactions)
    if let Some(coord) = coordinator {
        coord.enter_cross_evm_call();
    }

    // Call the parent EVM
    let result = match handler.borrow().call_parent(target_address, &call_data) {
        Ok(output) => {
            let precompile_output = PrecompileOutput::new(10000, output);
            let mut interpreter_result = InterpreterResult {
                result: InstructionResult::Return,
                gas: Gas::new(inputs.gas_limit),
                output: precompile_output.bytes,
            };
            let underflow = interpreter_result
                .gas
                .record_cost(precompile_output.gas_used);
            if !underflow {
                interpreter_result.result = InstructionResult::PrecompileOOG;
            }
            Ok(interpreter_result)
        }
        Err(e) => {
            // Mark error for atomic transaction rollback
            if let Some(coord) = coordinator {
                coord.mark_error();
            }
            Err(format!("Error calling parent: {}", e))
        }
    };

    // Exit cross-EVM call
    if let Some(coord) = coordinator {
        coord.exit_cross_evm_call();
    }

    result
}

/// Runs the encrypted call_child precompile
/// Input format: [20 bytes target address][encrypted payload]
/// where encrypted payload = [12 bytes nonce][32 bytes user_pubkey][ciphertext]
fn run_call_child_encrypted_precompile<CTX: ContextTr>(
    handler: &Rc<RefCell<dyn CrossEvmCall>>,
    coordinator: &Option<Arc<TransactionCoordinator>>,
    context: &mut CTX,
    inputs: &CallInputs,
) -> Result<InterpreterResult, String> {
    let input_bytes = match &inputs.input {
        revm::interpreter::CallInput::SharedBuffer(range) => {
            if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                slice.to_vec()
            } else {
                vec![]
            }
        }
        revm::interpreter::CallInput::Bytes(bytes) => bytes.0.to_vec(),
    };

    // Input format: [20 bytes address][encrypted payload]
    // Encrypted payload must be at least: 12 (nonce) + 32 (pubkey) + 16 (auth tag) = 60 bytes
    if input_bytes.len() < 20 + 60 {
        return Err("Input too short for encrypted call".to_string());
    }

    let target_address = Address::from_slice(&input_bytes[0..20]);
    let encrypted_data = Bytes::from(input_bytes[20..].to_vec());

    // Notify coordinator of cross-EVM call (if using atomic transactions)
    if let Some(coord) = coordinator {
        coord.enter_cross_evm_call();
    }

    // Call the child EVM with encrypted data
    let result = match handler
        .borrow()
        .call_child_encrypted(target_address, &encrypted_data)
    {
        Ok(encrypted_output) => {
            let precompile_output = PrecompileOutput::new(50000, encrypted_output); // Higher gas for encryption
            let mut interpreter_result = InterpreterResult {
                result: InstructionResult::Return,
                gas: Gas::new(inputs.gas_limit),
                output: precompile_output.bytes,
            };
            let underflow = interpreter_result
                .gas
                .record_cost(precompile_output.gas_used);
            if !underflow {
                interpreter_result.result = InstructionResult::PrecompileOOG;
            }
            Ok(interpreter_result)
        }
        Err(e) => {
            // Mark error for atomic transaction rollback
            if let Some(coord) = coordinator {
                coord.mark_error();
            }
            Err(format!("Error calling child encrypted: {}", e))
        }
    };

    // Exit cross-EVM call
    if let Some(coord) = coordinator {
        coord.exit_cross_evm_call();
    }

    result
}
