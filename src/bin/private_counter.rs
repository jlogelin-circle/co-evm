//! Private Counter: Encrypted Communication with Enclave EVM
//!
//! This demonstrates end-to-end encryption for private smart contracts:
//! 1. User encrypts transaction data with enclave's public key
//! 2. Parent EVM forwards encrypted data to child EVM (enclave)
//! 3. Enclave decrypts, executes the smart contract
//! 4. Enclave encrypts the response with user's public key
//! 5. User decrypts the response
//!
//! Benefits:
//! - Complete privacy: only user and enclave can see transaction details
//! - On-chain observers see only encrypted blobs
//! - Smart contract state is protected
//! - Responses are encrypted for the specific user

use alloy_sol_types::{SolCall, sol};
use anyhow::Result;
use co_evm::{
    child_evm::ChildEvm,
    crypto::{EnclaveKeys, UserKeyPair, UserKeys},
    parent_evm::ParentEvm,
    precompiles::CrossEvmCall,
};
use revm::{
    Context, MainContext,
    context::{BlockEnv, CfgEnv, Journal, LocalContext, TxEnv},
    context_interface::result::{ExecutionResult, Output},
    database::InMemoryDB,
    handler::ExecuteCommitEvm,
    primitives::{Address, Bytes, TxKind, U256},
};
use std::{cell::RefCell, rc::Rc};

sol! {
    #[allow(missing_docs)]
    /// Interface for PrivateCounter
    interface IPrivateCounter {
        function count() external view returns (uint256);
        function increment() external;
        function add(uint256 value) external;
        function set(uint256 value) external;
        function getCount() external view returns (uint256);
    }

    #[allow(missing_docs)]
    /// PrivateCounter contract - runs in enclave with encrypted communication
    /// Compiled with: solc v0.8.30 --via-ir --optimize PrivateCounter.sol --bin
    #[sol(bytecode="6080604052348015600e575f5ffd5b506101688061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610055575f3560e01c806306661abd146100595780631003e2d21461007357806360fe47b114610088578063a87d942c1461009a578063d09de08a146100a1575b5f5ffd5b6100615f5481565b60405190815260200160405180910390f35b6100866100813660046100d6565b6100a9565b005b6100866100963660046100d6565b5f55565b5f54610061565b6100866100c1565b805f5f8282546100b99190610101565b909155505050565b5f805490806100cf8361011a565b9190505550565b5f602082840312156100e6575f5ffd5b5035919050565b634e487b7160e01b5f52601160045260245ffd5b80820180821115610114576101146100ed565b92915050565b5f6001820161012b5761012b6100ed565b506001019056fea2646970667358221220f81cd336024f47c8e30934756e671ac9f53490d14fb6a4ca654f4e82b659e16864736f6c634300081e0033")]
    contract PrivateCounter {
        uint256 public count;

        function increment() public {
            count++;
        }

        function getCount() public view returns (uint256) {
            return count;
        }

        function add(uint256 value) public {
            count += value;
        }

        function set(uint256 value) public {
            count = value;
        }
    }
}

// Type alias for the context we're using
type EvmContext =
    Context<BlockEnv, TxEnv, CfgEnv, InMemoryDB, Journal<InMemoryDB>, (), LocalContext>;

/// Coordinator that manages both parent and child EVMs
#[derive(Debug)]
struct PrivateCoordinator {
    parent: RefCell<Option<ParentEvm<EvmContext, ()>>>,
    child: RefCell<Option<ChildEvm<EvmContext, ()>>>,
    parent_nonce: RefCell<u64>,
    child_nonce: RefCell<u64>,
}

impl PrivateCoordinator {
    fn new() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            parent: RefCell::new(None),
            child: RefCell::new(None),
            parent_nonce: RefCell::new(0),
            child_nonce: RefCell::new(0),
        }))
    }

    fn set_parent(&self, parent: ParentEvm<EvmContext, ()>) {
        *self.parent.borrow_mut() = Some(parent);
    }

    fn set_child(&self, child: ChildEvm<EvmContext, ()>) {
        *self.child.borrow_mut() = Some(child);
    }

    fn get_parent_nonce(&self) -> u64 {
        *self.parent_nonce.borrow()
    }

    fn get_child_nonce(&self) -> u64 {
        *self.child_nonce.borrow()
    }

    fn increment_parent_nonce(&self) {
        *self.parent_nonce.borrow_mut() += 1;
    }

    fn increment_child_nonce(&self) {
        *self.child_nonce.borrow_mut() += 1;
    }

    fn get_enclave_public_key(&self) -> Vec<u8> {
        let child_guard = self.child.borrow();
        let child = child_guard.as_ref().expect("Child not initialized");
        child.public_key()
    }
}

impl CrossEvmCall for PrivateCoordinator {
    fn call_child(&self, target: Address, input: &Bytes) -> Result<Bytes, &'static str> {
        let mut child_guard = self.child.borrow_mut();
        let child = child_guard.as_mut().ok_or("Child EVM not initialized")?;

        let nonce = self.get_child_nonce();
        match child.call_contract(target, input.clone(), nonce) {
            Ok(result) => {
                self.increment_child_nonce();
                match result {
                    ExecutionResult::Success { output, .. } => {
                        let output_bytes = match output {
                            Output::Call(data) => data,
                            Output::Create(data, _) => data,
                        };
                        Ok(output_bytes)
                    }
                    _ => Err("Child execution failed"),
                }
            }
            Err(_) => Err("Child execution error"),
        }
    }

    fn call_parent(&self, target: Address, input: &Bytes) -> Result<Bytes, &'static str> {
        let mut parent_guard = self.parent.borrow_mut();
        let parent = parent_guard.as_mut().ok_or("Parent EVM not initialized")?;

        let nonce = self.get_parent_nonce();
        match parent.call_contract(target, input.clone(), nonce) {
            Ok(result) => {
                self.increment_parent_nonce();
                match result {
                    ExecutionResult::Success { output, .. } => {
                        let output_bytes = match output {
                            Output::Call(data) => data,
                            Output::Create(data, _) => data,
                        };
                        Ok(output_bytes)
                    }
                    _ => Err("Parent execution failed"),
                }
            }
            Err(_) => Err("Parent execution error"),
        }
    }

    fn call_child_encrypted(
        &self,
        target: Address,
        encrypted_input: &Bytes,
    ) -> Result<Bytes, &'static str> {
        let mut child_guard = self.child.borrow_mut();
        let child = child_guard.as_mut().ok_or("Child EVM not initialized")?;

        let nonce = self.get_child_nonce();
        match child.call_contract_encrypted(target, encrypted_input.clone(), nonce) {
            Ok(encrypted_response) => {
                self.increment_child_nonce();
                Ok(encrypted_response)
            }
            Err(_) => Err("Child encrypted execution error"),
        }
    }
}

/// Initialize parent EVM
fn init_parent(coordinator: Rc<RefCell<PrivateCoordinator>>) -> Result<()> {
    let ctx = Context::mainnet().with_db(InMemoryDB::default());
    let parent_evm = ParentEvm::new(ctx, (), coordinator.clone());
    coordinator.borrow().set_parent(parent_evm);
    Ok(())
}

/// Initialize child EVM with specific keys (for testing)
fn init_child(
    coordinator: Rc<RefCell<PrivateCoordinator>>,
    keys: Option<EnclaveKeys>,
) -> Result<()> {
    let ctx = Context::mainnet().with_db(InMemoryDB::default());
    let child_evm = if let Some(k) = keys {
        ChildEvm::with_keys(ctx, (), coordinator.clone(), k)
    } else {
        ChildEvm::new(ctx, (), coordinator.clone())
    };
    coordinator.borrow().set_child(child_evm);
    Ok(())
}

/// Deploy PrivateCounter on child EVM
fn deploy_counter(coordinator: &Rc<RefCell<PrivateCoordinator>>) -> Result<Address> {
    let bytecode = PrivateCounter::BYTECODE.to_vec();
    let coord_borrow = coordinator.borrow();
    let nonce = coord_borrow.get_child_nonce();
    let mut child_guard = coord_borrow.child.borrow_mut();
    let child = child_guard.as_mut().expect("Child not initialized");

    let tx = TxEnv::builder()
        .kind(TxKind::Create)
        .data(Bytes::from(bytecode))
        .gas_limit(10_000_000)
        .nonce(nonce)
        .build()
        .unwrap();

    let result = ExecuteCommitEvm::transact_commit(&mut child.evm, tx)?;

    drop(child_guard);
    coord_borrow.increment_child_nonce();

    match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(address)),
            ..
        } => {
            println!("✅ PrivateCounter deployed at: {}", address);
            Ok(address)
        }
        _ => anyhow::bail!("Failed to deploy PrivateCounter"),
    }
}

/// Call increment via encrypted channel
fn encrypted_increment(
    coordinator: &Rc<RefCell<PrivateCoordinator>>,
    counter_addr: Address,
    user_keys: &UserKeys,
) -> Result<()> {
    let enclave_pubkey_bytes = coordinator.borrow().get_enclave_public_key();

    // Prepare the increment call data
    let call_data = IPrivateCounter::incrementCall {}.abi_encode();

    // Encrypt the call data for the enclave
    let encrypted_call = user_keys.encrypt_for_enclave(&call_data, &enclave_pubkey_bytes)?;

    // Prepare input for encrypted router: [target address][encrypted payload]
    let mut router_input = Vec::with_capacity(20 + encrypted_call.len());
    router_input.extend_from_slice(counter_addr.as_slice());
    router_input.extend_from_slice(&encrypted_call);

    // Call the encrypted router precompile (0xC1)
    let coord_borrow = coordinator.borrow();
    let nonce = coord_borrow.get_parent_nonce();
    let mut parent_guard = coord_borrow.parent.borrow_mut();
    let parent = parent_guard.as_mut().expect("Parent not initialized");

    let tx = TxEnv::builder()
        .kind(TxKind::Call(Address::from_slice(
            &hex::decode("00000000000000000000000000000000000000C1").unwrap(),
        )))
        .data(Bytes::from(router_input))
        .gas_limit(10_000_000)
        .nonce(nonce)
        .build()
        .unwrap();

    let result = ExecuteCommitEvm::transact_commit(&mut parent.evm, tx)?;

    drop(parent_guard);
    coord_borrow.increment_parent_nonce();

    // Extract encrypted response
    match result {
        ExecutionResult::Success { output, .. } => {
            let encrypted_response = match output {
                Output::Call(data) => data,
                Output::Create(data, _) => data,
            };

            // Decrypt the response
            if !encrypted_response.is_empty() {
                let _decrypted_response = user_keys.decrypt_response(&encrypted_response)?;
                println!("✅ Encrypted increment succeeded (response decrypted)");
            } else {
                println!("✅ Encrypted increment succeeded (no return value)");
            }

            Ok(())
        }
        _ => anyhow::bail!("Encrypted call failed"),
    }
}

/// Read counter value directly (non-encrypted, for verification)
fn read_counter(coordinator: &Rc<RefCell<PrivateCoordinator>>, addr: Address) -> Result<U256> {
    let coord_borrow = coordinator.borrow();
    let nonce = coord_borrow.get_child_nonce();
    let mut child_guard = coord_borrow.child.borrow_mut();
    let child = child_guard.as_mut().expect("Child not initialized");

    let call_data = IPrivateCounter::countCall {}.abi_encode();
    let result = child.call_contract(addr, Bytes::from(call_data), nonce)?;

    drop(child_guard);
    coord_borrow.increment_child_nonce();

    match result {
        ExecutionResult::Success { output, .. } => {
            let output_bytes = match output {
                Output::Call(data) => data,
                Output::Create(data, _) => data,
            };

            if output_bytes.len() >= 32 {
                let value = U256::from_be_slice(&output_bytes[..32]);
                Ok(value)
            } else {
                anyhow::bail!("Invalid output length")
            }
        }
        _ => anyhow::bail!("Call failed"),
    }
}

fn main() -> Result<()> {
    println!("\n🔒 Private Counter: Encrypted Smart Contract Execution 🔒\n");
    println!("═══════════════════════════════════════════════════════════════");
    println!("✨ End-to-end encryption for private smart contracts!");
    println!("   • User encrypts transaction → Enclave");
    println!("   • Enclave decrypts, executes privately");
    println!("   • Enclave encrypts response → User");
    println!("   • On-chain observers see only encrypted blobs\n");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Initialize
    let coordinator = PrivateCoordinator::new();
    init_parent(coordinator.clone())?;
    init_child(coordinator.clone(), None)?;

    // Generate user keys
    let user_keys = UserKeys::generate();
    println!("🔑 User key pair generated");

    // Get enclave's public key
    let enclave_pubkey = coordinator.borrow().get_enclave_public_key();
    println!("🔑 Enclave public key: {}\n", hex::encode(enclave_pubkey));

    // Deploy counter
    println!("📦 Deploying private counter in enclave...\n");
    let counter_addr = deploy_counter(&coordinator)?;
    println!();

    // Initial state
    let count = read_counter(&coordinator, counter_addr)?;
    println!("📊 Initial counter value: {}\n", count);

    // Encrypted increment
    println!("🔐 Sending encrypted increment transaction...");
    println!("   → Transaction data is encrypted with enclave's public key");
    println!("   → Only the enclave can decrypt and execute it\n");

    encrypted_increment(&coordinator, counter_addr, &user_keys)?;
    println!();

    // Verify increment worked
    let count = read_counter(&coordinator, counter_addr)?;
    println!("📊 Counter after encrypted increment: {}\n", count);

    // Do it again to show it works multiple times
    println!("🔐 Sending another encrypted increment...\n");
    encrypted_increment(&coordinator, counter_addr, &user_keys)?;
    println!();

    let count = read_counter(&coordinator, counter_addr)?;
    println!("📊 Final counter value: {}\n", count);

    println!("═══════════════════════════════════════════════════════════════\n");
    println!("✅ Success! Private smart contract execution completed!");
    println!("   • All transactions were encrypted end-to-end");
    println!("   • Enclave processed private computations");
    println!("   • Responses were encrypted for the user");
    println!("   • On-chain observers saw only encrypted data\n");

    println!("🎉 This demonstrates true privacy-preserving smart contracts! 🎉\n");

    Ok(())
}
