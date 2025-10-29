//! Clean Test Counter: Ultimate Clean Syntax with Universal CrossEvmLib
//!
//! This demonstrates the CLEANEST possible syntax for cross-EVM calls:
//!   ITestCounter(CrossEvmLib.other(otherAddr)).increment();
//!
//! Uses a SINGLE universal library and contract that works on BOTH EVMs!

use alloy_sol_types::{SolCall, sol};
use anyhow::Result;
use revm::{
    Context, MainContext,
    context::{BlockEnv, CfgEnv, Journal, LocalContext, TxEnv},
    context_interface::result::{ExecutionResult, Output},
    database::InMemoryDB,
    handler::ExecuteCommitEvm,
    primitives::{Address, Bytes, TxKind, U256},
};
use std::{cell::RefCell, rc::Rc};

use co_evm::{child_evm::ChildEvm, parent_evm::ParentEvm, precompiles::CrossEvmCall};

sol! {
    #[allow(missing_docs)]
    /// Interface for TestCounter
    interface ITestCounter {
        function count() external view returns (uint256);
        function increment() external;
        function incrementOther(address otherCounterAddr) external;
    }

    #[allow(missing_docs)]
    /// TestCounter - Universal contract that works on BOTH parent and child EVMs
    /// Uses CrossEvmLib.other() with CREATE2 for deterministic, reusable proxies
    /// Compiled with: solc v0.8.30 --via-ir --optimize TestCounterWithLib.sol
    #[sol(bytecode="60808060405234601557610526908161001a8239f35b5f80fdfe60806040526004361015610011575f80fd5b5f3560e01c806306661abd146101d95780632aa8e5c21461003f5763d09de08a1461003a575f80fd5b6101fe565b346101b35760203660031901126101b3576004356001600160a01b0381168082036101b3576100d96101499161016d936100e76100b16100bf61020e9361008860208601610274565b948086526102e36020870139604080516001600160a01b03909216602083015290928391820190565b03601f198101835282610233565b6040519485916100d3602084018096610284565b90610284565b03601f198101855284610233565b825181206040516001600160f81b0319602082019081523060601b6bffffffffffffffffffffffff19166021830152603582018590526055820192909252610155916101499161013a81607581016100b1565b5190206001600160a01b031690565b6001600160a01b031690565b92833b156101b7575b5050506001600160a01b031690565b803b156101b3575f809160046040518094819363684ef04560e11b83525af180156101ae5761019857005b806101a65f6101ac93610233565b806101f4565b005b610269565b5f80fd5b519192505ff56101d16001600160a01b0382161515610296565b83808061015e565b346101b3575f3660031901126101b3575f5460805260206080f35b5f9103126101b357565b346101b3575f3660031901126101b3575f545f19811461021f576001015f55005b634e487b7160e01b5f52601160045260245ffd5b90601f8019910116810190811067ffffffffffffffff82111761025557604052565b634e487b7160e01b5f52604160045260245ffd5b6040513d5f823e3d90fd5b906102826040519283610233565b565b805191908290602001825e015f815290565b1561029d57565b60405162461bcd60e51b815260206004820152601760248201527f50726f7879206465706c6f796d656e74206661696c65640000000000000000006044820152606490fdfe60a034606557601f61020e38819003918201601f19168301916001600160401b03831184841017606957808492602094604052833981010312606557516001600160a01b0381168103606557608052604051610190908161007e82396080518160060152f35b5f80fd5b634e487b7160e01b5f52604160045260245ffdfe60806040527f000000000000000000000000000000000000000000000000000000000000000060601b6bffffffffffffffffffffffff191660a052365f60b4375f60b436015260143601608052610058603436016100d1565b5f8060805160a08260c05af13d156100b2573d9067ffffffffffffffff82116100ad576100a590604051926100976020601f19601f84011601856100f4565b83523d5f602085013e610116565b602081519101f35b6100bd565b6100a5606091610116565b634e487b7160e01b5f52604160045260245ffd5b601f80199101166080016080811067ffffffffffffffff8211176100ad57604052565b90601f8019910116810190811067ffffffffffffffff8211176100ad57604052565b1561011d57565b60405162461bcd60e51b815260206004820152601560248201527410dc9bdcdccb5155934818d85b1b0819985a5b1959605a1b6044820152606490fdfea2646970667358221220ea88fb540bb948805248d2eb622ddd61dcdf726b65bf076e174637dc8008ce5564736f6c634300081e0033a26469706673582212209d8455aa030786251aefc02544c33b138161346272853a923c907143d6c0412064736f6c634300081e0033")]
    contract TestCounter {
        uint256 public count;

        function increment() public {
            count++;
        }

        function incrementOther(address otherCounterAddr) public {
            // This is exactly what you wanted!
            ITestCounter(CrossEvmLib.other(otherCounterAddr)).increment();
        }
    }

}

// Type alias for the context we're using
type EvmContext =
    Context<BlockEnv, TxEnv, CfgEnv, InMemoryDB, Journal<InMemoryDB>, (), LocalContext>;

/// Coordinator that manages both parent and child EVMs
#[derive(Debug)]
struct CleanCoordinator {
    parent: RefCell<Option<ParentEvm<EvmContext, ()>>>,
    child: RefCell<Option<ChildEvm<EvmContext, ()>>>,
    parent_nonce: RefCell<u64>,
    child_nonce: RefCell<u64>,
}

impl CleanCoordinator {
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
}

impl CrossEvmCall for CleanCoordinator {
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
fn init_parent(coordinator: Rc<RefCell<CleanCoordinator>>) -> Result<()> {
    let ctx = Context::mainnet().with_db(InMemoryDB::default());
    let parent_evm = ParentEvm::new(ctx, (), coordinator.clone());
    coordinator.borrow().set_parent(parent_evm);
    Ok(())
}

/// Initialize child EVM
fn init_child(coordinator: Rc<RefCell<CleanCoordinator>>) -> Result<()> {
    let ctx = Context::mainnet().with_db(InMemoryDB::default());
    let child_evm = ChildEvm::new(ctx, (), coordinator.clone());
    coordinator.borrow().set_child(child_evm);
    Ok(())
}

/// Deploy TestCounter on parent EVM
fn deploy_parent_counter(coordinator: &Rc<RefCell<CleanCoordinator>>) -> Result<Address> {
    let bytecode = TestCounter::BYTECODE.to_vec();
    let coord_borrow = coordinator.borrow();
    let nonce = coord_borrow.get_parent_nonce();
    let mut parent_guard = coord_borrow.parent.borrow_mut();
    let parent = parent_guard.as_mut().expect("Parent not initialized");

    let tx = TxEnv::builder()
        .kind(TxKind::Create)
        .data(Bytes::from(bytecode))
        .gas_limit(10_000_000)
        .nonce(nonce)
        .build()
        .unwrap();

    let result = ExecuteCommitEvm::transact_commit(&mut parent.evm, tx)?;

    drop(parent_guard);
    coord_borrow.increment_parent_nonce();

    match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(address)),
            ..
        } => {
            println!("✅ TestCounter (parent) deployed at: {}", address);
            Ok(address)
        }
        _ => anyhow::bail!("Failed to deploy TestCounter on parent"),
    }
}

/// Deploy TestCounter on child EVM
fn deploy_child_counter(coordinator: &Rc<RefCell<CleanCoordinator>>) -> Result<Address> {
    let bytecode = TestCounter::BYTECODE.to_vec();
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
            println!("✅ TestCounter (child) deployed at: {}", address);
            Ok(address)
        }
        _ => anyhow::bail!("Failed to deploy TestCounter on child"),
    }
}

/// Read counter value from parent EVM
fn read_parent_counter(coordinator: &Rc<RefCell<CleanCoordinator>>, addr: Address) -> Result<U256> {
    let coord_borrow = coordinator.borrow();
    let nonce = coord_borrow.get_parent_nonce();
    let mut parent_guard = coord_borrow.parent.borrow_mut();
    let parent = parent_guard.as_mut().expect("Parent not initialized");

    let call_data = ITestCounter::countCall {}.abi_encode();

    let result = parent.call_contract(addr, Bytes::from(call_data), nonce)?;

    drop(parent_guard);
    coord_borrow.increment_parent_nonce();

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

/// Read counter value from child EVM
fn read_child_counter(coordinator: &Rc<RefCell<CleanCoordinator>>, addr: Address) -> Result<U256> {
    let coord_borrow = coordinator.borrow();
    let nonce = coord_borrow.get_child_nonce();
    let mut child_guard = coord_borrow.child.borrow_mut();
    let child = child_guard.as_mut().expect("Child not initialized");

    let call_data = ITestCounter::countCall {}.abi_encode();

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

/// Call incrementOther on parent counter
fn parent_increment_other(
    coordinator: &Rc<RefCell<CleanCoordinator>>,
    parent_counter: Address,
    child_counter: Address,
) -> Result<()> {
    let call = ITestCounter::incrementOtherCall {
        otherCounterAddr: child_counter,
    };
    let coord_borrow = coordinator.borrow();
    let nonce = coord_borrow.get_parent_nonce();
    let mut parent_guard = coord_borrow.parent.borrow_mut();
    let parent = parent_guard.as_mut().expect("Parent not initialized");

    let tx = TxEnv::builder()
        .kind(TxKind::Call(parent_counter))
        .data(Bytes::from(call.abi_encode()))
        .gas_limit(10_000_000)
        .nonce(nonce)
        .build()
        .unwrap();

    ExecuteCommitEvm::transact_commit(&mut parent.evm, tx)?;

    drop(parent_guard);
    coord_borrow.increment_parent_nonce();
    Ok(())
}

/// Call incrementOther on child counter
#[allow(dead_code)]
fn child_increment_other(
    coordinator: &Rc<RefCell<CleanCoordinator>>,
    child_counter: Address,
    parent_counter: Address,
) -> Result<()> {
    let call = ITestCounter::incrementOtherCall {
        otherCounterAddr: parent_counter,
    };
    let coord_borrow = coordinator.borrow();
    let nonce = coord_borrow.get_child_nonce();
    let mut child_guard = coord_borrow.child.borrow_mut();
    let child = child_guard.as_mut().expect("Child not initialized");

    let tx = TxEnv::builder()
        .kind(TxKind::Call(child_counter))
        .data(Bytes::from(call.abi_encode()))
        .gas_limit(10_000_000)
        .nonce(nonce)
        .build()
        .unwrap();

    ExecuteCommitEvm::transact_commit(&mut child.evm, tx)?;

    drop(child_guard);
    coord_borrow.increment_child_nonce();
    Ok(())
}

fn main() -> Result<()> {
    println!("\n🎉 Ultimate Clean Syntax Demonstration 🎉\n");
    println!("═══════════════════════════════════════════════════════════════");
    println!("✨ Key insight: Only ONE router address (0xC0) needed!");
    println!("   • Parent EVM: routes to child");
    println!("   • Child EVM: routes to parent");
    println!("   • Same contract bytecode works on BOTH EVMs!\n");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Initialize
    let coordinator = CleanCoordinator::new();
    init_parent(coordinator.clone())?;
    init_child(coordinator.clone())?;

    // Deploy counters
    println!("📦 Deploying contracts...\n");
    let parent_counter = deploy_parent_counter(&coordinator)?;
    let child_counter = deploy_child_counter(&coordinator)?;
    println!();

    // Initial state
    let parent_count = read_parent_counter(&coordinator, parent_counter)?;
    let child_count = read_child_counter(&coordinator, child_counter)?;
    println!("📊 Initial state:");
    println!("   Parent counter: {}", parent_count);
    println!("   Child counter:  {}\n", child_count);

    // Parent increments child via universal library
    println!("🔄 Parent calls: incrementOther(childAddr)");
    println!("   Expands to: ITestCounter(CrossEvmLib.other(childAddr)).increment();\n");

    parent_increment_other(&coordinator, parent_counter, child_counter)?;

    let parent_count = read_parent_counter(&coordinator, parent_counter)?;
    let child_count = read_child_counter(&coordinator, child_counter)?;
    println!("✅ After parent->child call:");
    println!("   Parent counter: {} (unchanged)", parent_count);
    println!("   Child counter:  {} (incremented!)\n", child_count);

    println!("═══════════════════════════════════════════════════════════════\n");
    println!("✨ This is the CLEANEST possible syntax!");
    println!("   • Library handles proxy deployment automatically");
    println!("   • Type-safe interface pattern");
    println!("   • No manual encoding required");
    println!("   • Works bidirectionally\n");

    println!("📝 Full implementation in:");
    println!("   • contracts/TestCounter.sol");
    println!("   • contracts/CrossEvmLib.sol (Universal library!)\n");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture for clean_test_counter tests
    struct CleanTestFixture {
        coordinator: Rc<RefCell<CleanCoordinator>>,
        parent_counter: Address,
        child_counter: Address,
    }

    impl CleanTestFixture {
        fn new() -> Self {
            let coordinator = CleanCoordinator::new();

            let parent_ctx = Context::mainnet().with_db(InMemoryDB::default());
            let child_ctx = Context::mainnet().with_db(InMemoryDB::default());

            let coord_for_parent: Rc<RefCell<dyn CrossEvmCall>> = coordinator.clone();
            let coord_for_child: Rc<RefCell<dyn CrossEvmCall>> = coordinator.clone();

            let parent_evm = ParentEvm::new(parent_ctx, (), coord_for_parent);
            let child_evm = ChildEvm::new(child_ctx, (), coord_for_child);

            coordinator.borrow().set_parent(parent_evm);
            coordinator.borrow().set_child(child_evm);

            let parent_counter = deploy_parent_counter(&coordinator).expect("Deploy parent failed");
            let child_counter = deploy_child_counter(&coordinator).expect("Deploy child failed");

            Self {
                coordinator,
                parent_counter,
                child_counter,
            }
        }

        fn read_parent_count(&self) -> u64 {
            read_parent_counter(&self.coordinator, self.parent_counter)
                .expect("Read parent failed")
                .as_limbs()[0]
        }

        fn read_child_count(&self) -> u64 {
            read_child_counter(&self.coordinator, self.child_counter)
                .expect("Read child failed")
                .as_limbs()[0]
        }

        fn parent_increment_other(&self) {
            parent_increment_other(&self.coordinator, self.parent_counter, self.child_counter)
                .expect("Parent increment other failed");
        }

        fn child_increment_other(&self) {
            child_increment_other(&self.coordinator, self.child_counter, self.parent_counter)
                .expect("Child increment other failed");
        }
    }

    #[test]
    fn test_initial_state() {
        let fixture = CleanTestFixture::new();

        assert_eq!(
            fixture.read_parent_count(),
            0,
            "Parent counter should start at 0"
        );
        assert_eq!(
            fixture.read_child_count(),
            0,
            "Child counter should start at 0"
        );
    }

    #[test]
    fn test_parent_increments_child_via_library() {
        let fixture = CleanTestFixture::new();

        // Parent calls incrementOther(childAddr)
        // Expands to: ITestCounter(ParentCrossEvmLib.other(childAddr)).increment()
        fixture.parent_increment_other();

        assert_eq!(
            fixture.read_parent_count(),
            0,
            "Parent counter should stay 0"
        );
        assert_eq!(
            fixture.read_child_count(),
            1,
            "Child counter should be incremented to 1"
        );
    }

    #[test]
    fn test_child_increments_parent_via_library() {
        let fixture = CleanTestFixture::new();

        // Child calls incrementOther(parentAddr)
        // Expands to: ITestCounter(ChildCrossEvmLib.other(parentAddr)).increment()
        fixture.child_increment_other();

        assert_eq!(
            fixture.read_parent_count(),
            1,
            "Parent counter should be incremented to 1"
        );
        assert_eq!(fixture.read_child_count(), 0, "Child counter should stay 0");
    }

    #[test]
    fn test_bidirectional_increments() {
        let fixture = CleanTestFixture::new();

        // Parent increments child
        fixture.parent_increment_other();
        assert_eq!(fixture.read_parent_count(), 0);
        assert_eq!(fixture.read_child_count(), 1);

        // Child increments parent
        fixture.child_increment_other();
        assert_eq!(fixture.read_parent_count(), 1);
        assert_eq!(fixture.read_child_count(), 1);

        // Parent increments child again
        fixture.parent_increment_other();
        assert_eq!(fixture.read_parent_count(), 1);
        assert_eq!(fixture.read_child_count(), 2);
    }

    #[test]
    fn test_multiple_cross_evm_increments() {
        let fixture = CleanTestFixture::new();

        // Parent increments child 5 times
        for _ in 0..5 {
            fixture.parent_increment_other();
        }
        assert_eq!(fixture.read_parent_count(), 0);
        assert_eq!(fixture.read_child_count(), 5);

        // Child increments parent 3 times
        for _ in 0..3 {
            fixture.child_increment_other();
        }
        assert_eq!(fixture.read_parent_count(), 3);
        assert_eq!(fixture.read_child_count(), 5);
    }

    #[test]
    fn test_state_independence() {
        let fixture = CleanTestFixture::new();

        // Each side increments the other multiple times
        fixture.parent_increment_other(); // child = 1
        fixture.child_increment_other(); // parent = 1
        fixture.parent_increment_other(); // child = 2
        fixture.parent_increment_other(); // child = 3
        fixture.child_increment_other(); // parent = 2

        assert_eq!(fixture.read_parent_count(), 2);
        assert_eq!(fixture.read_child_count(), 3);
    }

    #[test]
    fn test_library_syntax_clean() {
        let fixture = CleanTestFixture::new();

        // Verify that the clean library syntax works correctly
        // This test demonstrates the ultimate clean syntax achievement!

        // Parent uses: ParentCrossEvmLib.other(childAddr)
        fixture.parent_increment_other();
        assert_eq!(fixture.read_child_count(), 1);

        // Child uses: ChildCrossEvmLib.other(parentAddr)
        fixture.child_increment_other();
        assert_eq!(fixture.read_parent_count(), 1);

        // Both counters can be incremented independently
        fixture.parent_increment_other();
        fixture.parent_increment_other();
        assert_eq!(fixture.read_child_count(), 3);
        assert_eq!(fixture.read_parent_count(), 1);
    }

    #[test]
    fn test_contract_addresses() {
        let fixture = CleanTestFixture::new();

        // Verify contracts are deployed
        assert_ne!(fixture.parent_counter, Address::ZERO);
        assert_ne!(fixture.child_counter, Address::ZERO);

        // Contracts should have the same deterministic address
        // (deployed with same bytecode and nonce in separate EVMs)
        assert_eq!(
            fixture.parent_counter, fixture.child_counter,
            "Deterministic deployment should produce same address"
        );
    }
}
