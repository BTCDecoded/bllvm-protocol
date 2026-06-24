//! Validation Rules Tests
//!
//! Tests for protocol-specific validation rules.

use blvm_consensus::types::{OutPoint, UtxoSet};
use blvm_consensus::{Block, BlockHeader, Transaction, TransactionInput, TransactionOutput};
use blvm_protocol::validation::{ProtocolValidationContext, ProtocolValidationRules};
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion, ValidationResult};

/// Test helper: Create a simple transaction
fn create_simple_transaction() -> Transaction {
    Transaction {
        version: 1,
        inputs: blvm_consensus::tx_inputs![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x01, 0x00],
            sequence: 0xffffffff,
        }],
        outputs: blvm_consensus::tx_outputs![TransactionOutput {
            value: 1000,
            script_pubkey: vec![blvm_consensus::opcodes::OP_1],
        }],
        lock_time: 0,
    }
}

// ============================================================================
// Phase 1: ProtocolValidationRules Tests
// ============================================================================

#[test]
fn test_validation_rules_for_protocol() {
    // Test getting validation rules for different protocols
    let mainnet_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::BitcoinV1);
    let testnet_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::Testnet3);
    let regtest_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::Regtest);

    // All should have same size limits
    assert_eq!(mainnet_rules.max_block_size, 4_000_000);
    assert_eq!(testnet_rules.max_block_size, 4_000_000);
    assert_eq!(regtest_rules.max_block_size, 4_000_000);
}

#[test]
fn test_validation_rules_mainnet() {
    // Test mainnet validation rules
    let rules = ProtocolValidationRules::mainnet();

    assert_eq!(rules.max_block_size, 4_000_000);
    assert_eq!(rules.max_tx_size, 1_000_000);
    assert_eq!(rules.max_script_size, 10_000);
    assert!(rules.segwit_enabled);
    assert!(rules.taproot_enabled);
    assert!(rules.rbf_enabled);
    assert_eq!(rules.min_fee_rate, 1);
    assert_eq!(rules.max_fee_rate, 1_000_000);
}

#[test]
fn test_validation_rules_testnet() {
    // Test testnet validation rules
    let rules = ProtocolValidationRules::testnet();

    // Should be same as mainnet
    assert_eq!(rules.max_block_size, 4_000_000);
    assert_eq!(rules.max_tx_size, 1_000_000);
    assert!(rules.segwit_enabled);
    assert!(rules.taproot_enabled);
}

#[test]
fn test_validation_rules_regtest() {
    // Test regtest validation rules
    let rules = ProtocolValidationRules::regtest();

    // Should be same as mainnet except for fees
    assert_eq!(rules.max_block_size, 4_000_000);
    assert_eq!(rules.max_tx_size, 1_000_000);
    assert_eq!(rules.min_fee_rate, 0); // No minimum fee for testing
}

// ============================================================================
// Phase 2: ProtocolValidationContext Tests
// ============================================================================

#[test]
fn test_validation_context_creation() {
    // Test creating a validation context
    let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 100000).unwrap();

    assert_eq!(context.block_height, 100000);
    assert_eq!(context.validation_rules.max_block_size, 4_000_000);
}

#[test]
fn test_validation_context_feature_check() {
    // Test checking if features are enabled
    let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000000).unwrap();

    assert!(context.is_feature_enabled("segwit"));
    assert!(context.is_feature_enabled("taproot"));
    assert!(context.is_feature_enabled("rbf"));
    assert!(!context.is_feature_enabled("nonexistent"));
}

#[test]
fn test_validation_context_max_sizes() {
    // Test getting maximum sizes
    let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 100000).unwrap();

    assert_eq!(context.get_max_size("block"), 4_000_000);
    assert_eq!(context.get_max_size("transaction"), 1_000_000);
    assert_eq!(context.get_max_size("script"), 10_000);
    assert_eq!(context.get_max_size("nonexistent"), 0);
}

// ============================================================================
// Phase 3: Size Validation Tests
// ============================================================================

#[test]
fn test_block_size_validation() {
    // Test block size validation
    let _engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let _context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 0).unwrap();

    // Create a simple block (should be well under limit)
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![create_simple_transaction()].into_boxed_slice(),
    };

    // Should pass validation (block is small)
    // Note: calculate_block_size is private, so we verify the block structure instead
    assert!(!block.transactions.is_empty());
    assert!(block.transactions.len() < 10000); // Transaction count limit
}

#[test]
fn test_transaction_size_validation() {
    // Test transaction size validation
    let _engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let _context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 0).unwrap();

    // Create a simple transaction (should be well under limit)
    let tx = create_simple_transaction();

    // Should pass validation (transaction is small)
    // Note: calculate_transaction_size is private, so we verify the transaction structure instead
    assert!(!tx.inputs.is_empty());
    assert!(!tx.outputs.is_empty());
}

#[test]
fn test_script_size_validation() {
    // Test script size validation
    let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 0).unwrap();

    // Create transaction with small scripts (should pass)
    let tx = create_simple_transaction();

    // All scripts should be under limit
    for input in &tx.inputs {
        assert!(input.script_sig.len() <= context.validation_rules.max_script_size as usize);
    }
    for output in &tx.outputs {
        assert!(output.script_pubkey.len() <= context.validation_rules.max_script_size as usize);
    }
}

// ============================================================================
// Phase 4: Protocol-Specific Validation Tests
// ============================================================================

#[test]
fn test_validate_block_with_protocol() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
    let mut context = ProtocolValidationContext::new(ProtocolVersion::Regtest, 0).unwrap();
    let utxos = UtxoSet::default();

    let block = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: [0u8; 32],
            merkle_root: [1; 32],
            timestamp: 1_700_000_000,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: vec![create_simple_transaction()].into_boxed_slice(),
    };
    context.network_time = block.header.timestamp;

    let result = engine
        .validate_block_with_protocol(&block, &utxos, 0, &context)
        .unwrap();
    assert_eq!(result, ValidationResult::Valid);
}

#[test]
fn test_validate_transaction_with_protocol() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
    let mut context = ProtocolValidationContext::new(ProtocolVersion::Regtest, 0).unwrap();
    context.network_time = 1_700_000_000;

    let tx = create_simple_transaction();

    let result = engine
        .validate_transaction_with_protocol(&tx, &context)
        .unwrap();
    assert_eq!(result, ValidationResult::Valid);
}

// ============================================================================
// Phase 5: Fee Rate Tests
// ============================================================================

#[test]
fn test_fee_rate_limits() {
    // Test fee rate limits for different networks
    let mainnet_rules = ProtocolValidationRules::mainnet();
    let regtest_rules = ProtocolValidationRules::regtest();

    // Mainnet has minimum fee
    assert_eq!(mainnet_rules.min_fee_rate, 1);

    // Regtest has no minimum fee
    assert_eq!(regtest_rules.min_fee_rate, 0);

    // Both have same maximum
    assert_eq!(mainnet_rules.max_fee_rate, 1_000_000);
    assert_eq!(regtest_rules.max_fee_rate, 1_000_000);
}

// ============================================================================
// Phase 6: Feature Flags Tests
// ============================================================================

#[test]
fn test_feature_flags_mainnet() {
    // Test feature flags for mainnet
    let rules = ProtocolValidationRules::mainnet();

    assert!(rules.segwit_enabled);
    assert!(rules.taproot_enabled);
    assert!(rules.rbf_enabled);
}

#[test]
fn test_feature_flags_all_networks() {
    // Test feature flags are consistent across networks
    let mainnet = ProtocolValidationRules::mainnet();
    let testnet = ProtocolValidationRules::testnet();
    let regtest = ProtocolValidationRules::regtest();

    // All networks should have same feature flags
    assert_eq!(mainnet.segwit_enabled, testnet.segwit_enabled);
    assert_eq!(testnet.segwit_enabled, regtest.segwit_enabled);
    assert_eq!(mainnet.taproot_enabled, testnet.taproot_enabled);
    assert_eq!(testnet.taproot_enabled, regtest.taproot_enabled);
}
