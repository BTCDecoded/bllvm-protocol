//! Protocol validation interface
//!
//! This module provides protocol-specific validation that extends
//! the pure mathematical consensus rules with network-specific
//! and protocol-specific validation logic.

use crate::error::ProtocolError;
use crate::features::FeatureRegistry;
use crate::{BitcoinProtocolEngine, NetworkParameters, ProtocolVersion};
use crate::{Block, Transaction, ValidationResult};
use blvm_consensus::types::UtxoSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Protocol-specific Result type
type Result<T> = std::result::Result<T, ProtocolError>;

/// Protocol-specific validation rules
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolValidationRules {
    /// Maximum block size for this protocol
    pub max_block_size: u32,
    /// Maximum transaction size for this protocol
    pub max_tx_size: u32,
    /// Maximum script size for this protocol
    pub max_script_size: u32,
    /// Whether SegWit is enabled
    pub segwit_enabled: bool,
    /// Whether Taproot is enabled
    pub taproot_enabled: bool,
    /// Whether RBF (Replace-By-Fee) is enabled
    pub rbf_enabled: bool,
    /// Minimum transaction fee rate
    pub min_fee_rate: u64,
    /// Maximum transaction fee rate
    pub max_fee_rate: u64,
}

impl ProtocolValidationRules {
    /// Get validation rules for a specific protocol version
    pub fn for_protocol(version: ProtocolVersion) -> Self {
        match version {
            ProtocolVersion::BitcoinV1 => Self::mainnet(),
            ProtocolVersion::Testnet3 => Self::testnet(),
            ProtocolVersion::Regtest => Self::regtest(),
        }
    }

    /// Mainnet validation rules (strict production rules)
    pub fn mainnet() -> Self {
        Self {
            max_block_size: 4_000_000, // 4MB block size limit
            max_tx_size: 1_000_000,    // 1MB transaction size limit
            max_script_size: 10_000,   // 10KB script size limit
            segwit_enabled: true,
            taproot_enabled: true,
            rbf_enabled: true,
            min_fee_rate: 1,         // 1 sat/vB minimum
            max_fee_rate: 1_000_000, // 1M sat/vB maximum
        }
    }

    /// Testnet validation rules (same as mainnet but with testnet parameters)
    pub fn testnet() -> Self {
        Self {
            max_block_size: 4_000_000,
            max_tx_size: 1_000_000,
            max_script_size: 10_000,
            segwit_enabled: true,
            taproot_enabled: true,
            rbf_enabled: true,
            min_fee_rate: 1,
            max_fee_rate: 1_000_000,
        }
    }

    /// Regtest validation rules (relaxed for testing)
    pub fn regtest() -> Self {
        Self {
            max_block_size: 4_000_000,
            max_tx_size: 1_000_000,
            max_script_size: 10_000,
            segwit_enabled: true,
            taproot_enabled: true,
            rbf_enabled: true,
            min_fee_rate: 0, // No minimum fee for testing
            max_fee_rate: 1_000_000,
        }
    }
}

/// Protocol-specific validation context
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolValidationContext {
    /// Current block height
    pub block_height: u64,
    /// Current network parameters
    pub network_params: NetworkParameters,
    /// Protocol validation rules
    pub validation_rules: ProtocolValidationRules,
    /// Feature activation registry for this protocol version.
    ///
    /// Used by `is_feature_enabled` to derive activation status from
    /// `block_height` / `network_time` rather than static booleans.
    pub feature_registry: FeatureRegistry,
    /// Median time-past used for time-based validation (BIP113)
    ///
    /// This is populated by the node using recent headers and is threaded down
    /// to consensus for timestamp validation.
    pub median_time_past: u64,
    /// Current adjusted network time (Unix timestamp)
    ///
    /// This is populated by the node from its time source and used by consensus
    /// to enforce future timestamp limits.
    pub network_time: u64,
    /// Additional context data
    pub context_data: HashMap<String, String>,
}

impl ProtocolValidationContext {
    /// Create validation context for a protocol version
    pub fn new(version: ProtocolVersion, block_height: u64) -> Result<Self> {
        let network_params = NetworkParameters::for_version(version)?;
        let validation_rules = ProtocolValidationRules::for_protocol(version);

        let feature_registry = FeatureRegistry::for_protocol(version);
        Ok(Self {
            block_height,
            network_params,
            validation_rules,
            feature_registry,
            // Default to zero; callers that care about time must set these explicitly.
            median_time_past: 0,
            network_time: 0,
            context_data: HashMap::new(),
        })
    }

    /// Check if a feature is enabled at the current block height and network time.
    ///
    /// Queries the `FeatureRegistry` so activation reflects the actual deployment
    /// height/timestamp rather than static booleans that ignore `block_height`.
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        self.feature_registry
            .is_feature_active(feature, self.block_height, self.network_time)
    }

    /// Get maximum allowed size for a component
    pub fn get_max_size(&self, component: &str) -> u32 {
        match component {
            "block" => self.validation_rules.max_block_size,
            "transaction" => self.validation_rules.max_tx_size,
            "script" => self.validation_rules.max_script_size,
            _ => 0,
        }
    }
}

impl BitcoinProtocolEngine {
    /// Validate a block with protocol-specific rules
    pub fn validate_block_with_protocol(
        &self,
        block: &Block,
        _utxos: &UtxoSet,
        _height: u64,
        context: &ProtocolValidationContext,
    ) -> Result<ValidationResult> {
        // First, apply protocol-specific validation
        self.apply_protocol_validation(block, context)?;

        Ok(ValidationResult::Valid)
    }

    /// Validate a transaction with protocol-specific rules
    pub fn validate_transaction_with_protocol(
        &self,
        tx: &Transaction,
        context: &ProtocolValidationContext,
    ) -> Result<ValidationResult> {
        // First, run consensus validation
        let consensus_result = self.consensus.validate_transaction(tx)?;

        // Then, apply protocol-specific validation
        self.apply_transaction_protocol_validation(tx, context)?;

        Ok(consensus_result)
    }

    /// Apply protocol-specific validation rules
    fn apply_protocol_validation(
        &self,
        block: &Block,
        context: &ProtocolValidationContext,
    ) -> Result<()> {
        // Check block weight limits (BIP141).
        // `max_block_size` is in weight units (4,000,000 WU = 4MB weight).
        //
        // LIMITATION (P1-H/P1-I): the `Block` type carries no witness data, so we can only
        // compute base weight here (stripped_size * 4). BIP141 actual weight is:
        //   weight = stripped_size * 4 + witness_size
        // A block with stripped_size < 1 MB can still exceed 4 MWU if its witnesses are large.
        // This check is therefore a LOWER BOUND — it rejects blocks whose base weight alone
        // exceeds the limit but cannot catch witness-heavy blocks that slip under the base check.
        // Full witness-aware weight validation requires witnesses to flow into this path (see P1-I).
        let stripped_size = self.calculate_block_size(block);
        let base_weight = stripped_size.saturating_mul(4);
        if base_weight > context.validation_rules.max_block_size {
            return Err(ProtocolError::Validation(
                format!(
                    "Block base weight exceeds maximum: {} WU (max {} WU); stripped_size={}",
                    base_weight, context.validation_rules.max_block_size, stripped_size
                )
                .into(),
            ));
        }

        // Check transaction count limits
        if block.transactions.len() > 10000 {
            // Reasonable limit
            return Err(ProtocolError::Validation(
                "Too many transactions in block (max 10000)".into(),
            ));
        }

        // Validate each transaction with protocol rules
        for tx in &block.transactions {
            self.apply_transaction_protocol_validation(tx, context)?;
        }

        Ok(())
    }

    /// Apply protocol-specific transaction validation
    fn apply_transaction_protocol_validation(
        &self,
        tx: &Transaction,
        context: &ProtocolValidationContext,
    ) -> Result<()> {
        // Check transaction size limits
        let tx_size = self.calculate_transaction_size(tx);
        if tx_size > context.validation_rules.max_tx_size {
            return Err(ProtocolError::Validation(
                format!(
                    "Transaction size exceeds maximum: {} bytes (max {} bytes)",
                    tx_size, context.validation_rules.max_tx_size
                )
                .into(),
            ));
        }

        // Check script size limits
        for input in &tx.inputs {
            if input.script_sig.len() > context.validation_rules.max_script_size as usize {
                return Err(ProtocolError::Validation(
                    format!(
                        "Script size exceeds maximum: {} bytes (max {} bytes)",
                        input.script_sig.len(),
                        context.validation_rules.max_script_size
                    )
                    .into(),
                ));
            }
        }

        for output in &tx.outputs {
            if output.script_pubkey.len() > context.validation_rules.max_script_size as usize {
                return Err(ProtocolError::Validation(
                    format!(
                        "Script size exceeds maximum: {} bytes (max {} bytes)",
                        output.script_pubkey.len(),
                        context.validation_rules.max_script_size
                    )
                    .into(),
                ));
            }
        }

        Ok(())
    }

    /// Calculate block size in bytes
    fn calculate_block_size(&self, block: &Block) -> u32 {
        // Simplified size calculation
        // In reality, this would include proper serialization
        let header_size = 80; // Block header is always 80 bytes
        let tx_count_size = 4; // Varint for transaction count
        let tx_sizes: u32 = block
            .transactions
            .iter()
            .map(|tx| self.calculate_transaction_size(tx))
            .sum();

        header_size + tx_count_size + tx_sizes
    }

    /// Calculate transaction size in bytes
    fn calculate_transaction_size(&self, tx: &Transaction) -> u32 {
        // Use canonical serialization-based size from consensus layer (TX_NO_WITNESS size).
        //
        // This keeps protocol-level size limits aligned with the exact serialization
        // used for consensus checks and transaction size tests.
        blvm_consensus::transaction::calculate_transaction_size(tx) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blvm_consensus::types::{OutPoint, TransactionInput, TransactionOutput};
    use blvm_consensus::{Block, BlockHeader, Transaction};

    #[test]
    fn test_validation_rules() {
        let mainnet_rules = ProtocolValidationRules::mainnet();
        assert_eq!(mainnet_rules.max_block_size, 4_000_000);
        assert!(mainnet_rules.segwit_enabled);
        assert!(mainnet_rules.taproot_enabled);

        let regtest_rules = ProtocolValidationRules::regtest();
        assert_eq!(regtest_rules.max_block_size, 4_000_000);
        assert!(regtest_rules.segwit_enabled);
        assert_eq!(regtest_rules.min_fee_rate, 0); // No minimum fee for testing
    }

    #[test]
    fn test_validation_rules_all_protocols() {
        let mainnet_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::BitcoinV1);
        let testnet_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::Testnet3);
        let regtest_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::Regtest);

        // Mainnet and testnet should have same rules
        assert_eq!(mainnet_rules.max_block_size, testnet_rules.max_block_size);
        assert_eq!(mainnet_rules.max_tx_size, testnet_rules.max_tx_size);
        assert_eq!(mainnet_rules.max_script_size, testnet_rules.max_script_size);
        assert_eq!(mainnet_rules.segwit_enabled, testnet_rules.segwit_enabled);
        assert_eq!(mainnet_rules.taproot_enabled, testnet_rules.taproot_enabled);
        assert_eq!(mainnet_rules.rbf_enabled, testnet_rules.rbf_enabled);
        assert_eq!(mainnet_rules.min_fee_rate, testnet_rules.min_fee_rate);
        assert_eq!(mainnet_rules.max_fee_rate, testnet_rules.max_fee_rate);

        // Regtest should have relaxed fee rules
        assert_eq!(regtest_rules.min_fee_rate, 0);
        assert_eq!(regtest_rules.max_fee_rate, mainnet_rules.max_fee_rate);
    }

    #[test]
    fn test_validation_rules_serialization() {
        let mainnet_rules = ProtocolValidationRules::mainnet();
        let json = serde_json::to_string(&mainnet_rules).unwrap();
        let deserialized: ProtocolValidationRules = serde_json::from_str(&json).unwrap();

        assert_eq!(mainnet_rules.max_block_size, deserialized.max_block_size);
        assert_eq!(mainnet_rules.max_tx_size, deserialized.max_tx_size);
        assert_eq!(mainnet_rules.max_script_size, deserialized.max_script_size);
        assert_eq!(mainnet_rules.segwit_enabled, deserialized.segwit_enabled);
        assert_eq!(mainnet_rules.taproot_enabled, deserialized.taproot_enabled);
        assert_eq!(mainnet_rules.rbf_enabled, deserialized.rbf_enabled);
        assert_eq!(mainnet_rules.min_fee_rate, deserialized.min_fee_rate);
        assert_eq!(mainnet_rules.max_fee_rate, deserialized.max_fee_rate);
    }

    #[test]
    fn test_validation_rules_equality() {
        let mainnet1 = ProtocolValidationRules::mainnet();
        let mainnet2 = ProtocolValidationRules::mainnet();
        let testnet = ProtocolValidationRules::testnet();

        assert_eq!(mainnet1, mainnet2);
        assert_eq!(mainnet1, testnet); // Mainnet and testnet should be identical
    }

    #[test]
    fn test_validation_context() {
        // Use a height past both segwit (481824) and taproot (709632) activation.
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 800_000).unwrap();
        assert_eq!(context.block_height, 800_000);
        assert!(context.is_feature_enabled("segwit"));
        assert!(!context.is_feature_enabled("nonexistent"));
        assert_eq!(context.get_max_size("block"), 4_000_000);
    }

    #[test]
    fn test_validation_context_all_protocols() {
        // Per-network heights past segwit+taproot activation:
        //   mainnet: taproot at 709_632   → use 800_000
        //   testnet3: taproot at 2_016_000 → use 2_100_000
        //   regtest: all features AlwaysActive → any height works
        let mainnet_context =
            ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 800_000).unwrap();
        let testnet_context =
            ProtocolValidationContext::new(ProtocolVersion::Testnet3, 2_100_000).unwrap();
        let regtest_context = ProtocolValidationContext::new(ProtocolVersion::Regtest, 1).unwrap();

        assert_eq!(mainnet_context.block_height, 800_000);
        assert_eq!(testnet_context.block_height, 2_100_000);
        assert_eq!(regtest_context.block_height, 1);

        // All should support same features
        assert!(mainnet_context.is_feature_enabled("segwit"));
        assert!(testnet_context.is_feature_enabled("segwit"));
        assert!(regtest_context.is_feature_enabled("segwit"));

        assert!(mainnet_context.is_feature_enabled("taproot"));
        assert!(testnet_context.is_feature_enabled("taproot"));
        assert!(regtest_context.is_feature_enabled("taproot"));

        assert!(mainnet_context.is_feature_enabled("rbf"));
        assert!(testnet_context.is_feature_enabled("rbf"));
        assert!(regtest_context.is_feature_enabled("rbf"));
    }

    #[test]
    fn test_validation_context_feature_queries() {
        // Height past both segwit (481824) and taproot (709632) so all features are active.
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 800_000).unwrap();

        // Test all supported features
        assert!(context.is_feature_enabled("segwit"));
        assert!(context.is_feature_enabled("taproot"));
        assert!(context.is_feature_enabled("rbf"));

        // Test unsupported features
        assert!(!context.is_feature_enabled("nonexistent"));
        assert!(!context.is_feature_enabled(""));
        assert!(!context.is_feature_enabled("fast_mining"));
    }

    #[test]
    fn test_validation_context_size_queries() {
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        assert_eq!(context.get_max_size("block"), 4_000_000);
        assert_eq!(context.get_max_size("transaction"), 1_000_000);
        assert_eq!(context.get_max_size("script"), 10_000);

        // Test unknown component
        assert_eq!(context.get_max_size("unknown"), 0);
    }

    #[test]
    fn test_validation_context_serialization() {
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();
        let json = serde_json::to_string(&context).unwrap();
        let deserialized: ProtocolValidationContext = serde_json::from_str(&json).unwrap();

        assert_eq!(context.block_height, deserialized.block_height);
        assert_eq!(
            context.network_params.network_name,
            deserialized.network_params.network_name
        );
        assert_eq!(
            context.validation_rules.max_block_size,
            deserialized.validation_rules.max_block_size
        );
    }

    #[test]
    fn test_validation_context_equality() {
        let context1 = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();
        let context2 = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();
        let context3 = ProtocolValidationContext::new(ProtocolVersion::Testnet3, 1000).unwrap();

        assert_eq!(context1, context2);
        assert_ne!(context1, context3); // Different network parameters
    }

    #[test]
    fn test_block_size_validation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Create a block that's within size limits with a valid coinbase transaction
        let coinbase_tx = Transaction {
            version: 1,
            inputs: blvm_consensus::tx_inputs![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![0x01, 0x00], // Height 0
                sequence: 0xffffffff,
            }],
            outputs: blvm_consensus::tx_outputs![TransactionOutput {
                value: 50_0000_0000,
                script_pubkey: vec![blvm_consensus::opcodes::OP_1],
            }],
            lock_time: 0,
        };

        // Calculate proper merkle root
        let merkle_root = blvm_consensus::mining::calculate_merkle_root(&[coinbase_tx.clone()])
            .expect("Should calculate merkle root");

        let small_block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root,
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![coinbase_tx].into_boxed_slice(),
        };

        // This should pass validation
        let result =
            engine.validate_block_with_protocol(&small_block, &UtxoSet::default(), 1000, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_size_validation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Create a small transaction
        let small_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0,
                },
                script_sig: vec![blvm_consensus::opcodes::PUSH_65_BYTES, 0x04],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 50_0000_0000,
                script_pubkey: vec![
                    blvm_consensus::opcodes::OP_DUP,
                    blvm_consensus::opcodes::OP_HASH160,
                    blvm_consensus::opcodes::PUSH_20_BYTES,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    blvm_consensus::opcodes::OP_EQUALVERIFY,
                    blvm_consensus::opcodes::OP_CHECKSIG,
                ],
            }]
            .into(),
            lock_time: 0,
        };

        // This should pass validation
        let result = engine.validate_transaction_with_protocol(&small_tx, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_script_size_validation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Create a transaction with small scripts
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0,
                },
                script_sig: vec![blvm_consensus::opcodes::PUSH_65_BYTES, 0x04],
                sequence: 0xffffffff,
            }]
            .into(),
            outputs: vec![TransactionOutput {
                value: 50_0000_0000,
                script_pubkey: vec![
                    blvm_consensus::opcodes::OP_DUP,
                    blvm_consensus::opcodes::OP_HASH160,
                    blvm_consensus::opcodes::PUSH_20_BYTES,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    blvm_consensus::opcodes::OP_EQUALVERIFY,
                    blvm_consensus::opcodes::OP_CHECKSIG,
                ],
            }]
            .into(),
            lock_time: 0,
        };

        // This should pass validation
        let result = engine.validate_transaction_with_protocol(&tx, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_context_data() {
        let mut context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Add some context data
        context
            .context_data
            .insert("test_key".to_string(), "test_value".to_string());

        assert_eq!(
            context.context_data.get("test_key"),
            Some(&"test_value".to_string())
        );
        assert_eq!(context.context_data.get("nonexistent"), None);
    }

    #[test]
    fn test_validation_rules_boundary_values() {
        let rules = ProtocolValidationRules::mainnet();

        // Test boundary values
        assert!(rules.max_block_size > 0);
        assert!(rules.max_tx_size > 0);
        assert!(rules.max_script_size > 0);
        assert!(rules.max_fee_rate > rules.min_fee_rate);

        // Test that limits are reasonable
        assert!(rules.max_block_size <= 10_000_000); // Not unreasonably large
        assert!(rules.max_tx_size <= 5_000_000); // Not unreasonably large
        assert!(rules.max_script_size <= 50_000); // Not unreasonably large
    }
}
