//! Bitcoin Protocol Engine
//!
//! This crate provides a Bitcoin protocol abstraction layer that enables:
//! - Multiple Bitcoin variants (mainnet, testnet, regtest, educational)
//! - Protocol evolution support (Bitcoin V1, V2, etc.)
//! - Economic model abstraction (PoW, future variants)
//! - Educational and research-friendly interfaces
//!
//! This is Tier 3 of the 5-tier BTCDecoded architecture:
//!
//! 1. Orange Paper (mathematical foundation)
//! 2. blvm-consensus (pure math implementation)
//! 3. blvm-protocol (Bitcoin abstraction) ← THIS CRATE
//! 4. blvm-node (full Bitcoin node)
//! 5. blvm-sdk (ergonomic API)

use serde::{Deserialize, Serialize};

// Re-export commonly used types for convenience
// This allows upper layers (like blvm-node) to depend only on blvm-protocol
pub use blvm_consensus::config::NetworkMessageLimits;
pub use blvm_consensus::error::{ConsensusError, Result as ConsensusResult};
pub use blvm_consensus::types::{
    Block, BlockHeader, ByteString, Hash, Integer, Natural, OutPoint, Transaction,
    TransactionInput, TransactionOutput, UtxoSet, ValidationResult, Witness, UTXO,
};
pub use blvm_consensus::ConsensusProof;

#[cfg(all(feature = "production", feature = "benchmarking"))]
pub use blvm_consensus::config::{reset_assume_valid_height, set_assume_valid_height};
/// Buried deployment heights (Core chainparams) for RPC / tooling without a direct `blvm-consensus` dep.
pub use blvm_consensus::{
    BIP112_CSV_ACTIVATION_MAINNET, BIP112_CSV_ACTIVATION_REGTEST, BIP112_CSV_ACTIVATION_TESTNET,
    GENESIS_BLOCK_HASH_INTERNAL, SEGWIT_ACTIVATION_MAINNET, SEGWIT_ACTIVATION_TESTNET,
    TAPROOT_ACTIVATION_MAINNET, TAPROOT_ACTIVATION_TESTNET,
};

// Re-export smallvec for macro use when production feature is enabled
#[cfg(feature = "production")]
pub use smallvec;
// Re-export lru and rayon for production caches and parallel validation
#[cfg(feature = "production")]
pub use lru;
#[cfg(feature = "production")]
pub use rayon;

/// Forwards to `blvm_consensus::profile_log!` so upper layers avoid naming `blvm-consensus` directly.
/// When the `profile` feature is off on consensus, the inner macro expands to a no-op.
#[macro_export]
macro_rules! profile_log {
    ($($arg:tt)*) => {
        ::blvm_consensus::profile_log!($($arg)*)
    };
}

// Protocol-specific Result type
pub use error::{ProtocolError, Result};

// Re-export commonly used modules
pub mod mempool {
    pub use blvm_consensus::mempool::*;
}
pub mod segwit {
    pub use blvm_consensus::segwit::*;
}
pub mod block {
    pub use blvm_consensus::block::*;

    use crate::types::{BlockHeader, Network};

    /// Forwards to [`BlockValidationContext::from_connect_block_ibd_args`] with no BIP54 activation
    /// override and no boundary timestamps. Does not invent time or headers; pass the same values
    /// you would pass to the underlying constructor.
    #[inline]
    pub fn block_validation_context_for_connect_ibd<H: AsRef<BlockHeader>>(
        recent_headers: Option<&[H]>,
        network_time: u64,
        network: Network,
    ) -> BlockValidationContext {
        BlockValidationContext::from_connect_block_ibd_args(
            recent_headers,
            network_time,
            network,
            None,
            None,
        )
    }
}
pub mod mining {
    pub use blvm_consensus::mining::*;
}
pub mod pow {
    pub use blvm_consensus::pow::*;
}

pub mod witness {
    pub use blvm_consensus::witness::*;
}

pub mod crypto {
    pub use blvm_consensus::crypto::*;
}

pub mod transaction {
    pub use blvm_consensus::transaction::*;
}

/// Script interpreter (consensus). Exposed so benches/node avoid a direct `blvm-consensus` dep where possible.
pub mod script {
    pub use blvm_consensus::script::*;
}

/// Transaction sighash / txid helpers from consensus.
pub mod transaction_hash {
    pub use blvm_consensus::transaction_hash::*;
}

/// Production-only batch hashing, preallocation, and related optimization helpers from consensus.
#[cfg(feature = "production")]
pub mod optimizations {
    pub use blvm_consensus::optimizations::*;
}

/// Consensus constants (`blvm-primitives` / Orange Paper symbols) — same as `blvm_consensus::constants`.
pub mod constants {
    pub use blvm_consensus::constants::*;
}

pub mod bip113 {
    pub use blvm_consensus::bip113::*;
}

pub mod bip_validation {
    pub use blvm_consensus::bip_validation::*;
}

pub mod utxo_overlay {
    pub use blvm_consensus::utxo_overlay::*;
}

pub mod version_bits {
    pub use blvm_consensus::version_bits::*;
}

pub mod activation {
    pub use blvm_consensus::activation::*;
}

/// Consensus runtime configuration from `blvm-consensus` (distinct from this crate's [`config`] module).
pub mod consensus_config {
    pub use blvm_consensus::config::*;
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    pub use blvm_consensus::test_utils::*;
}

/// Script opcodes (re-exported from consensus / primitives) for callers that should not name `blvm-consensus` directly.
pub use blvm_consensus::opcodes;

pub mod sigop {
    pub use blvm_consensus::sigop::*;
}

#[cfg(feature = "utxo-commitments")]
pub mod utxo_commitments;

// Spam filter is always available (not behind utxo-commitments feature)
pub mod spam_filter;
pub mod serialization {
    pub use blvm_consensus::serialization::*;
}
pub mod commons;
pub mod network;
/// Framed TCP P2P (mainnet magic, command allowlist supplied by the node). Not BIP324 v2 transport.
pub mod node_tcp;

pub use node_tcp::{ProtocolMessage, TcpFramedParser};
pub mod p2p_commands;
pub mod p2p_frame;
pub mod p2p_framing;
pub mod service_flags;
pub mod varint;

// BIP324: v2 encrypted transport
#[cfg(all(
    feature = "bip324",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod v2_transport;

// Re-export commonly used types for convenience
pub use commons::{
    BanListMessage,
    // Filtered block types
    FilterPreferences,
    // Commons-only types kept in blvm-protocol for bridge layers
    FilteredBlockMessage,
    GetBanListMessage,
    GetFilteredBlockMessage,
    // UTXO proof types
    GetUTXOProofMessage,
    GetUTXOSetMessage,
    // UTXO commitment protocol types
    UTXOCommitment,
    UTXOProofMessage,
    UTXOSetMessage,
};
pub use config::{
    ProtocolConfig, ProtocolFeaturesConfig, ProtocolValidationConfig, ServiceFlagsConfig,
};
pub use network::{BlockMessage, CompactBlockMessage, TxMessage};
pub use service_flags::{commons as service_flags_commons, standard as service_flags_standard};
// Wire format module - Bitcoin P2P wire protocol serialization
pub mod wire;

#[cfg(test)]
mod bip155_serialization_tests;
pub mod types {
    pub use blvm_consensus::types::*;
}
// Re-export macros from blvm-consensus for convenience
#[cfg(feature = "production")]
pub use blvm_consensus::tx_inputs;
#[cfg(not(feature = "production"))]
pub use blvm_consensus::tx_inputs;
#[cfg(feature = "production")]
pub use blvm_consensus::tx_outputs;
#[cfg(not(feature = "production"))]
pub use blvm_consensus::tx_outputs;
pub mod error;

// Re-export feature and economic modules for convenience
pub use economic::EconomicParameters;
pub use features::{ActivationMethod, FeatureActivation, FeatureContext, FeatureRegistry};

pub mod config;
pub mod economic;
pub mod features;
pub mod genesis;
pub mod network_params;
pub mod validation;
pub mod variants;

// Protocol-level BIP implementations
pub mod address; // BIP173/350/351: Bech32/Bech32m address encoding
#[cfg(feature = "ctv")]
pub mod bip119 {
    pub use blvm_consensus::bip119::*;
}
pub mod bip152; // BIP152: Compact block relay (wire types)
pub mod bip157; // BIP157: Client-side block filtering network protocol
pub mod bip158; // BIP158: Compact block filters
pub mod payment; // BIP70: Payment protocol (P2P variant)
pub mod time;

/// Bitcoin Protocol Engine
///
/// Provides protocol abstraction for different Bitcoin variants and evolution.
/// Acts as a bridge between blvm-consensus (pure math) and blvm-node (implementation).
pub struct BitcoinProtocolEngine {
    consensus: ConsensusProof,
    protocol_version: ProtocolVersion,
    network_params: NetworkParameters,
    config: ProtocolConfig,
}

/// Bitcoin protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolVersion {
    /// Current Bitcoin mainnet protocol
    BitcoinV1,
    /// Bitcoin testnet protocol
    Testnet3,
    /// Regression test network protocol
    Regtest,
}

/// Network parameters for different Bitcoin variants
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkParameters {
    /// Network magic bytes for P2P protocol
    pub magic_bytes: [u8; 4],
    /// Default P2P port
    pub default_port: u16,
    /// Genesis block for this network
    pub genesis_block: Block,
    /// Maximum proof-of-work target
    pub max_target: u32,
    /// Block subsidy halving interval
    pub halving_interval: u64,
    /// Network name for identification
    pub network_name: String,
    /// Whether this is a test network
    pub is_testnet: bool,
}

impl BitcoinProtocolEngine {
    /// Create a new protocol engine for the specified variant with default configuration
    pub fn new(version: ProtocolVersion) -> Result<Self> {
        Self::with_config(version, ProtocolConfig::default())
    }

    /// Create a new protocol engine with custom configuration
    pub fn with_config(version: ProtocolVersion, config: ProtocolConfig) -> Result<Self> {
        let consensus = ConsensusProof::new();
        let network_params = NetworkParameters::for_version(version)?;

        Ok(BitcoinProtocolEngine {
            consensus,
            protocol_version: version,
            network_params,
            config,
        })
    }

    /// Get the protocol configuration
    pub fn get_config(&self) -> &ProtocolConfig {
        &self.config
    }

    /// Get mutable reference to protocol configuration
    pub fn get_config_mut(&mut self) -> &mut ProtocolConfig {
        &mut self.config
    }

    /// Get the current protocol version
    pub fn get_protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Get network parameters for this protocol
    pub fn get_network_params(&self) -> &NetworkParameters {
        &self.network_params
    }

    /// Validate a block using this protocol's rules
    pub fn validate_block(
        &self,
        block: &Block,
        utxos: &UtxoSet,
        height: u64,
    ) -> Result<ValidationResult> {
        let network = match self.protocol_version {
            ProtocolVersion::BitcoinV1 => types::Network::Mainnet,
            ProtocolVersion::Testnet3 => types::Network::Testnet,
            ProtocolVersion::Regtest => types::Network::Regtest,
        };
        let witnesses: Vec<Vec<blvm_consensus::segwit::Witness>> = block
            .transactions
            .iter()
            .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
            .collect();
        let (result, _) = self
            .consensus
            .validate_block_with_time_context(
                block,
                &witnesses,
                utxos.clone(),
                height,
                None,
                network,
            )
            .map_err(ProtocolError::from)?;
        Ok(result)
    }

    /// Validate a transaction using this protocol's rules
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<ValidationResult> {
        self.consensus
            .validate_transaction(tx)
            .map_err(ProtocolError::from)
    }

    /// Validate block with protocol rules and update UTXO set
    ///
    /// This method combines protocol validation (size limits, feature flags)
    /// with consensus validation and UTXO set updates. This is the recommended
    /// method for node implementations that need both validation and state updates.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to validate and connect
    /// * `witnesses` - Witness data for each transaction in the block
    /// * `utxos` - Current UTXO set (will be cloned, not mutated)
    /// * `height` - Current block height
    /// * `recent_headers` - Optional recent block headers for median time-past calculation (BIP113)
    /// * `context` - Protocol validation context
    ///
    /// # Returns
    ///
    /// Returns `(ValidationResult, UtxoSet)` where:
    /// - `ValidationResult` indicates if the block is valid
    /// - `UtxoSet` is the updated UTXO set after applying the block's transactions
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};
    /// use blvm_protocol::validation::ProtocolValidationContext;
    /// use blvm_protocol::{Block, UtxoSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;
    /// let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 0)?;
    /// // Create a test block
    /// let block = Block {
    ///     header: blvm_consensus::BlockHeader {
    ///         version: 1,
    ///         prev_block_hash: [0u8; 32],
    ///         merkle_root: [0u8; 32],
    ///         timestamp: 1231006505,
    ///         bits: 0x1d00ffff,
    ///         nonce: 0,
    ///     },
    ///     transactions: vec![].into_boxed_slice(),
    /// };
    /// let witnesses = vec![];
    /// let utxos = UtxoSet::default();
    ///
    /// let (result, new_utxo_set) = engine.validate_and_connect_block(
    ///     &block,
    ///     &witnesses,
    ///     &utxos,
    ///     0,
    ///     None,
    ///     &context,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate_and_connect_block(
        &self,
        block: &Block,
        witnesses: &[Vec<segwit::Witness>], // CRITICAL FIX: Changed from &[Witness] to &[Vec<Witness>]
        // witnesses is now Vec<Vec<Witness>> where each Vec<Witness> is for one transaction
        // and each Witness is for one input
        utxos: &UtxoSet,
        height: u64,
        recent_headers: Option<&[BlockHeader]>,
        context: &validation::ProtocolValidationContext,
    ) -> Result<(ValidationResult, UtxoSet)> {
        // First, protocol validation (size limits, feature flags)
        let protocol_result = self.validate_block_with_protocol(block, utxos, height, context)?;
        if !matches!(protocol_result, ValidationResult::Valid) {
            return Ok((protocol_result, utxos.clone()));
        }

        // Then, consensus validation with UTXO update
        // Convert protocol version to network type
        let network = match self.protocol_version {
            ProtocolVersion::BitcoinV1 => types::Network::Mainnet,
            ProtocolVersion::Testnet3 => types::Network::Testnet,
            ProtocolVersion::Regtest => types::Network::Regtest,
        };
        let network_time = crate::time::current_timestamp();
        let context = crate::block::block_validation_context_for_connect_ibd(
            recent_headers,
            network_time,
            network,
        );
        let (result, new_utxo_set, _undo_log) = blvm_consensus::block::connect_block(
            block,
            witnesses,
            utxos.clone(),
            height,
            &context,
        )?;

        Ok((result, new_utxo_set))
    }

    /// Check if this protocol supports a specific feature
    pub fn supports_feature(&self, feature: &str) -> bool {
        match self.protocol_version {
            ProtocolVersion::BitcoinV1 => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv")
            }
            ProtocolVersion::Testnet3 => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv")
            }
            ProtocolVersion::Regtest => {
                matches!(
                    feature,
                    "segwit" | "taproot" | "rbf" | "ctv" | "fast_mining"
                )
            }
        }
    }

    /// Check if a feature is active at a specific block height and timestamp
    pub fn is_feature_active(&self, feature: &str, height: u64, timestamp: u64) -> bool {
        let registry = features::FeatureRegistry::for_protocol(self.protocol_version);
        registry.is_feature_active(feature, height, timestamp)
    }

    /// Get economic parameters for this protocol
    pub fn get_economic_parameters(&self) -> economic::EconomicParameters {
        economic::EconomicParameters::for_protocol(self.protocol_version)
    }

    /// Get feature activation registry for this protocol
    pub fn get_feature_registry(&self) -> features::FeatureRegistry {
        features::FeatureRegistry::for_protocol(self.protocol_version)
    }

    /// Create a feature context for a specific block height and timestamp
    /// This consolidates all feature activation checks into a single context
    pub fn feature_context(&self, height: u64, timestamp: u64) -> features::FeatureContext {
        let registry = features::FeatureRegistry::for_protocol(self.protocol_version);
        registry.create_context(height, timestamp)
    }
}

impl NetworkParameters {
    /// Create network parameters for a specific protocol version
    pub fn for_version(version: ProtocolVersion) -> Result<Self> {
        match version {
            ProtocolVersion::BitcoinV1 => Self::mainnet(),
            ProtocolVersion::Testnet3 => Self::testnet(),
            ProtocolVersion::Regtest => Self::regtest(),
        }
    }

    /// Bitcoin mainnet parameters
    pub fn mainnet() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0xf9, 0xbe, 0xb4, 0xd9], // Bitcoin mainnet magic
            default_port: 8333,
            genesis_block: genesis::mainnet_genesis(),
            max_target: 0x1d00ffff,
            halving_interval: 210000,
            network_name: "mainnet".to_string(),
            is_testnet: false,
        })
    }

    /// Bitcoin testnet parameters
    pub fn testnet() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0x0b, 0x11, 0x09, 0x07], // Bitcoin testnet magic
            default_port: 18333,
            genesis_block: genesis::testnet_genesis(),
            max_target: 0x1d00ffff,
            halving_interval: 210000,
            network_name: "testnet".to_string(),
            is_testnet: true,
        })
    }

    /// Bitcoin regtest parameters
    pub fn regtest() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0xfa, 0xbf, 0xb5, 0xda], // Bitcoin regtest magic
            default_port: 18444,
            genesis_block: genesis::regtest_genesis(),
            max_target: 0x207fffff, // Easier difficulty for testing
            halving_interval: 150,  // Faster halving for testing
            network_name: "regtest".to_string(),
            is_testnet: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blvm_consensus::types::{BlockHeader, OutPoint, TransactionInput, TransactionOutput};

    #[test]
    fn test_blvm_protocol_creation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        assert_eq!(engine.get_protocol_version(), ProtocolVersion::BitcoinV1);
        assert_eq!(engine.get_network_params().network_name, "mainnet");
    }

    #[test]
    fn test_blvm_protocol_creation_all_variants() {
        // Test mainnet
        let mainnet = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        assert_eq!(mainnet.get_protocol_version(), ProtocolVersion::BitcoinV1);
        assert_eq!(mainnet.get_network_params().network_name, "mainnet");
        assert!(!mainnet.get_network_params().is_testnet);

        // Test testnet
        let testnet = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
        assert_eq!(testnet.get_protocol_version(), ProtocolVersion::Testnet3);
        assert_eq!(testnet.get_network_params().network_name, "testnet");
        assert!(testnet.get_network_params().is_testnet);

        // Test regtest
        let regtest = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
        assert_eq!(regtest.get_protocol_version(), ProtocolVersion::Regtest);
        assert_eq!(regtest.get_network_params().network_name, "regtest");
        assert!(regtest.get_network_params().is_testnet);
    }

    #[test]
    fn test_network_parameters() {
        let mainnet = NetworkParameters::mainnet().unwrap();
        assert_eq!(mainnet.magic_bytes, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(mainnet.default_port, 8333);
        assert!(!mainnet.is_testnet);

        let testnet = NetworkParameters::testnet().unwrap();
        assert_eq!(testnet.magic_bytes, [0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(testnet.default_port, 18333);
        assert!(testnet.is_testnet);

        let regtest = NetworkParameters::regtest().unwrap();
        assert_eq!(regtest.magic_bytes, [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(regtest.default_port, 18444);
        assert!(regtest.is_testnet);
    }

    #[test]
    fn test_network_parameters_consistency() {
        let mainnet = NetworkParameters::mainnet().unwrap();
        assert_eq!(mainnet.max_target, 0x1d00ffff);
        assert_eq!(mainnet.halving_interval, 210000);

        let testnet = NetworkParameters::testnet().unwrap();
        assert_eq!(testnet.max_target, 0x1d00ffff);
        assert_eq!(testnet.halving_interval, 210000);

        let regtest = NetworkParameters::regtest().unwrap();
        assert_eq!(regtest.max_target, 0x207fffff); // Easier difficulty
        assert_eq!(regtest.halving_interval, 150); // Faster halving
    }

    #[test]
    fn test_feature_support() {
        let mainnet = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        assert!(mainnet.supports_feature("segwit"));
        assert!(mainnet.supports_feature("taproot"));
        assert!(mainnet.supports_feature("rbf"));
        assert!(mainnet.supports_feature("ctv"));
        assert!(!mainnet.supports_feature("fast_mining"));
        assert!(!mainnet.supports_feature("nonexistent"));

        let testnet = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
        assert!(testnet.supports_feature("segwit"));
        assert!(testnet.supports_feature("taproot"));
        assert!(testnet.supports_feature("rbf"));
        assert!(testnet.supports_feature("ctv"));
        assert!(!testnet.supports_feature("fast_mining"));

        let regtest = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
        assert!(regtest.supports_feature("segwit"));
        assert!(regtest.supports_feature("taproot"));
        assert!(regtest.supports_feature("rbf"));
        assert!(regtest.supports_feature("ctv"));
        assert!(regtest.supports_feature("fast_mining"));
    }

    #[test]
    fn test_block_validation_empty_utxos() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let utxos = UtxoSet::default();

        // Create a simple block with just a coinbase transaction
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
                ], // P2PKH
            }],
            lock_time: 0,
        };

        // Calculate proper merkle root
        let merkle_root = blvm_consensus::mining::calculate_merkle_root(&[coinbase_tx.clone()])
            .expect("Should calculate merkle root");

        let block = Block {
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

        // This should pass validation for a genesis block
        let result = engine.validate_block(&block, &utxos, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_validation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();

        // Create a simple transaction
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
                ], // P2PKH
            }]
            .into(),
            lock_time: 0,
        };

        let result = engine.validate_transaction(&tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cross_protocol_validation() {
        let mainnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let testnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();

        // Both engines should support the same features
        assert_eq!(
            mainnet_engine.supports_feature("segwit"),
            testnet_engine.supports_feature("segwit")
        );
        assert_eq!(
            mainnet_engine.supports_feature("taproot"),
            testnet_engine.supports_feature("taproot")
        );

        // But they should have different network parameters
        assert_ne!(
            mainnet_engine.get_network_params().magic_bytes,
            testnet_engine.get_network_params().magic_bytes
        );
        assert_ne!(
            mainnet_engine.get_network_params().default_port,
            testnet_engine.get_network_params().default_port
        );
    }

    #[test]
    fn test_protocol_version_switching() {
        // Test that we can create engines for different protocol versions
        let versions = vec![
            ProtocolVersion::BitcoinV1,
            ProtocolVersion::Testnet3,
            ProtocolVersion::Regtest,
        ];

        for version in versions {
            let engine = BitcoinProtocolEngine::new(version).unwrap();
            assert_eq!(engine.get_protocol_version(), version);
        }
    }

    #[test]
    fn test_network_parameters_serialization() {
        let mainnet = NetworkParameters::mainnet().unwrap();
        let testnet = NetworkParameters::testnet().unwrap();
        let regtest = NetworkParameters::regtest().unwrap();

        // Test that parameters can be serialized and deserialized
        let mainnet_json = serde_json::to_string(&mainnet).unwrap();
        let mainnet_deserialized: NetworkParameters = serde_json::from_str(&mainnet_json).unwrap();
        assert_eq!(mainnet.magic_bytes, mainnet_deserialized.magic_bytes);
        assert_eq!(mainnet.default_port, mainnet_deserialized.default_port);
        assert_eq!(mainnet.network_name, mainnet_deserialized.network_name);
        assert_eq!(mainnet.is_testnet, mainnet_deserialized.is_testnet);

        let testnet_json = serde_json::to_string(&testnet).unwrap();
        let testnet_deserialized: NetworkParameters = serde_json::from_str(&testnet_json).unwrap();
        assert_eq!(testnet.magic_bytes, testnet_deserialized.magic_bytes);

        let regtest_json = serde_json::to_string(&regtest).unwrap();
        let regtest_deserialized: NetworkParameters = serde_json::from_str(&regtest_json).unwrap();
        assert_eq!(regtest.magic_bytes, regtest_deserialized.magic_bytes);
    }

    #[test]
    fn test_protocol_version_serialization() {
        let versions = vec![
            ProtocolVersion::BitcoinV1,
            ProtocolVersion::Testnet3,
            ProtocolVersion::Regtest,
        ];

        for version in versions {
            let json = serde_json::to_string(&version).unwrap();
            let deserialized: ProtocolVersion = serde_json::from_str(&json).unwrap();
            assert_eq!(version, deserialized);
        }
    }

    #[test]
    fn test_network_parameters_equality() {
        let mainnet1 = NetworkParameters::mainnet().unwrap();
        let mainnet2 = NetworkParameters::mainnet().unwrap();
        let testnet = NetworkParameters::testnet().unwrap();

        assert_eq!(mainnet1, mainnet2);
        assert_ne!(mainnet1, testnet);
    }

    #[test]
    fn test_protocol_version_equality() {
        assert_eq!(ProtocolVersion::BitcoinV1, ProtocolVersion::BitcoinV1);
        assert_ne!(ProtocolVersion::BitcoinV1, ProtocolVersion::Testnet3);
        assert_ne!(ProtocolVersion::Testnet3, ProtocolVersion::Regtest);
    }

    #[test]
    fn test_feature_activation_by_height() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();

        // SegWit activates at block 481,824
        assert!(!engine.is_feature_active("segwit", 481_823, 1503539000));
        assert!(engine.is_feature_active("segwit", 481_824, 1503539857));
        assert!(engine.is_feature_active("segwit", 500_000, 1504000000));

        // Taproot activates at block 709,632
        assert!(!engine.is_feature_active("taproot", 709_631, 1636934000));
        assert!(engine.is_feature_active("taproot", 709_632, 1636934400));
        assert!(engine.is_feature_active("taproot", 800_000, 1640000000));
    }

    #[test]
    fn test_economic_parameters_access() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let params = engine.get_economic_parameters();

        assert_eq!(params.initial_subsidy, 50_0000_0000);
        assert_eq!(params.halving_interval, 210_000);
        assert_eq!(params.coinbase_maturity, 100);

        // Test block subsidy calculation
        assert_eq!(params.get_block_subsidy(0), 50_0000_0000);
        assert_eq!(params.get_block_subsidy(210_000), 25_0000_0000);
    }

    #[test]
    fn test_feature_registry_access() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let registry = engine.get_feature_registry();

        assert!(registry.get_feature("segwit").is_some());
        assert!(registry.get_feature("taproot").is_some());
        assert!(registry.get_feature("nonexistent").is_none());

        let features = registry.list_features();
        assert!(features.contains(&"segwit".to_string()));
        assert!(features.contains(&"taproot".to_string()));
    }
}
