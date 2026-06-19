//! Configuration for blvm-protocol
//!
//! Provides configurable parameters for protocol-level settings, service flags,
//! protocol validation rules, and Commons-specific extensions. These settings
//! complement blvm-consensus configuration by focusing on protocol abstraction
//! rather than consensus validation.
//!
//! Operational limits and sub-configs align with [`blvm_consensus::config`] (which builds on
//! `blvm-primitives` for foundational types). [`ConsensusConfig`](crate::consensus_config::ConsensusConfig)
//! remains the full consensus aggregate in `blvm-consensus`.

pub use blvm_consensus::config::{
    AdvancedConfig, BlockValidationConfig, DebugConfig, FeatureFlagsConfig, MempoolConfig,
    NetworkMessageLimits, PerformanceConfig, UtxoCommitmentConfig,
};

use crate::ProtocolVersion;
use serde::{Deserialize, Serialize};

/// Protocol validation rules configuration
///
/// Controls protocol-specific size limits and feature enablement.
/// These are protocol-level rules that may differ from consensus rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolValidationConfig {
    /// Maximum block size for protocol validation (bytes)
    /// Default: 4,000,000 (4MB)
    #[serde(default = "default_max_block_size")]
    pub max_block_size: u32,

    /// Maximum transaction size for protocol validation (bytes)
    /// Default: 1,000,000 (1MB)
    #[serde(default = "default_max_tx_size")]
    pub max_tx_size: u32,

    /// Maximum script size for protocol validation (bytes)
    /// Default: 10,000 (10KB)
    #[serde(default = "default_max_script_size")]
    pub max_script_size: u32,

    /// Maximum transactions per block (protocol limit)
    /// Default: 10,000
    #[serde(default = "default_max_txs_per_block")]
    pub max_txs_per_block: usize,

    /// Maximum block locator hashes in GetHeaders/GetBlocks
    /// Default: 100
    #[serde(default = "default_max_locator_hashes")]
    pub max_locator_hashes: usize,
}

fn default_max_block_size() -> u32 {
    4_000_000
}

fn default_max_tx_size() -> u32 {
    1_000_000
}

fn default_max_script_size() -> u32 {
    10_000
}

fn default_max_txs_per_block() -> usize {
    10_000
}

fn default_max_locator_hashes() -> usize {
    100
}

impl Default for ProtocolValidationConfig {
    fn default() -> Self {
        Self {
            max_block_size: 4_000_000,
            max_tx_size: 1_000_000,
            max_script_size: 10_000,
            max_txs_per_block: 10_000,
            max_locator_hashes: 100,
        }
    }
}

/// Service flags configuration
///
/// Controls which service capabilities are advertised to peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceFlagsConfig {
    /// Advertise NODE_NETWORK capability
    /// Default: true (always enabled)
    #[serde(default = "default_true")]
    pub node_network: bool,

    /// Advertise NODE_WITNESS capability (SegWit support)
    /// Default: true
    #[serde(default = "default_true")]
    pub node_witness: bool,

    /// Advertise NODE_COMPACT_FILTERS capability (BIP157/158)
    /// Default: false
    #[serde(default = "default_false")]
    pub node_compact_filters: bool,

    /// Advertise NODE_NETWORK_LIMITED capability
    /// Default: false
    #[serde(default = "default_false")]
    pub node_network_limited: bool,

    /// Advertise Commons NODE_FIBRE capability
    /// Default: false
    #[serde(default = "default_false")]
    pub node_fibre: bool,

    /// Advertise Commons NODE_DANDELION capability
    /// Default: false
    #[serde(default = "default_false")]
    pub node_dandelion: bool,

    /// Advertise Commons NODE_PACKAGE_RELAY capability (BIP331)
    /// Default: false
    #[serde(default = "default_false")]
    pub node_package_relay: bool,

    /// Advertise Commons NODE_UTXO_COMMITMENTS capability
    /// Default: false (requires utxo-commitments feature)
    #[serde(default = "default_false")]
    pub node_utxo_commitments: bool,

    /// Advertise Commons NODE_BAN_LIST_SHARING capability
    /// Default: false
    #[serde(default = "default_false")]
    pub node_ban_list_sharing: bool,

    /// Advertise NODE_V2_TRANSPORT capability (BIP324)
    /// Default: false (requires bip324 feature)
    #[cfg(feature = "bip324")]
    #[serde(default = "default_false")]
    pub node_v2_transport: bool,

    /// Advertise Commons NODE_GOVERNANCE capability (governance message relay)
    /// Default: false
    #[serde(default = "default_false")]
    pub node_governance: bool,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

impl Default for ServiceFlagsConfig {
    fn default() -> Self {
        Self {
            node_network: true,
            node_witness: true,
            node_compact_filters: false,
            node_network_limited: false,
            node_fibre: false,
            node_dandelion: false,
            node_package_relay: false,
            node_utxo_commitments: false,
            node_ban_list_sharing: false,
            node_governance: false,
            #[cfg(feature = "bip324")]
            node_v2_transport: false,
        }
    }
}

/// Protocol feature configuration
///
/// Controls which protocol features are enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolFeaturesConfig {
    /// Enable SegWit (Segregated Witness)
    /// Default: true
    #[serde(default = "default_true")]
    pub segwit: bool,

    /// Enable Taproot
    /// Default: true
    #[serde(default = "default_true")]
    pub taproot: bool,

    /// Enable RBF (Replace-By-Fee)
    /// Default: true
    #[serde(default = "default_true")]
    pub rbf: bool,

    /// Enable CTV (CheckTemplateVerify, BIP119)
    /// Default: false
    #[serde(default = "default_false")]
    pub ctv: bool,

    /// Enable BIP152 Compact Block Relay
    /// Default: true
    #[serde(default = "default_true")]
    pub compact_blocks: bool,

    /// Enable BIP157/158 Compact Block Filters
    /// Default: false
    #[serde(default = "default_false")]
    pub compact_filters: bool,
}

impl Default for ProtocolFeaturesConfig {
    fn default() -> Self {
        Self {
            segwit: true,
            taproot: true,
            rbf: true,
            ctv: false,
            compact_blocks: true,
            compact_filters: false,
        }
    }
}

/// Fee rate configuration
///
/// Controls protocol-level fee rate limits and validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRateConfig {
    /// Minimum transaction fee rate (satoshis per virtual byte)
    /// Default: 1 sat/vB
    #[serde(default = "default_min_fee_rate")]
    pub min_fee_rate: u64,

    /// Maximum transaction fee rate (satoshis per virtual byte)
    /// Default: 1,000,000 sat/vB
    #[serde(default = "default_max_fee_rate")]
    pub max_fee_rate: u64,
}

fn default_min_fee_rate() -> u64 {
    1
}

fn default_max_fee_rate() -> u64 {
    1_000_000
}

impl Default for FeeRateConfig {
    fn default() -> Self {
        Self {
            min_fee_rate: 1,
            max_fee_rate: 1_000_000,
        }
    }
}

/// BIP152 Compact Block Relay configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactBlockConfig {
    /// Enable compact block relay
    /// Default: true
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Preferred compact block version (1 or 2)
    /// Default: 2 (latest)
    #[serde(default = "default_compact_block_version")]
    pub preferred_version: u64,

    /// Maximum transaction indices in GetBlockTxn
    /// Default: 10,000
    #[serde(default = "default_max_blocktxn_indices")]
    pub max_blocktxn_indices: usize,
}

fn default_compact_block_version() -> u64 {
    2
}

fn default_max_blocktxn_indices() -> usize {
    10_000
}

impl Default for CompactBlockConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            preferred_version: 2,
            max_blocktxn_indices: 10_000,
        }
    }
}

/// Commons-specific protocol extensions configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CommonsExtensionsConfig {
    /// Enable UTXO commitments protocol
    /// Default: false (requires utxo-commitments feature)
    #[serde(default = "default_false")]
    pub utxo_commitments: bool,

    /// Enable filtered block relay (spam filtering)
    /// Default: false
    #[serde(default = "default_false")]
    pub filtered_blocks: bool,

    /// Enable ban list sharing
    /// Default: false
    #[serde(default = "default_false")]
    pub ban_list_sharing: bool,

    /// Default filter preferences for filtered blocks
    #[serde(default)]
    pub default_filter_preferences: FilterPreferencesConfig,
}

/// Filter preferences configuration for spam filtering
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FilterPreferencesConfig {
    /// Filter Ordinals/Inscriptions
    /// Default: false
    #[serde(default = "default_false")]
    pub filter_ordinals: bool,

    /// Filter dust outputs (< 546 satoshis)
    /// Default: false
    #[serde(default = "default_false")]
    pub filter_dust: bool,

    /// Filter BRC-20 patterns
    /// Default: false
    #[serde(default = "default_false")]
    pub filter_brc20: bool,

    /// Minimum output value to include (satoshis)
    /// Default: 0 (no minimum)
    #[serde(default)]
    pub min_output_value: u64,
}

/// Complete protocol configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolConfig {
    /// Protocol version to use
    /// Default: BitcoinV1 (mainnet)
    #[serde(default = "default_protocol_version")]
    pub protocol_version: ProtocolVersion,

    /// Network message limits (from blvm-consensus to avoid duplication)
    /// These limits protect against DoS attacks by bounding message sizes
    #[serde(default)]
    pub network_limits: NetworkMessageLimits,

    /// Protocol validation rules
    #[serde(default)]
    pub validation: ProtocolValidationConfig,

    /// Service flags configuration
    #[serde(default)]
    pub service_flags: ServiceFlagsConfig,

    /// Protocol features configuration
    #[serde(default)]
    pub features: ProtocolFeaturesConfig,

    /// Fee rate configuration
    #[serde(default)]
    pub fee_rates: FeeRateConfig,

    /// BIP152 Compact Block Relay configuration
    #[serde(default)]
    pub compact_blocks: CompactBlockConfig,

    /// Commons-specific extensions configuration
    #[serde(default)]
    pub commons: CommonsExtensionsConfig,
}

fn default_protocol_version() -> ProtocolVersion {
    ProtocolVersion::BitcoinV1
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            protocol_version: ProtocolVersion::BitcoinV1,
            network_limits: NetworkMessageLimits::default(),
            validation: ProtocolValidationConfig::default(),
            service_flags: ServiceFlagsConfig::default(),
            features: ProtocolFeaturesConfig::default(),
            fee_rates: FeeRateConfig::default(),
            compact_blocks: CompactBlockConfig::default(),
            commons: CommonsExtensionsConfig::default(),
        }
    }
}

impl ProtocolConfig {
    /// Load configuration from environment variables
    ///
    /// Uses short names aligned with blvm-consensus where applicable.
    /// Examples: `BLVM_PROTOCOL_VERSION=Testnet3`, `BLVM_MAX_BLOCK_SIZE=4000000`
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Protocol version
        if let Ok(val) = std::env::var("BLVM_PROTOCOL_VERSION") {
            config.protocol_version = match val.as_str() {
                "Testnet3" | "testnet" => ProtocolVersion::Testnet3,
                "Regtest" | "regtest" => ProtocolVersion::Regtest,
                "Signet" | "signet" => ProtocolVersion::Signet,
                _ => ProtocolVersion::BitcoinV1,
            };
        }

        // Network limits (same vars as blvm-consensus)
        if let Ok(val) = std::env::var("BLVM_MAX_ADDR_ADDRESSES") {
            if let Ok(count) = val.parse::<usize>() {
                config.network_limits.max_addr_addresses = count;
            }
        }
        if let Ok(val) = std::env::var("BLVM_MAX_INV_ITEMS") {
            if let Ok(count) = val.parse::<usize>() {
                config.network_limits.max_inv_items = count;
            }
        }
        if let Ok(val) = std::env::var("BLVM_MAX_HEADERS") {
            if let Ok(count) = val.parse::<usize>() {
                config.network_limits.max_headers = count;
            }
        }
        if let Ok(val) = std::env::var("BLVM_MAX_USER_AGENT_LENGTH") {
            if let Ok(length) = val.parse::<usize>() {
                config.network_limits.max_user_agent_length = length;
            }
        }

        // Validation
        if let Ok(val) = std::env::var("BLVM_MAX_BLOCK_SIZE") {
            if let Ok(size) = val.parse::<u32>() {
                config.validation.max_block_size = size;
            }
        }
        if let Ok(val) = std::env::var("BLVM_MAX_TX_SIZE") {
            if let Ok(size) = val.parse::<u32>() {
                config.validation.max_tx_size = size;
            }
        }
        if let Ok(val) = std::env::var("BLVM_MAX_TXS_PER_BLOCK") {
            if let Ok(count) = val.parse::<usize>() {
                config.validation.max_txs_per_block = count;
            }
        }
        if let Ok(val) = std::env::var("BLVM_MAX_LOCATOR_HASHES") {
            if let Ok(count) = val.parse::<usize>() {
                config.validation.max_locator_hashes = count;
            }
        }

        // Service flags
        if let Ok(val) = std::env::var("BLVM_SERVICE_FIBRE") {
            if let Ok(enabled) = val.parse::<bool>() {
                config.service_flags.node_fibre = enabled;
            }
        }
        if let Ok(val) = std::env::var("BLVM_SERVICE_UTXO_COMMITMENTS") {
            if let Ok(enabled) = val.parse::<bool>() {
                config.service_flags.node_utxo_commitments = enabled;
            }
        }
        if let Ok(val) = std::env::var("BLVM_SERVICE_BAN_LIST_SHARING") {
            if let Ok(enabled) = val.parse::<bool>() {
                config.service_flags.node_ban_list_sharing = enabled;
            }
        }

        // Features
        if let Ok(val) = std::env::var("BLVM_FEATURE_COMPACT_BLOCKS") {
            if let Ok(enabled) = val.parse::<bool>() {
                config.features.compact_blocks = enabled;
            }
        }

        // Commons extensions
        if let Ok(val) = std::env::var("BLVM_UTXO_COMMITMENTS") {
            if let Ok(enabled) = val.parse::<bool>() {
                config.commons.utxo_commitments = enabled;
            }
        }

        config
    }

    /// Get service flags value from configuration
    pub fn get_service_flags(&self) -> u64 {
        use crate::service_flags::{commons, set_flag, standard};
        let mut flags = 0u64;

        if self.service_flags.node_network {
            set_flag(&mut flags, standard::NODE_NETWORK);
        }
        if self.service_flags.node_witness {
            set_flag(&mut flags, standard::NODE_WITNESS);
        }
        if self.service_flags.node_compact_filters {
            set_flag(&mut flags, standard::NODE_COMPACT_FILTERS);
        }
        if self.service_flags.node_network_limited {
            set_flag(&mut flags, standard::NODE_NETWORK_LIMITED);
        }
        if self.service_flags.node_fibre {
            set_flag(&mut flags, commons::NODE_FIBRE);
        }
        if self.service_flags.node_dandelion {
            set_flag(&mut flags, commons::NODE_DANDELION);
        }
        if self.service_flags.node_package_relay {
            set_flag(&mut flags, commons::NODE_PACKAGE_RELAY);
        }
        #[cfg(feature = "utxo-commitments")]
        if self.service_flags.node_utxo_commitments {
            set_flag(&mut flags, commons::NODE_UTXO_COMMITMENTS);
        }
        if self.service_flags.node_ban_list_sharing {
            set_flag(&mut flags, commons::NODE_BAN_LIST_SHARING);
        }
        if self.service_flags.node_governance {
            set_flag(&mut flags, commons::NODE_GOVERNANCE);
        }

        flags
    }
}
