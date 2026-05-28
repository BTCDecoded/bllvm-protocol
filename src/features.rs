//! Feature Activation Tracking
//!
//! Tracks when protocol features activate by block height or timestamp.
//! This allows the protocol engine to determine if features are active
//! at a specific block height, not just whether they're supported.

use crate::ProtocolVersion;
use serde::{Deserialize, Serialize};

/// Feature activation method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivationMethod {
    /// BIP9 version bits activation
    BIP9,
    /// Height-based activation (e.g., BIP34 blocks version)
    HeightBased,
    /// Timestamp-based activation
    Timestamp,
    /// Hard fork - immediate activation at genesis
    HardFork,
    /// Always active from genesis
    AlwaysActive,
}

/// Feature activation information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureActivation {
    /// Feature name
    pub feature_name: String,
    /// Activation block height (if height-based)
    pub activation_height: Option<u64>,
    /// Activation timestamp (Unix timestamp, if time-based)
    pub activation_timestamp: Option<u64>,
    /// Activation method
    pub activation_method: ActivationMethod,
    /// BIP number (if applicable)
    pub bip_number: Option<u32>,
}

impl FeatureActivation {
    /// Check if feature is active at given height and timestamp
    pub fn is_active_at(&self, height: u64, timestamp: u64) -> bool {
        match self.activation_method {
            ActivationMethod::AlwaysActive => true,
            ActivationMethod::HardFork => {
                // Hard forks activate immediately at genesis
                true
            }
            ActivationMethod::HeightBased => {
                if let Some(activation_height) = self.activation_height {
                    height >= activation_height
                } else {
                    false
                }
            }
            ActivationMethod::Timestamp => {
                if let Some(activation_timestamp) = self.activation_timestamp {
                    timestamp >= activation_timestamp
                } else {
                    false
                }
            }
            ActivationMethod::BIP9 => {
                // BIP9 activation is determined by height (block height at which the deployment
                // is considered ACTIVE after lock-in). Timestamp alone must NOT activate a
                // feature — that was the bug: `height_active || timestamp_active` allowed
                // timestamp to short-circuit the height gate.
                //
                // If activation_height is set, it is the authoritative gate.
                // Timestamp is only used as the gate when no activation_height is configured
                // (timestamp-only BIP9 pre-height-based locking).
                if self.activation_height.is_some() {
                    self.activation_height.is_some_and(|h| height >= h)
                } else {
                    self.activation_timestamp.is_some_and(|t| timestamp >= t)
                }
            }
        }
    }
}

/// Feature activation registry for a protocol version
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureRegistry {
    /// Protocol version
    pub protocol_version: ProtocolVersion,
    /// Feature activations
    pub features: Vec<FeatureActivation>,
}

impl FeatureRegistry {
    /// Get feature activations for a protocol version
    pub fn for_protocol(version: ProtocolVersion) -> Self {
        match version {
            ProtocolVersion::BitcoinV1 => Self::mainnet(),
            ProtocolVersion::Testnet3 => Self::testnet(),
            ProtocolVersion::Regtest => Self::regtest(),
        }
    }

    /// Mainnet feature activations
    pub fn mainnet() -> Self {
        Self {
            protocol_version: ProtocolVersion::BitcoinV1,
            features: vec![
                // SegWit activated via BIP9 at block 481,824 (August 24, 2017)
                FeatureActivation {
                    feature_name: "segwit".to_string(),
                    activation_height: Some(481_824),
                    activation_timestamp: Some(1503539857), // Aug 24, 2017
                    activation_method: ActivationMethod::BIP9,
                    bip_number: Some(141),
                },
                // Taproot activated via BIP9 at block 709,632 (November 14, 2021)
                FeatureActivation {
                    feature_name: "taproot".to_string(),
                    activation_height: Some(709_632),
                    activation_timestamp: Some(1636934400), // Nov 14, 2021
                    activation_method: ActivationMethod::BIP9,
                    bip_number: Some(341),
                },
                // RBF (BIP125) - Always available (mempool policy)
                FeatureActivation {
                    feature_name: "rbf".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(125),
                },
                // CTV (CheckTemplateVerify) - Not yet activated
                FeatureActivation {
                    feature_name: "ctv".to_string(),
                    activation_height: None,
                    activation_timestamp: None,
                    activation_method: ActivationMethod::BIP9,
                    bip_number: Some(119),
                },
                // CSV (CheckSequenceVerify) - Always active
                FeatureActivation {
                    feature_name: "csv".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(112),
                },
                // CLTV (CheckLockTimeVerify) - Always active
                FeatureActivation {
                    feature_name: "cltv".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(65),
                },
            ],
        }
    }

    /// Testnet feature activations
    pub fn testnet() -> Self {
        Self {
            protocol_version: ProtocolVersion::Testnet3,
            features: vec![
                // SegWit activated earlier on testnet
                FeatureActivation {
                    feature_name: "segwit".to_string(),
                    activation_height: Some(465_600), // Earlier on testnet
                    activation_timestamp: Some(1493596800), // May 1, 2017
                    activation_method: ActivationMethod::BIP9,
                    bip_number: Some(141),
                },
                // Taproot activated earlier on testnet
                FeatureActivation {
                    feature_name: "taproot".to_string(),
                    activation_height: Some(2_016_000), // Earlier on testnet
                    activation_timestamp: Some(1628640000), // Aug 11, 2021
                    activation_method: ActivationMethod::BIP9,
                    bip_number: Some(341),
                },
                // RBF - Always available
                FeatureActivation {
                    feature_name: "rbf".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(125),
                },
                // CSV - Always active
                FeatureActivation {
                    feature_name: "csv".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(112),
                },
                // CLTV - Always active
                FeatureActivation {
                    feature_name: "cltv".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(65),
                },
            ],
        }
    }

    /// Regtest feature activations (all features active from genesis)
    pub fn regtest() -> Self {
        Self {
            protocol_version: ProtocolVersion::Regtest,
            features: vec![
                // All features active from genesis on regtest
                FeatureActivation {
                    feature_name: "segwit".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(141),
                },
                FeatureActivation {
                    feature_name: "taproot".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(341),
                },
                FeatureActivation {
                    feature_name: "rbf".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(125),
                },
                FeatureActivation {
                    feature_name: "csv".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(112),
                },
                FeatureActivation {
                    feature_name: "cltv".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: Some(65),
                },
                FeatureActivation {
                    feature_name: "fast_mining".to_string(),
                    activation_height: Some(0),
                    activation_timestamp: None,
                    activation_method: ActivationMethod::AlwaysActive,
                    bip_number: None,
                },
            ],
        }
    }

    /// Check if a feature is active at a given height and timestamp
    pub fn is_feature_active(&self, feature_name: &str, height: u64, timestamp: u64) -> bool {
        self.features
            .iter()
            .find(|f| f.feature_name == feature_name)
            .map(|f| f.is_active_at(height, timestamp))
            .unwrap_or(false)
    }

    /// Get feature activation information
    pub fn get_feature(&self, feature_name: &str) -> Option<&FeatureActivation> {
        self.features
            .iter()
            .find(|f| f.feature_name == feature_name)
    }

    /// List all features
    pub fn list_features(&self) -> Vec<String> {
        self.features
            .iter()
            .map(|f| f.feature_name.clone())
            .collect()
    }

    /// Create a FeatureContext for a specific height and timestamp
    /// This consolidates all feature activation checks into a single context
    pub fn create_context(&self, height: u64, timestamp: u64) -> FeatureContext {
        FeatureContext {
            segwit: self.is_feature_active("segwit", height, timestamp),
            taproot: self.is_feature_active("taproot", height, timestamp),
            csv: self.is_feature_active("csv", height, timestamp),
            cltv: self.is_feature_active("cltv", height, timestamp),
            rbf: self.is_feature_active("rbf", height, timestamp),
            ctv: self.is_feature_active("ctv", height, timestamp),
            height,
            timestamp,
        }
    }
}

/// Feature context consolidating all Bitcoin feature flags at a specific height/timestamp
/// This provides a single source of truth for feature activation state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureContext {
    /// SegWit (BIP141/143) activation state
    pub segwit: bool,
    /// Taproot (BIP341/342) activation state
    pub taproot: bool,
    /// CSV (BIP112) activation state
    pub csv: bool,
    /// CLTV (BIP65) activation state
    pub cltv: bool,
    /// RBF (BIP125) activation state (mempool policy)
    pub rbf: bool,
    /// CTV (BIP119) activation state
    pub ctv: bool,
    /// Block height at which this context is valid
    pub height: u64,
    /// Timestamp at which this context is valid
    pub timestamp: u64,
}

impl FeatureContext {
    /// Create a new feature context from a feature registry
    pub fn from_registry(registry: &FeatureRegistry, height: u64, timestamp: u64) -> Self {
        registry.create_context(height, timestamp)
    }

    /// Check if a specific feature is active
    pub fn is_active(&self, feature: &str) -> bool {
        match feature {
            "segwit" => self.segwit,
            "taproot" => self.taproot,
            "csv" => self.csv,
            "cltv" => self.cltv,
            "rbf" => self.rbf,
            "ctv" => self.ctv,
            _ => false,
        }
    }

    /// Get list of all active features
    pub fn active_features(&self) -> Vec<&'static str> {
        let mut features = Vec::new();
        if self.segwit {
            features.push("segwit");
        }
        if self.taproot {
            features.push("taproot");
        }
        if self.csv {
            features.push("csv");
        }
        if self.cltv {
            features.push("cltv");
        }
        if self.rbf {
            features.push("rbf");
        }
        if self.ctv {
            features.push("ctv");
        }
        features
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segwit_activation_mainnet() {
        let registry = FeatureRegistry::mainnet();

        // Before activation
        assert!(!registry.is_feature_active("segwit", 481_823, 1503539000));

        // At activation height
        assert!(registry.is_feature_active("segwit", 481_824, 1503539857));

        // After activation
        assert!(registry.is_feature_active("segwit", 500_000, 1504000000));
    }

    #[test]
    fn test_taproot_activation_mainnet() {
        let registry = FeatureRegistry::mainnet();

        // Before activation
        assert!(!registry.is_feature_active("taproot", 709_631, 1636934000));

        // At activation height
        assert!(registry.is_feature_active("taproot", 709_632, 1636934400));

        // After activation
        assert!(registry.is_feature_active("taproot", 800_000, 1640000000));
    }

    #[test]
    fn test_always_active_features() {
        let registry = FeatureRegistry::mainnet();

        // RBF, CSV, CLTV should always be active
        assert!(registry.is_feature_active("rbf", 0, 1231006505));
        assert!(registry.is_feature_active("csv", 0, 1231006505));
        assert!(registry.is_feature_active("cltv", 0, 1231006505));
        assert!(registry.is_feature_active("rbf", 1_000_000, 2000000000));
    }

    #[test]
    fn test_regtest_all_features_active() {
        let registry = FeatureRegistry::regtest();

        // All features should be active from genesis on regtest
        assert!(registry.is_feature_active("segwit", 0, 1231006505));
        assert!(registry.is_feature_active("taproot", 0, 1231006505));
        assert!(registry.is_feature_active("rbf", 0, 1231006505));
        assert!(registry.is_feature_active("fast_mining", 0, 1231006505));
    }

    #[test]
    fn test_testnet_earlier_activations() {
        let registry = FeatureRegistry::testnet();

        // SegWit activated earlier on testnet
        assert!(!registry.is_feature_active("segwit", 465_599, 1493596000));
        assert!(registry.is_feature_active("segwit", 465_600, 1493596800));
        assert!(registry.is_feature_active("segwit", 500_000, 1500000000));
    }

    #[test]
    fn test_feature_not_found() {
        let registry = FeatureRegistry::mainnet();

        // Non-existent feature should return false
        assert!(!registry.is_feature_active("nonexistent", 1_000_000, 2000000000));
    }

    #[test]
    fn test_get_feature() {
        let registry = FeatureRegistry::mainnet();

        let segwit = registry.get_feature("segwit").unwrap();
        assert_eq!(segwit.feature_name, "segwit");
        assert_eq!(segwit.bip_number, Some(141));
        assert_eq!(segwit.activation_method, ActivationMethod::BIP9);

        assert!(registry.get_feature("nonexistent").is_none());
    }

    #[test]
    fn test_list_features() {
        let mainnet = FeatureRegistry::mainnet();
        let features = mainnet.list_features();

        assert!(features.contains(&"segwit".to_string()));
        assert!(features.contains(&"taproot".to_string()));
        assert!(features.contains(&"rbf".to_string()));
        assert!(features.contains(&"csv".to_string()));
        assert!(features.contains(&"cltv".to_string()));
    }

    #[test]
    fn test_activation_methods() {
        let mainnet = FeatureRegistry::mainnet();

        let segwit = mainnet.get_feature("segwit").unwrap();
        assert_eq!(segwit.activation_method, ActivationMethod::BIP9);

        let rbf = mainnet.get_feature("rbf").unwrap();
        assert_eq!(rbf.activation_method, ActivationMethod::AlwaysActive);
    }

    #[test]
    fn test_bip9_height_and_timestamp() {
        let registry = FeatureRegistry::mainnet();

        // BIP9 with activation_height set: height is authoritative.
        // Height met, timestamp below activation → active (height wins).
        assert!(registry.is_feature_active("segwit", 481_824, 1500000000));

        // Height NOT met, timestamp at/above activation → NOT active.
        // This is the corrected behaviour: timestamp alone cannot activate
        // a BIP9 feature that has an explicit activation_height configured.
        assert!(!registry.is_feature_active("segwit", 481_000, 1503539857));

        // Both met → active.
        assert!(registry.is_feature_active("segwit", 481_824, 1503539857));
    }

    #[test]
    fn test_feature_context_creation() {
        let registry = FeatureRegistry::mainnet();

        // Before SegWit activation
        let ctx_before = registry.create_context(481_823, 1503539000);
        assert!(!ctx_before.segwit);
        assert!(!ctx_before.taproot);
        assert!(ctx_before.csv); // CSV is always active
        assert!(ctx_before.cltv); // CLTV is always active
        assert!(ctx_before.rbf); // RBF is always active

        // At SegWit activation
        let ctx_at_segwit = registry.create_context(481_824, 1503539857);
        assert!(ctx_at_segwit.segwit);
        assert!(!ctx_at_segwit.taproot);

        // At Taproot activation
        let ctx_at_taproot = registry.create_context(709_632, 1636934400);
        assert!(ctx_at_taproot.segwit);
        assert!(ctx_at_taproot.taproot);

        // After all activations
        let ctx_after = registry.create_context(800_000, 1640000000);
        assert!(ctx_after.segwit);
        assert!(ctx_after.taproot);
    }

    #[test]
    fn test_feature_context_is_active() {
        let registry = FeatureRegistry::mainnet();
        let ctx = registry.create_context(800_000, 1640000000);

        assert!(ctx.is_active("segwit"));
        assert!(ctx.is_active("taproot"));
        assert!(ctx.is_active("csv"));
        assert!(ctx.is_active("cltv"));
        assert!(ctx.is_active("rbf"));
        assert!(!ctx.is_active("ctv")); // CTV not activated
        assert!(!ctx.is_active("nonexistent"));
    }

    #[test]
    fn test_feature_context_active_features() {
        let registry = FeatureRegistry::mainnet();

        // Before any activations
        let ctx_before = registry.create_context(0, 1231006505);
        let active = ctx_before.active_features();
        assert!(active.contains(&"csv"));
        assert!(active.contains(&"cltv"));
        assert!(active.contains(&"rbf"));
        assert!(!active.contains(&"segwit"));
        assert!(!active.contains(&"taproot"));

        // After all activations
        let ctx_after = registry.create_context(800_000, 1640000000);
        let active = ctx_after.active_features();
        assert!(active.contains(&"segwit"));
        assert!(active.contains(&"taproot"));
        assert!(active.contains(&"csv"));
        assert!(active.contains(&"cltv"));
        assert!(active.contains(&"rbf"));
    }

    #[test]
    fn test_feature_context_regtest() {
        let registry = FeatureRegistry::regtest();
        let ctx = registry.create_context(0, 1231006505);

        // All features should be active from genesis on regtest
        assert!(ctx.segwit);
        assert!(ctx.taproot);
        assert!(ctx.csv);
        assert!(ctx.cltv);
        assert!(ctx.rbf);
    }

    #[test]
    fn test_feature_context_from_registry() {
        let registry = FeatureRegistry::mainnet();
        let ctx = FeatureContext::from_registry(&registry, 800_000, 1640000000);

        assert!(ctx.segwit);
        assert!(ctx.taproot);
        assert_eq!(ctx.height, 800_000);
        assert_eq!(ctx.timestamp, 1640000000);
    }
}
