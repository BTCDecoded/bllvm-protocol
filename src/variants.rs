//! Protocol variants implementation
//!
//! This module implements different Bitcoin protocol variants:
//! - Mainnet: Production Bitcoin network
//! - Testnet: Bitcoin test network
//! - Regtest: Regression testing network

use crate::ProtocolVersion;
use serde::{Deserialize, Serialize};

/// Protocol variant configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVariant {
    pub version: ProtocolVersion,
    pub name: String,
    pub description: String,
    pub is_production: bool,
    pub supports_mining: bool,
    pub supports_wallet: bool,
}

impl ProtocolVariant {
    /// Get all available protocol variants
    pub fn all_variants() -> Vec<Self> {
        vec![
            ProtocolVariant {
                version: ProtocolVersion::BitcoinV1,
                name: "Bitcoin Mainnet".to_string(),
                description: "Production Bitcoin network with full consensus rules".to_string(),
                is_production: true,
                supports_mining: true,
                supports_wallet: true,
            },
            ProtocolVariant {
                version: ProtocolVersion::Testnet3,
                name: "Bitcoin Testnet".to_string(),
                description: "Bitcoin test network for development and testing".to_string(),
                is_production: false,
                supports_mining: true,
                supports_wallet: true,
            },
            ProtocolVariant {
                version: ProtocolVersion::Regtest,
                name: "Bitcoin Regtest".to_string(),
                description: "Regression testing network with configurable difficulty".to_string(),
                is_production: false,
                supports_mining: true,
                supports_wallet: true,
            },
            ProtocolVariant {
                version: ProtocolVersion::Signet,
                name: "Bitcoin Signet".to_string(),
                description: "Signet test network with BIP325 block-solution challenge".to_string(),
                is_production: false,
                supports_mining: true,
                supports_wallet: true,
            },
        ]
    }

    /// Get variant by protocol version
    pub fn for_version(version: ProtocolVersion) -> Option<Self> {
        Self::all_variants()
            .into_iter()
            .find(|v| v.version == version)
    }

    /// Check if this variant is suitable for production use
    pub fn is_production_ready(&self) -> bool {
        self.is_production
    }

    /// Check if this variant supports mining operations
    pub fn supports_mining_operations(&self) -> bool {
        self.supports_mining
    }

    /// Check if this variant supports wallet operations
    pub fn supports_wallet_operations(&self) -> bool {
        self.supports_wallet
    }
}

/// Protocol evolution support
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolEvolution {
    /// Protocol version number
    pub version: u32,
    /// Features enabled in this version
    pub enabled_features: Vec<String>,
    /// Features deprecated in this version
    pub deprecated_features: Vec<String>,
    /// Breaking changes from previous version
    pub breaking_changes: Vec<String>,
}

impl ProtocolEvolution {
    /// Bitcoin V1 (current)
    pub fn bitcoin_v1() -> Self {
        Self {
            version: 1,
            enabled_features: vec![
                "basic_transactions".to_string(),
                "proof_of_work".to_string(),
                "economic_model".to_string(),
                "p2p_networking".to_string(),
            ],
            deprecated_features: vec![],
            breaking_changes: vec![],
        }
    }

    /// Bitcoin V2 (future hypothetical)
    pub fn bitcoin_v2() -> Self {
        Self {
            version: 2,
            enabled_features: vec![
                "basic_transactions".to_string(),
                "proof_of_work".to_string(),
                "economic_model".to_string(),
                "p2p_networking".to_string(),
                "advanced_scripting".to_string(),
                "privacy_features".to_string(),
            ],
            deprecated_features: vec!["legacy_addresses".to_string()],
            breaking_changes: vec![
                "new_address_format".to_string(),
                "enhanced_script_engine".to_string(),
            ],
        }
    }

    /// Check if a feature is enabled in this protocol version
    pub fn has_feature(&self, feature: &str) -> bool {
        self.enabled_features.contains(&feature.to_string())
    }

    /// Check if a feature is deprecated in this protocol version
    pub fn is_deprecated(&self, feature: &str) -> bool {
        self.deprecated_features.contains(&feature.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_variants() {
        let variants = ProtocolVariant::all_variants();
        assert_eq!(variants.len(), 4);

        let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        assert_eq!(mainnet.name, "Bitcoin Mainnet");
        assert!(mainnet.is_production_ready());
        assert!(mainnet.supports_mining_operations());

        let signet = ProtocolVariant::for_version(ProtocolVersion::Signet).unwrap();
        assert_eq!(signet.name, "Bitcoin Signet");
        assert!(!signet.is_production_ready());

        let regtest = ProtocolVariant::for_version(ProtocolVersion::Regtest).unwrap();
        assert_eq!(regtest.name, "Bitcoin Regtest");
        assert!(!regtest.is_production_ready());
        assert!(regtest.supports_mining_operations());
    }

    #[test]
    fn test_protocol_variants_all_versions() {
        let variants = ProtocolVariant::all_variants();

        // Test that all expected variants are present
        let mainnet = variants
            .iter()
            .find(|v| v.version == ProtocolVersion::BitcoinV1)
            .unwrap();
        let testnet = variants
            .iter()
            .find(|v| v.version == ProtocolVersion::Testnet3)
            .unwrap();
        let regtest = variants
            .iter()
            .find(|v| v.version == ProtocolVersion::Regtest)
            .unwrap();

        assert_eq!(mainnet.name, "Bitcoin Mainnet");
        assert_eq!(testnet.name, "Bitcoin Testnet");
        assert_eq!(regtest.name, "Bitcoin Regtest");
    }

    #[test]
    fn test_protocol_variant_lookup() {
        // Test valid versions
        let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();
        let regtest = ProtocolVariant::for_version(ProtocolVersion::Regtest).unwrap();

        assert_eq!(mainnet.version, ProtocolVersion::BitcoinV1);
        assert_eq!(testnet.version, ProtocolVersion::Testnet3);
        assert_eq!(regtest.version, ProtocolVersion::Regtest);
    }

    #[test]
    fn test_protocol_variant_production_readiness() {
        let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();
        let regtest = ProtocolVariant::for_version(ProtocolVersion::Regtest).unwrap();

        assert!(mainnet.is_production_ready());
        assert!(!testnet.is_production_ready());
        assert!(!regtest.is_production_ready());
    }

    #[test]
    fn test_protocol_variant_mining_support() {
        let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();
        let regtest = ProtocolVariant::for_version(ProtocolVersion::Regtest).unwrap();

        assert!(mainnet.supports_mining_operations());
        assert!(testnet.supports_mining_operations());
        assert!(regtest.supports_mining_operations());
    }

    #[test]
    fn test_protocol_variant_wallet_support() {
        let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();
        let regtest = ProtocolVariant::for_version(ProtocolVersion::Regtest).unwrap();

        assert!(mainnet.supports_wallet_operations());
        assert!(testnet.supports_wallet_operations());
        assert!(regtest.supports_wallet_operations());
    }

    #[test]
    fn test_protocol_variant_descriptions() {
        let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();
        let regtest = ProtocolVariant::for_version(ProtocolVersion::Regtest).unwrap();

        assert!(mainnet.description.contains("Production"));
        assert!(testnet.description.contains("test"));
        assert!(regtest.description.contains("testing"));
    }

    #[test]
    fn test_protocol_variant_serialization() {
        let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        let json = serde_json::to_string(&mainnet).unwrap();
        let deserialized: ProtocolVariant = serde_json::from_str(&json).unwrap();

        assert_eq!(mainnet.version, deserialized.version);
        assert_eq!(mainnet.name, deserialized.name);
        assert_eq!(mainnet.description, deserialized.description);
        assert_eq!(mainnet.is_production, deserialized.is_production);
        assert_eq!(mainnet.supports_mining, deserialized.supports_mining);
        assert_eq!(mainnet.supports_wallet, deserialized.supports_wallet);
    }

    #[test]
    fn test_protocol_variant_equality() {
        let mainnet1 = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        let mainnet2 = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
        let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();

        assert_eq!(mainnet1, mainnet2);
        assert_ne!(mainnet1, testnet);
    }

    #[test]
    fn test_protocol_evolution() {
        let v1 = ProtocolEvolution::bitcoin_v1();
        assert_eq!(v1.version, 1);
        assert!(v1.has_feature("basic_transactions"));
        assert!(!v1.is_deprecated("basic_transactions"));

        let v2 = ProtocolEvolution::bitcoin_v2();
        assert_eq!(v2.version, 2);
        assert!(v2.has_feature("privacy_features"));
        assert!(v2.is_deprecated("legacy_addresses"));
    }

    #[test]
    fn test_protocol_evolution_v1_features() {
        let v1 = ProtocolEvolution::bitcoin_v1();

        // Test all V1 features
        assert!(v1.has_feature("basic_transactions"));
        assert!(v1.has_feature("proof_of_work"));
        assert!(v1.has_feature("economic_model"));
        assert!(v1.has_feature("p2p_networking"));

        // Test that V1 doesn't have V2 features
        assert!(!v1.has_feature("advanced_scripting"));
        assert!(!v1.has_feature("privacy_features"));

        // Test that V1 has no deprecated features
        assert!(!v1.is_deprecated("basic_transactions"));
        assert!(!v1.is_deprecated("proof_of_work"));
    }

    #[test]
    fn test_protocol_evolution_v2_features() {
        let v2 = ProtocolEvolution::bitcoin_v2();

        // Test V2 has all V1 features
        assert!(v2.has_feature("basic_transactions"));
        assert!(v2.has_feature("proof_of_work"));
        assert!(v2.has_feature("economic_model"));
        assert!(v2.has_feature("p2p_networking"));

        // Test V2 has new features
        assert!(v2.has_feature("advanced_scripting"));
        assert!(v2.has_feature("privacy_features"));

        // Test V2 has deprecated features
        assert!(v2.is_deprecated("legacy_addresses"));

        // Test V2 has breaking changes
        assert!(
            v2.breaking_changes
                .contains(&"new_address_format".to_string())
        );
        assert!(
            v2.breaking_changes
                .contains(&"enhanced_script_engine".to_string())
        );
    }

    #[test]
    fn test_protocol_evolution_feature_queries() {
        let v1 = ProtocolEvolution::bitcoin_v1();
        let v2 = ProtocolEvolution::bitcoin_v2();

        // Test feature existence
        assert!(v1.has_feature("basic_transactions"));
        assert!(!v1.has_feature("nonexistent"));
        assert!(!v1.has_feature(""));

        // Test deprecation queries
        assert!(!v1.is_deprecated("basic_transactions"));
        assert!(v2.is_deprecated("legacy_addresses"));
        assert!(!v2.is_deprecated("basic_transactions"));
    }

    #[test]
    fn test_protocol_evolution_serialization() {
        let v1 = ProtocolEvolution::bitcoin_v1();
        let json = serde_json::to_string(&v1).unwrap();
        let deserialized: ProtocolEvolution = serde_json::from_str(&json).unwrap();

        assert_eq!(v1.version, deserialized.version);
        assert_eq!(v1.enabled_features, deserialized.enabled_features);
        assert_eq!(v1.deprecated_features, deserialized.deprecated_features);
        assert_eq!(v1.breaking_changes, deserialized.breaking_changes);
    }

    #[test]
    fn test_protocol_evolution_equality() {
        let v1_1 = ProtocolEvolution::bitcoin_v1();
        let v1_2 = ProtocolEvolution::bitcoin_v1();
        let v2 = ProtocolEvolution::bitcoin_v2();

        assert_eq!(v1_1, v1_2);
        assert_ne!(v1_1, v2);
    }

    #[test]
    fn test_protocol_evolution_version_comparison() {
        let v1 = ProtocolEvolution::bitcoin_v1();
        let v2 = ProtocolEvolution::bitcoin_v2();

        assert!(v2.version > v1.version);
        assert_eq!(v1.version, 1);
        assert_eq!(v2.version, 2);
    }

    #[test]
    fn test_protocol_evolution_feature_sets() {
        let v1 = ProtocolEvolution::bitcoin_v1();
        let v2 = ProtocolEvolution::bitcoin_v2();

        // V2 should have all V1 features plus new ones
        for feature in &v1.enabled_features {
            assert!(v2.has_feature(feature));
        }

        // V2 should have additional features
        assert!(v2.enabled_features.len() > v1.enabled_features.len());

        // V1 should have no deprecated features
        assert!(v1.deprecated_features.is_empty());

        // V2 should have deprecated features
        assert!(!v2.deprecated_features.is_empty());
    }
}
