//! Protocol Variants Edge Cases Tests
//!
//! Edge cases and transition scenarios for protocol variants.

use blvm_protocol::ProtocolVersion;
use blvm_protocol::variants::{ProtocolEvolution, ProtocolVariant};

#[test]
fn test_all_variants_list() {
    // Test that all variants are returned
    let variants = ProtocolVariant::all_variants();

    assert_eq!(variants.len(), 4);
    assert!(
        variants
            .iter()
            .any(|v| v.version == ProtocolVersion::BitcoinV1)
    );
    assert!(
        variants
            .iter()
            .any(|v| v.version == ProtocolVersion::Testnet3)
    );
    assert!(
        variants
            .iter()
            .any(|v| v.version == ProtocolVersion::Signet)
    );
    assert!(
        variants
            .iter()
            .any(|v| v.version == ProtocolVersion::Regtest)
    );
}

#[test]
fn test_variant_for_version() {
    // Test getting variant by version
    let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1);
    assert!(mainnet.is_some());
    let mainnet_variant = mainnet.as_ref().unwrap();
    assert_eq!(mainnet_variant.version, ProtocolVersion::BitcoinV1);
    assert!(mainnet_variant.is_production);

    let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3);
    assert!(testnet.is_some());
    let testnet_variant = testnet.as_ref().unwrap();
    assert_eq!(testnet_variant.version, ProtocolVersion::Testnet3);
    assert!(!testnet_variant.is_production);

    let signet = ProtocolVariant::for_version(ProtocolVersion::Signet);
    assert!(signet.is_some());
    let signet_variant = signet.as_ref().unwrap();
    assert_eq!(signet_variant.version, ProtocolVersion::Signet);
    assert!(!signet_variant.is_production);

    let regtest = ProtocolVariant::for_version(ProtocolVersion::Regtest);
    assert!(regtest.is_some());
    let regtest_variant = regtest.as_ref().unwrap();
    assert_eq!(regtest_variant.version, ProtocolVersion::Regtest);
    assert!(!regtest_variant.is_production);
}

#[test]
fn test_variant_production_ready() {
    // Test production readiness checks
    let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
    assert!(mainnet.is_production_ready());

    let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();
    assert!(!testnet.is_production_ready());

    let signet = ProtocolVariant::for_version(ProtocolVersion::Signet).unwrap();
    assert!(!signet.is_production_ready());

    let regtest = ProtocolVariant::for_version(ProtocolVersion::Regtest).unwrap();
    assert!(!regtest.is_production_ready());
}

#[test]
fn test_variant_mining_support() {
    // Test mining support checks
    let variants = ProtocolVariant::all_variants();

    for variant in variants {
        assert!(variant.supports_mining_operations());
    }
}

#[test]
fn test_variant_wallet_support() {
    // Test wallet support checks
    let variants = ProtocolVariant::all_variants();

    for variant in variants {
        assert!(variant.supports_wallet_operations());
    }
}

#[test]
fn test_protocol_evolution_bitcoin_v1() {
    // Test Bitcoin V1 evolution structure
    let evolution = ProtocolEvolution::bitcoin_v1();

    assert_eq!(evolution.version, 1);
    assert!(
        evolution
            .enabled_features
            .contains(&"basic_transactions".to_string())
    );
    assert!(
        evolution
            .enabled_features
            .contains(&"proof_of_work".to_string())
    );
    assert!(evolution.deprecated_features.is_empty());
}

#[test]
fn test_protocol_evolution_future_version() {
    // Test future protocol version structure
    // bitcoin_v2() exists and represents a future version
    let evolution = ProtocolEvolution::bitcoin_v2();

    assert!(evolution.version > 1);
    assert!(!evolution.enabled_features.is_empty());
    assert!(
        evolution
            .deprecated_features
            .contains(&"legacy_addresses".to_string())
    );
}

#[test]
fn test_protocol_evolution_breaking_changes() {
    // Test breaking changes tracking
    let evolution = ProtocolEvolution::bitcoin_v2();

    // Future versions may have breaking changes
    // Just verify the field exists and can be checked
    let _has_breaking = !evolution.breaking_changes.is_empty();
    assert!(!evolution.breaking_changes.is_empty());
}

#[test]
fn test_variant_serialization() {
    // Test variant serialization/deserialization
    let mainnet = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();

    let json = serde_json::to_string(&mainnet).unwrap();
    let deserialized: ProtocolVariant = serde_json::from_str(&json).unwrap();

    assert_eq!(mainnet.version, deserialized.version);
    assert_eq!(mainnet.name, deserialized.name);
    assert_eq!(mainnet.is_production, deserialized.is_production);
}

#[test]
fn test_variant_equality() {
    // Test variant equality
    let mainnet1 = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
    let mainnet2 = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
    let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();

    assert_eq!(mainnet1, mainnet2);
    assert_ne!(mainnet1, testnet);
}

#[test]
fn test_protocol_version_transitions() {
    // Test protocol version transition scenarios
    let v1 = ProtocolVariant::for_version(ProtocolVersion::BitcoinV1).unwrap();
    let testnet = ProtocolVariant::for_version(ProtocolVersion::Testnet3).unwrap();

    // Both should support same operations
    assert_eq!(v1.supports_mining, testnet.supports_mining);
    assert_eq!(v1.supports_wallet, testnet.supports_wallet);

    // But have different production status
    assert_ne!(v1.is_production, testnet.is_production);
}

#[test]
fn test_variant_descriptions() {
    // Test variant descriptions are meaningful
    let variants = ProtocolVariant::all_variants();

    for variant in variants {
        assert!(!variant.description.is_empty());
        assert!(!variant.name.is_empty());
    }
}

#[test]
fn test_evolution_deprecated_features() {
    // Test deprecated features tracking
    let evolution = ProtocolEvolution::bitcoin_v2();

    // Future versions may deprecate features
    assert!(evolution.is_deprecated("legacy_addresses"));
    assert!(!evolution.is_deprecated("new_feature"));
}
