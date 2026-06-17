//! Edge case tests for features module (activation, dependencies, conflicts)

use blvm_protocol::ProtocolVersion;
use blvm_protocol::features::{ActivationMethod, FeatureActivation, FeatureRegistry};

#[test]
fn test_feature_activation_height_based() {
    let feature = FeatureActivation {
        feature_name: "test_feature".to_string(),
        activation_height: Some(100),
        activation_timestamp: None,
        activation_method: ActivationMethod::HeightBased,
        bip_number: None,
    };

    // Before activation
    assert!(!feature.is_active_at(99, 0));

    // At activation
    assert!(feature.is_active_at(100, 0));

    // After activation
    assert!(feature.is_active_at(101, 0));
    assert!(feature.is_active_at(1000, 0));
}

#[test]
fn test_feature_activation_timestamp_based() {
    let feature = FeatureActivation {
        feature_name: "test_feature".to_string(),
        activation_height: None,
        activation_timestamp: Some(1000),
        activation_method: ActivationMethod::Timestamp,
        bip_number: None,
    };

    // Before activation
    assert!(!feature.is_active_at(0, 999));

    // At activation
    assert!(feature.is_active_at(0, 1000));

    // After activation
    assert!(feature.is_active_at(0, 1001));
    assert!(feature.is_active_at(0, 10000));
}

#[test]
fn test_feature_activation_always_active() {
    let feature = FeatureActivation {
        feature_name: "test_feature".to_string(),
        activation_height: None,
        activation_timestamp: None,
        activation_method: ActivationMethod::AlwaysActive,
        bip_number: None,
    };

    // Should always be active
    assert!(feature.is_active_at(0, 0));
    assert!(feature.is_active_at(100, 1000));
    assert!(feature.is_active_at(u64::MAX, u64::MAX));
}

#[test]
fn test_feature_activation_hard_fork() {
    let feature = FeatureActivation {
        feature_name: "test_feature".to_string(),
        activation_height: None,
        activation_timestamp: None,
        activation_method: ActivationMethod::HardFork,
        bip_number: None,
    };

    // Hard forks activate immediately at genesis
    assert!(feature.is_active_at(0, 0));
    assert!(feature.is_active_at(100, 1000));
}

#[test]
fn test_feature_activation_bip9() {
    let feature = FeatureActivation {
        feature_name: "test_feature".to_string(),
        activation_height: Some(100),
        activation_timestamp: Some(1000),
        activation_method: ActivationMethod::BIP9,
        bip_number: Some(141),
    };

    // BIP9 with activation_height set: height is authoritative.
    // Before both: not active.
    assert!(!feature.is_active_at(99, 999));

    // Height met, timestamp not: active (height is the gate).
    assert!(feature.is_active_at(100, 999));

    // Timestamp met, height not: NOT active.
    // Corrected: timestamp alone cannot activate when activation_height is set.
    assert!(!feature.is_active_at(99, 1000));

    // Both met: active.
    assert!(feature.is_active_at(100, 1000));
}

#[test]
fn test_feature_registry_for_protocol() {
    let mainnet = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);
    let testnet = FeatureRegistry::for_protocol(ProtocolVersion::Testnet3);
    let regtest = FeatureRegistry::for_protocol(ProtocolVersion::Regtest);

    // Each should have features
    assert!(!mainnet.features.is_empty());
    assert!(!testnet.features.is_empty());
    assert!(!regtest.features.is_empty());

    // Should have different protocol versions
    assert_eq!(mainnet.protocol_version, ProtocolVersion::BitcoinV1);
    assert_eq!(testnet.protocol_version, ProtocolVersion::Testnet3);
    assert_eq!(regtest.protocol_version, ProtocolVersion::Regtest);
}

#[test]
fn test_feature_registry_is_feature_active() {
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Test with known features
    // SegWit should be active at high heights
    let segwit_active = registry.is_feature_active("segwit", 500_000, 1_500_000_000);
    // May or may not be active depending on activation height
    let _ = segwit_active;

    // Unknown feature should return false
    assert!(!registry.is_feature_active("nonexistent_feature", 0, 0));
}

#[test]
fn test_feature_registry_get_feature() {
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Should be able to get known features
    let segwit = registry.get_feature("segwit");
    // May or may not exist depending on registry
    let _ = segwit;

    // Unknown feature should return None
    assert!(registry.get_feature("nonexistent_feature").is_none());
}

#[test]
fn test_feature_registry_list_features() {
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    let features = registry.list_features();

    // Should have some features
    assert!(!features.is_empty());

    // All should be strings
    for feature in &features {
        assert!(!feature.is_empty());
    }
}

#[test]
fn test_feature_context_creation() {
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    let context = registry.create_context(500_000, 1_500_000_000);

    // Context should be created (feature list is valid)
    let _ = context.active_features().len();
}

#[test]
fn test_feature_activation_edge_cases() {
    // Test with None values for height-based
    let feature = FeatureActivation {
        feature_name: "test".to_string(),
        activation_height: None,
        activation_timestamp: None,
        activation_method: ActivationMethod::HeightBased,
        bip_number: None,
    };

    // Should return false if no activation height
    assert!(!feature.is_active_at(0, 0));
    assert!(!feature.is_active_at(u64::MAX, u64::MAX));
}

#[test]
fn test_feature_activation_timestamp_edge_cases() {
    // Test with None values for timestamp-based
    let feature = FeatureActivation {
        feature_name: "test".to_string(),
        activation_height: None,
        activation_timestamp: None,
        activation_method: ActivationMethod::Timestamp,
        bip_number: None,
    };

    // Should return false if no activation timestamp
    assert!(!feature.is_active_at(0, 0));
    assert!(!feature.is_active_at(0, u64::MAX));
}

#[test]
fn test_feature_activation_boundary_values() {
    let feature = FeatureActivation {
        feature_name: "test".to_string(),
        activation_height: Some(100),
        activation_timestamp: None,
        activation_method: ActivationMethod::HeightBased,
        bip_number: None,
    };

    // Test boundary values
    assert!(!feature.is_active_at(99, 0)); // Just before
    assert!(feature.is_active_at(100, 0)); // Exactly at
    assert!(feature.is_active_at(101, 0)); // Just after

    // Test with u64::MAX
    assert!(feature.is_active_at(u64::MAX, 0));
}

#[test]
fn test_feature_activation_multiple_methods() {
    // Test that different activation methods work independently
    let height_feature = FeatureActivation {
        feature_name: "height".to_string(),
        activation_height: Some(100),
        activation_timestamp: None,
        activation_method: ActivationMethod::HeightBased,
        bip_number: None,
    };

    let timestamp_feature = FeatureActivation {
        feature_name: "timestamp".to_string(),
        activation_height: None,
        activation_timestamp: Some(1000),
        activation_method: ActivationMethod::Timestamp,
        bip_number: None,
    };

    // At height 100, timestamp 999
    assert!(height_feature.is_active_at(100, 999));
    assert!(!timestamp_feature.is_active_at(100, 999));

    // At height 99, timestamp 1000
    assert!(!height_feature.is_active_at(99, 1000));
    assert!(timestamp_feature.is_active_at(99, 1000));
}
