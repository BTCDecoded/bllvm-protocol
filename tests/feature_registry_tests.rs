//! Feature Registry Tests
//!
//! Tests for feature activation tracking and protocol version compatibility.

use blvm_consensus::{SEGWIT_ACTIVATION_MAINNET, TAPROOT_ACTIVATION_MAINNET};
use blvm_protocol::ProtocolVersion;
use blvm_protocol::features::{
    ActivationMethod, FeatureActivation, FeatureContext, FeatureRegistry,
};

/// Test helper: Create a SegWit feature activation
fn create_segwit_activation() -> FeatureActivation {
    FeatureActivation {
        feature_name: "segwit".to_string(),
        activation_height: Some(SEGWIT_ACTIVATION_MAINNET), // BIP141 / buried deployment (mainnet)
        activation_timestamp: Some(1503539857),             // SegWit activation timestamp
        activation_method: ActivationMethod::BIP9,
        bip_number: Some(141),
    }
}

/// Test helper: Create a Taproot feature activation
fn create_taproot_activation() -> FeatureActivation {
    FeatureActivation {
        feature_name: "taproot".to_string(),
        activation_height: Some(TAPROOT_ACTIVATION_MAINNET), // BIP341 (mainnet)
        activation_timestamp: Some(1638316800),              // Taproot activation timestamp
        activation_method: ActivationMethod::BIP9,
        bip_number: Some(341),
    }
}

/// Test helper: Create a feature context from registry
fn create_feature_context(
    registry: &FeatureRegistry,
    height: u64,
    timestamp: u64,
) -> FeatureContext {
    FeatureContext::from_registry(registry, height, timestamp)
}

// ============================================================================
// Phase 1: FeatureRegistry Creation Tests
// ============================================================================

#[test]
fn test_feature_registry_creation() {
    // Test creating a feature registry
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Should have features registered
    assert!(!registry.features.is_empty());
}

#[test]
fn test_feature_registry_for_different_protocols() {
    // Test feature registry for different protocol versions
    let mainnet = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);
    let testnet = FeatureRegistry::for_protocol(ProtocolVersion::Testnet3);
    let regtest = FeatureRegistry::for_protocol(ProtocolVersion::Regtest);

    // All should have features
    assert!(!mainnet.features.is_empty());
    assert!(!testnet.features.is_empty());
    assert!(!regtest.features.is_empty());
}

// ============================================================================
// Phase 2: Feature Activation Tests
// ============================================================================

#[test]
fn test_feature_activation_check_segwit() {
    // Test checking if SegWit is active
    let activation = create_segwit_activation();
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Before activation
    let before_context =
        create_feature_context(&registry, SEGWIT_ACTIVATION_MAINNET - 1, 1503539856);
    assert!(!activation.is_active_at(before_context.height, before_context.timestamp));

    // At activation height
    let at_context = create_feature_context(&registry, SEGWIT_ACTIVATION_MAINNET, 1503539857);
    assert!(activation.is_active_at(at_context.height, at_context.timestamp));

    // After activation
    let after_context =
        create_feature_context(&registry, SEGWIT_ACTIVATION_MAINNET + 1, 1503539858);
    assert!(activation.is_active_at(after_context.height, after_context.timestamp));
}

#[test]
fn test_feature_activation_check_taproot() {
    // Test checking if Taproot is active
    let activation = create_taproot_activation();
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Before activation
    let before_context =
        create_feature_context(&registry, TAPROOT_ACTIVATION_MAINNET - 1, 1638316799);
    assert!(!activation.is_active_at(before_context.height, before_context.timestamp));

    // At activation
    let at_context = create_feature_context(&registry, TAPROOT_ACTIVATION_MAINNET, 1638316800);
    assert!(activation.is_active_at(at_context.height, at_context.timestamp));
}

#[test]
fn test_feature_activation_always_active() {
    // Test AlwaysActive activation method
    let activation = FeatureActivation {
        feature_name: "always_on".to_string(),
        activation_height: None,
        activation_timestamp: None,
        activation_method: ActivationMethod::AlwaysActive,
        bip_number: None,
    };

    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);
    let context = create_feature_context(&registry, 0, 0);
    assert!(activation.is_active_at(context.height, context.timestamp));
}

#[test]
fn test_feature_activation_hard_fork() {
    // Test HardFork activation method
    let activation = FeatureActivation {
        feature_name: "hardfork".to_string(),
        activation_height: None,
        activation_timestamp: None,
        activation_method: ActivationMethod::HardFork,
        bip_number: None,
    };

    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);
    let context = create_feature_context(&registry, 0, 0);
    // Hard forks activate immediately at genesis
    assert!(activation.is_active_at(context.height, context.timestamp));
}

#[test]
fn test_feature_activation_height_based() {
    // Test HeightBased activation method
    let activation = FeatureActivation {
        feature_name: "height_based".to_string(),
        activation_height: Some(1000),
        activation_timestamp: None,
        activation_method: ActivationMethod::HeightBased,
        bip_number: None,
    };

    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Before activation height
    let before = create_feature_context(&registry, 999, 0);
    assert!(!activation.is_active_at(before.height, before.timestamp));

    // At activation height
    let at = create_feature_context(&registry, 1000, 0);
    assert!(activation.is_active_at(at.height, at.timestamp));

    // After activation height
    let after = create_feature_context(&registry, 1001, 0);
    assert!(activation.is_active_at(after.height, after.timestamp));
}

#[test]
fn test_feature_activation_timestamp_based() {
    // Test Timestamp activation method
    let activation = FeatureActivation {
        feature_name: "timestamp_based".to_string(),
        activation_height: None,
        activation_timestamp: Some(1000000000),
        activation_method: ActivationMethod::Timestamp,
        bip_number: None,
    };

    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Before activation timestamp
    let before = create_feature_context(&registry, 0, 999999999);
    assert!(!activation.is_active_at(before.height, before.timestamp));

    // At activation timestamp
    let at = create_feature_context(&registry, 0, 1000000000);
    assert!(activation.is_active_at(at.height, at.timestamp));

    // After activation timestamp
    let after = create_feature_context(&registry, 0, 1000000001);
    assert!(activation.is_active_at(after.height, after.timestamp));
}

#[test]
fn test_feature_activation_bip9() {
    // Test BIP9 activation method (uses both height and timestamp)
    let activation = create_segwit_activation();

    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // BIP9 with activation_height set: height is authoritative.
    // Before both: not active.
    let before = create_feature_context(&registry, SEGWIT_ACTIVATION_MAINNET - 1, 1503539856);
    assert!(!activation.is_active_at(before.height, before.timestamp));

    // At height but before timestamp: active (height is the gate).
    let height_met = create_feature_context(&registry, SEGWIT_ACTIVATION_MAINNET, 1503539856);
    assert!(activation.is_active_at(height_met.height, height_met.timestamp));

    // At timestamp but before height: NOT active.
    // Corrected behaviour: timestamp alone cannot activate a BIP9 feature
    // that has an explicit activation_height configured.
    let timestamp_met =
        create_feature_context(&registry, SEGWIT_ACTIVATION_MAINNET - 1, 1503539857);
    assert!(!activation.is_active_at(timestamp_met.height, timestamp_met.timestamp));
}

// ============================================================================
// Phase 3: Feature Registry Lookup Tests
// ============================================================================

#[test]
fn test_feature_registry_contains_segwit() {
    // Test that mainnet registry contains SegWit
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    let segwit = registry.get_feature("segwit");
    assert!(segwit.is_some());
    assert_eq!(segwit.unwrap().feature_name, "segwit");
}

#[test]
fn test_feature_registry_contains_taproot() {
    // Test that mainnet registry contains Taproot
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    let taproot = registry.get_feature("taproot");
    assert!(taproot.is_some());
    assert_eq!(taproot.unwrap().feature_name, "taproot");
}

#[test]
fn test_feature_registry_multiple_features() {
    // Test that registry contains multiple features
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Should have multiple features registered
    let features = registry.list_features();
    assert!(features.len() >= 2);

    // Check for common features
    assert!(features.contains(&"segwit".to_string()));
    assert!(features.contains(&"taproot".to_string()));
}

// ============================================================================
// Phase 4: Feature Context Tests
// ============================================================================

#[test]
fn test_feature_context_creation() {
    // Test creating a feature context
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);
    let context = create_feature_context(&registry, 100000, 1234567890);

    assert_eq!(context.height, 100000);
    assert_eq!(context.timestamp, 1234567890);
}

#[test]
fn test_feature_context_different_protocols() {
    // Test feature context with different protocol versions
    let mainnet_registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);
    let testnet_registry = FeatureRegistry::for_protocol(ProtocolVersion::Testnet3);

    let mainnet_context = create_feature_context(&mainnet_registry, 100000, 1234567890);
    let testnet_context = create_feature_context(&testnet_registry, 100000, 1234567890);

    // Contexts should have same height/timestamp but may have different feature states
    assert_eq!(mainnet_context.height, testnet_context.height);
    assert_eq!(mainnet_context.timestamp, testnet_context.timestamp);
}

// ============================================================================
// Phase 5: Activation Method Tests
// ============================================================================

#[test]
fn test_activation_method_variants() {
    // Test all activation method variants exist
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // Check different activation methods are used
    let segwit = registry.get_feature("segwit").unwrap();
    assert_eq!(segwit.activation_method, ActivationMethod::BIP9);

    let rbf = registry.get_feature("rbf").unwrap();
    assert_eq!(rbf.activation_method, ActivationMethod::AlwaysActive);
}

#[test]
fn test_activation_method_usage() {
    // Test that different activation methods work correctly
    let registry = FeatureRegistry::for_protocol(ProtocolVersion::BitcoinV1);

    // BIP9 feature (SegWit)
    let segwit = registry.get_feature("segwit").unwrap();
    assert_eq!(segwit.activation_method, ActivationMethod::BIP9);

    // AlwaysActive feature (RBF)
    let rbf = registry.get_feature("rbf").unwrap();
    assert_eq!(rbf.activation_method, ActivationMethod::AlwaysActive);

    // Verify they activate differently
    assert!(!registry.is_feature_active("segwit", 0, 0));
    assert!(registry.is_feature_active("rbf", 0, 0));
}
