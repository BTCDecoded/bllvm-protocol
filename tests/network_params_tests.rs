//! Network Parameters Tests
//!
//! Additional tests for network parameters and genesis blocks.
//! Note: Basic tests exist in src/network_params.rs, these complement them.

use blvm_protocol::ProtocolVersion;
use blvm_protocol::genesis::{mainnet_genesis, regtest_genesis, testnet_genesis};
use blvm_protocol::network_params::{Checkpoint, NetworkConstants};

// ============================================================================
// Phase 1: Genesis Block Tests
// ============================================================================

#[test]
fn test_genesis_blocks_are_different() {
    // Test that genesis blocks for all networks are different
    let mainnet_gen = mainnet_genesis();
    let testnet_gen = testnet_genesis();
    let regtest_gen = regtest_genesis();

    // Verify they're different (check timestamps - testnet and regtest have same timestamp, so check nonces)
    assert_ne!(mainnet_gen.header.timestamp, testnet_gen.header.timestamp);
    // Testnet and regtest have same timestamp, but different nonces
    assert_eq!(testnet_gen.header.timestamp, regtest_gen.header.timestamp);
    assert_ne!(mainnet_gen.header.nonce, testnet_gen.header.nonce);
    assert_ne!(testnet_gen.header.nonce, regtest_gen.header.nonce);
}

#[test]
fn test_genesis_blocks_have_coinbase() {
    // Test that all genesis blocks have coinbase transactions
    let mainnet_gen = mainnet_genesis();
    let testnet_gen = testnet_genesis();
    let regtest_gen = regtest_genesis();

    // All should have at least one transaction (coinbase)
    assert!(!mainnet_gen.transactions.is_empty());
    assert!(!testnet_gen.transactions.is_empty());
    assert!(!regtest_gen.transactions.is_empty());
}

#[test]
fn test_genesis_block_timestamps() {
    // Test genesis block timestamps
    let mainnet_gen = mainnet_genesis();
    let testnet_gen = testnet_genesis();
    let regtest_gen = regtest_genesis();

    // Mainnet genesis: Jan 3, 2009
    assert_eq!(mainnet_gen.header.timestamp, 1231006505);

    // Testnet and regtest should have different timestamps
    assert_ne!(mainnet_gen.header.timestamp, testnet_gen.header.timestamp);
    assert_ne!(mainnet_gen.header.timestamp, regtest_gen.header.timestamp);
}

// ============================================================================
// Phase 2: Network Constants Integration Tests
// ============================================================================

#[test]
fn test_network_constants_consistency() {
    // Test that network constants are consistent
    let mainnet = NetworkConstants::mainnet().unwrap();
    let testnet = NetworkConstants::testnet().unwrap();
    let regtest = NetworkConstants::regtest().unwrap();

    // All should have valid magic bytes
    assert_ne!(mainnet.magic_bytes, [0u8; 4]);
    assert_ne!(testnet.magic_bytes, [0u8; 4]);
    assert_ne!(regtest.magic_bytes, [0u8; 4]);

    // All should have valid ports
    assert!(mainnet.default_port > 0);
    assert!(testnet.default_port > 0);
    assert!(regtest.default_port > 0);
}

#[test]
fn test_network_constants_for_all_versions() {
    // Test that we can get constants for all protocol versions
    let mainnet = NetworkConstants::for_version(ProtocolVersion::BitcoinV1).unwrap();
    let testnet = NetworkConstants::for_version(ProtocolVersion::Testnet3).unwrap();
    let regtest = NetworkConstants::for_version(ProtocolVersion::Regtest).unwrap();

    assert_eq!(mainnet.network_name, "mainnet");
    assert_eq!(testnet.network_name, "testnet");
    assert_eq!(regtest.network_name, "regtest");
}

// ============================================================================
// Phase 3: Checkpoint Tests
// ============================================================================

#[test]
fn test_checkpoint_structure() {
    // Test checkpoint structure
    let checkpoint = Checkpoint {
        height: 11111,
        hash: [0x01; 32],
        timestamp: 1231006505,
    };

    assert_eq!(checkpoint.height, 11111);
    assert_eq!(checkpoint.hash, [0x01; 32]);
    assert_eq!(checkpoint.timestamp, 1231006505);
}

#[test]
fn test_checkpoint_validation() {
    // Test checkpoint validation (basic structure checks)
    let checkpoint = Checkpoint {
        height: 11111,
        hash: [
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        timestamp: 1231006505,
    };

    // Verify checkpoint has valid structure
    assert!(checkpoint.height > 0);
    assert_ne!(checkpoint.hash, [0u8; 32]);
    assert!(checkpoint.timestamp > 0);
}
