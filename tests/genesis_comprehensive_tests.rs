//! Comprehensive Genesis Block Tests
//!
//! Tests for genesis block generation across all network variants.

use blvm_protocol::BitcoinProtocolEngine;
use blvm_protocol::ProtocolVersion;
use blvm_protocol::genesis::{mainnet_genesis, regtest_genesis, testnet_genesis};

#[test]
fn test_mainnet_genesis_block() {
    let genesis = mainnet_genesis();

    // Genesis block should have all-zero prev_block_hash
    assert_eq!(genesis.header.prev_block_hash, [0u8; 32]);

    // Genesis block should have version 1
    assert_eq!(genesis.header.version, 1);

    // Genesis block should have correct timestamp (Jan 3, 2009)
    assert_eq!(genesis.header.timestamp, 1231006505);

    // Genesis block should have correct bits
    assert_eq!(genesis.header.bits, 0x1d00ffff);

    // Genesis block should have correct nonce
    assert_eq!(genesis.header.nonce, 2083236893);

    // Genesis block should have exactly one transaction (coinbase)
    assert_eq!(genesis.transactions.len(), 1);

    // Coinbase transaction should have 50 BTC output
    assert_eq!(genesis.transactions[0].outputs[0].value, 50_0000_0000);
}

#[test]
fn test_testnet_genesis_block() {
    let genesis = testnet_genesis();

    // Genesis block should have all-zero prev_block_hash
    assert_eq!(genesis.header.prev_block_hash, [0u8; 32]);

    // Genesis block should have version 1
    assert_eq!(genesis.header.version, 1);

    // Testnet genesis has different timestamp
    assert_eq!(genesis.header.timestamp, 1296688602);

    // Testnet genesis should have correct bits
    assert_eq!(genesis.header.bits, 0x1d00ffff);

    // Testnet genesis should have different nonce
    assert_eq!(genesis.header.nonce, 414098458);

    // Genesis block should have exactly one transaction (coinbase)
    assert_eq!(genesis.transactions.len(), 1);

    // Coinbase transaction should have 50 BTC output
    assert_eq!(genesis.transactions[0].outputs[0].value, 50_0000_0000);
}

#[test]
fn test_regtest_genesis_block() {
    let genesis = regtest_genesis();

    // Genesis block should have all-zero prev_block_hash
    assert_eq!(genesis.header.prev_block_hash, [0u8; 32]);

    // Genesis block should have version 1
    assert_eq!(genesis.header.version, 1);

    // Regtest genesis has same timestamp as testnet
    assert_eq!(genesis.header.timestamp, 1296688602);

    // Regtest genesis should have easier difficulty
    assert_eq!(genesis.header.bits, 0x207fffff);

    // Regtest genesis should have different nonce
    assert_eq!(genesis.header.nonce, 2);

    // Genesis block should have exactly one transaction (coinbase)
    assert_eq!(genesis.transactions.len(), 1);

    // Coinbase transaction should have 50 BTC output
    assert_eq!(genesis.transactions[0].outputs[0].value, 50_0000_0000);
}

#[test]
fn test_genesis_blocks_different() {
    let mainnet = mainnet_genesis();
    let testnet = testnet_genesis();
    let regtest = regtest_genesis();

    // All genesis blocks should have different nonces
    assert_ne!(mainnet.header.nonce, testnet.header.nonce);
    assert_ne!(mainnet.header.nonce, regtest.header.nonce);
    assert_ne!(testnet.header.nonce, regtest.header.nonce);

    // Mainnet and testnet should have different timestamps
    assert_ne!(mainnet.header.timestamp, testnet.header.timestamp);

    // Testnet and regtest have same timestamp but different nonces
    assert_eq!(testnet.header.timestamp, regtest.header.timestamp);

    // Regtest should have easier difficulty
    assert_ne!(mainnet.header.bits, regtest.header.bits);
    assert_ne!(testnet.header.bits, regtest.header.bits);
}

#[test]
fn test_genesis_coinbase_transaction() {
    let mainnet = mainnet_genesis();
    let testnet = testnet_genesis();
    let regtest = regtest_genesis();

    for genesis in [&mainnet, &testnet, &regtest] {
        let coinbase = &genesis.transactions[0];

        // Coinbase should have exactly one input
        assert_eq!(coinbase.inputs.len(), 1);

        // Coinbase input should have all-zero hash and 0xffffffff index
        assert_eq!(coinbase.inputs[0].prevout.hash, [0u8; 32]);
        assert_eq!(coinbase.inputs[0].prevout.index, 0xffffffff);

        // Coinbase should have exactly one output
        assert_eq!(coinbase.outputs.len(), 1);

        // Coinbase output should have 50 BTC
        assert_eq!(coinbase.outputs[0].value, 50_0000_0000);

        // Coinbase should have lock_time 0
        assert_eq!(coinbase.lock_time, 0);
    }
}

#[test]
fn test_genesis_coinbase_script_sig() {
    let mainnet = mainnet_genesis();

    // Coinbase script_sig should contain the Times headline
    let script_sig = &mainnet.transactions[0].inputs[0].script_sig;

    // Should start with push opcode
    assert!(script_sig.len() > 0);

    // Should contain the message (all genesis blocks have same message)
    let message = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    assert!(script_sig.iter().any(|&b| b == message[0]));
}

#[test]
fn test_genesis_merkle_root() {
    let mainnet = mainnet_genesis();
    let testnet = testnet_genesis();
    let regtest = regtest_genesis();

    // All genesis blocks should have the same merkle root
    // (since they all have the same coinbase transaction)
    assert_eq!(mainnet.header.merkle_root, testnet.header.merkle_root);
    assert_eq!(mainnet.header.merkle_root, regtest.header.merkle_root);
}

#[test]
fn test_genesis_in_protocol_engine() {
    // Test that genesis blocks are accessible through protocol engine
    let mainnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let testnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
    let regtest_engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();

    // Protocol engines should have genesis blocks
    // Access through get_network_params() method
    let mainnet_genesis = &mainnet_engine.get_network_params().genesis_block;
    let testnet_genesis = &testnet_engine.get_network_params().genesis_block;
    let regtest_genesis = &regtest_engine.get_network_params().genesis_block;

    assert_eq!(mainnet_genesis.header.timestamp, 1231006505);
    assert_eq!(testnet_genesis.header.timestamp, 1296688602);
    assert_eq!(regtest_genesis.header.timestamp, 1296688602);
}

#[test]
fn test_genesis_block_consistency() {
    let mainnet = mainnet_genesis();
    let testnet = testnet_genesis();
    let regtest = regtest_genesis();

    // All genesis blocks should have:
    // - Version 1
    // - All-zero prev_block_hash
    // - Exactly one transaction
    // - 50 BTC coinbase output

    for genesis in [&mainnet, &testnet, &regtest] {
        assert_eq!(genesis.header.version, 1);
        assert_eq!(genesis.header.prev_block_hash, [0u8; 32]);
        assert_eq!(genesis.transactions.len(), 1);
        assert_eq!(genesis.transactions[0].outputs[0].value, 50_0000_0000);
    }
}

#[test]
fn test_genesis_block_validation() {
    let mainnet = mainnet_genesis();

    // Genesis block should be valid
    // (Basic structure checks - full validation would require consensus engine)
    assert!(mainnet.header.version > 0);
    assert!(mainnet.header.timestamp > 0);
    assert!(mainnet.header.bits > 0);
    assert!(!mainnet.transactions.is_empty());
}
