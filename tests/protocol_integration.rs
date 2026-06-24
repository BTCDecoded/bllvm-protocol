//! Protocol integration tests
//!
//! End-to-end tests for protocol engine functionality

use blvm_consensus::opcodes::OP_1;
use blvm_consensus::types::{Hash, OutPoint, TransactionInput, TransactionOutput, UTXO, UtxoSet};
use blvm_consensus::utxo_set_insert;
use blvm_consensus::{Block, BlockHeader, Transaction, segwit::Witness};
use blvm_protocol::validation::ProtocolValidationContext;
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion, ValidationResult};

fn block_hash(header: &BlockHeader) -> Hash {
    use blvm_consensus::serialization::block::serialize_block_header;
    blvm_consensus::crypto::OptimizedSha256::new().hash256(&serialize_block_header(header))
}

fn coinbase_script_sig(height: u64) -> Vec<u8> {
    let mut height_bytes = height.to_le_bytes().to_vec();
    while height_bytes.last() == Some(&0) && height_bytes.len() > 1 {
        height_bytes.pop();
    }
    let mut script_sig = vec![height_bytes.len() as u8];
    script_sig.extend(height_bytes);
    if script_sig.len() < 2 {
        script_sig = vec![0x01, 0x00];
    }
    script_sig
}

fn regtest_coinbase_block(prev_hash: Hash, height: u64) -> Block {
    let coinbase = Transaction {
        version: 2,
        inputs: blvm_consensus::tx_inputs![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0xffffffff,
            },
            script_sig: coinbase_script_sig(height),
            sequence: 0xffffffff,
        }],
        outputs: blvm_consensus::tx_outputs![TransactionOutput {
            value: 5_000_000_000,
            script_pubkey: vec![OP_1],
        }],
        lock_time: 0,
    };
    let merkle_root =
        blvm_consensus::mining::calculate_merkle_root(std::slice::from_ref(&coinbase))
            .expect("merkle root");
    Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: 1_231_006_505 + height * 600,
            bits: 0x0300ffff,
            nonce: height,
        },
        transactions: vec![coinbase].into_boxed_slice(),
    }
}

fn witnesses_for(block: &Block) -> Vec<Vec<Witness>> {
    block
        .transactions
        .iter()
        .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
        .collect()
}

fn connect_regtest_block(
    engine: &BitcoinProtocolEngine,
    block: &Block,
    utxos: &UtxoSet,
    height: u64,
) -> (ValidationResult, UtxoSet) {
    let mut context = ProtocolValidationContext::new(ProtocolVersion::Regtest, height).unwrap();
    context.network_time = block.header.timestamp;
    context.median_time_past = block.header.timestamp;
    let witnesses = witnesses_for(block);
    engine
        .validate_and_connect_block(block, &witnesses, utxos, height, None, &context)
        .unwrap()
}

#[test]
fn test_end_to_end_blvm_protocol_initialization() {
    // Test that we can create engines for all protocol versions
    let mainnet = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let testnet = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
    let regtest = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();

    // Verify they have correct network parameters
    assert_eq!(mainnet.get_network_params().network_name, "mainnet");
    assert_eq!(testnet.get_network_params().network_name, "testnet");
    assert_eq!(regtest.get_network_params().network_name, "regtest");

    // Verify they support the same features
    assert!(mainnet.supports_feature("segwit"));
    assert!(testnet.supports_feature("segwit"));
    assert!(regtest.supports_feature("segwit"));
}

#[test]
fn test_full_block_validation_workflow() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
    let utxos = UtxoSet::default();
    let block = regtest_coinbase_block([0u8; 32], 0);

    let (result, new_utxos) = connect_regtest_block(&engine, &block, &utxos, 0);
    assert_eq!(result, ValidationResult::Valid);
    assert!(!new_utxos.is_empty());
}

#[test]
fn test_multi_block_chain_validation() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
    let mut utxos = UtxoSet::default();

    let block1 = regtest_coinbase_block([0u8; 32], 0);
    let (result1, utxos) = connect_regtest_block(&engine, &block1, &utxos, 0);
    assert_eq!(result1, ValidationResult::Valid);

    let prev = block_hash(&block1.header);
    let block2 = regtest_coinbase_block(prev, 1);
    let (result2, _) = connect_regtest_block(&engine, &block2, &utxos, 1);
    assert_eq!(result2, ValidationResult::Valid);
}

#[test]
fn test_transaction_creation_and_validation_workflow() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();

    // Create a transaction
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0,
            },
            script_sig: vec![0x41, 0x04], // Signature
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

    // Structural validation only (no UTXO/script execution in this API).
    let result = engine
        .validate_transaction(&tx)
        .expect("validate_transaction");
    assert_eq!(result, ValidationResult::Valid);
}

#[test]
fn test_utxo_tracking_across_transactions() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let mut utxos = UtxoSet::default();

    // Add initial UTXO
    utxo_set_insert(
        &mut utxos,
        OutPoint {
            hash: [0u8; 32],
            index: 0,
        },
        UTXO {
            value: 100_0000_0000,
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
            ]
            .into(),
            height: 0,
            is_coinbase: false,
        },
    );

    // Create transaction that spends the UTXO
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0,
            },
            script_sig: vec![0x41, 0x04], // Signature
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![
            TransactionOutput {
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
            },
            TransactionOutput {
                value: 49_0000_0000, // Change output
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
            },
        ]
        .into(),
        lock_time: 0,
    };

    // Structural validation only (no UTXO/script execution in this API).
    let result = engine
        .validate_transaction(&tx)
        .expect("validate_transaction");
    assert_eq!(result, ValidationResult::Valid);
}

#[test]
fn test_connect_rejects_invalid_merkle_root() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
    let mut block = regtest_coinbase_block([0u8; 32], 0);
    block.header.merkle_root = [0xff; 32];

    let utxos = UtxoSet::default();
    let (result, _) = connect_regtest_block(&engine, &block, &utxos, 0);
    assert!(
        matches!(result, ValidationResult::Invalid(_)),
        "bad merkle root must not connect as Valid"
    );
}

#[test]
fn test_protocol_switching_scenarios() {
    // Test that we can create engines for different protocols
    let mainnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let testnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
    let regtest_engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();

    // All engines should support the same basic features
    assert!(mainnet_engine.supports_feature("segwit"));
    assert!(testnet_engine.supports_feature("segwit"));
    assert!(regtest_engine.supports_feature("segwit"));

    // But they should have different network parameters
    assert_ne!(
        mainnet_engine.get_network_params().magic_bytes,
        testnet_engine.get_network_params().magic_bytes
    );
    assert_ne!(
        testnet_engine.get_network_params().magic_bytes,
        regtest_engine.get_network_params().magic_bytes
    );
}

#[test]
fn test_concurrent_validation_requests() {
    use std::sync::Arc;
    use std::thread;

    let engine = Arc::new(BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap());
    let mut handles = vec![];

    // Create multiple threads that validate the same transaction
    for i in 0..5 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let tx = Transaction {
                version: 1,
                inputs: vec![TransactionInput {
                    prevout: OutPoint {
                        hash: [i as u8; 32],
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

            engine_clone.validate_transaction(&tx)
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let result = handle.join().unwrap().expect("validate_transaction");
        assert_eq!(result, ValidationResult::Valid);
    }
}
