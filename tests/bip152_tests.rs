//! BIP152 Compact Block Relay Tests
//!
//! Comprehensive tests for BIP152 compact block relay protocol.
//! Tests cover SendCmpct negotiation, CmpctBlock reconstruction,
//! GetBlockTxn/BlockTxn transaction fetching, and edge cases.

use blvm_consensus::{Block, BlockHeader, Hash, Transaction, TransactionInput, TransactionOutput};
use blvm_protocol::network::{
    BlockTxnMessage, ChainStateAccess, CmpctBlockMessage, GetBlockTxnMessage, NetworkMessage,
    NetworkResponse, PeerState, PrefilledTransaction, SendCmpctMessage, process_network_message,
};
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Mock chain state for compact block testing
struct MockChainForCompactBlocks {
    blocks: HashMap<Hash, Block>,
}

impl MockChainForCompactBlocks {
    fn new() -> Self {
        Self {
            blocks: HashMap::new(),
        }
    }

    fn add_block(&mut self, hash: Hash, block: Block) {
        self.blocks.insert(hash, block);
    }
}

impl ChainStateAccess for MockChainForCompactBlocks {
    fn has_object(&self, hash: &Hash) -> bool {
        self.blocks.contains_key(hash)
    }

    fn get_object(&self, hash: &Hash) -> Option<blvm_protocol::network::ChainObject> {
        self.blocks
            .get(hash)
            .map(|b| blvm_protocol::network::ChainObject::Block(Arc::new(b.clone())))
    }

    fn get_headers_for_locator(&self, _locator: &[Hash], _stop: &Hash) -> Vec<BlockHeader> {
        vec![]
    }

    fn get_mempool_transactions(&self) -> Vec<Transaction> {
        vec![]
    }
}

fn create_test_engine() -> BitcoinProtocolEngine {
    BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap()
}

fn calculate_block_hash(header: &BlockHeader) -> Hash {
    use sha2::{Digest, Sha256};

    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(&(header.version as u32).to_le_bytes());
    bytes.extend_from_slice(&header.prev_block_hash);
    bytes.extend_from_slice(&header.merkle_root);
    bytes.extend_from_slice(&(header.timestamp as u32).to_le_bytes());
    bytes.extend_from_slice(&(header.bits as u32).to_le_bytes());
    bytes.extend_from_slice(&(header.nonce as u32).to_le_bytes());

    let first_hash = Sha256::digest(&bytes);
    let second_hash = Sha256::digest(&first_hash);

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&second_hash);
    hash
}

fn create_test_block_with_txs(tx_count: usize) -> (Hash, Block) {
    let mut transactions = Vec::new();

    // Coinbase transaction
    transactions.push(Transaction {
        version: 1,
        inputs: blvm_consensus::tx_inputs![TransactionInput {
            prevout: blvm_consensus::types::OutPoint {
                hash: [0u8; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x01, 0x00], // Height 0
            sequence: 0xffffffff,
        }],
        outputs: blvm_consensus::tx_outputs![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![blvm_consensus::opcodes::OP_1],
        }],
        lock_time: 0,
    });

    // Additional transactions
    for i in 0..tx_count {
        transactions.push(Transaction {
            version: 1,
            inputs: blvm_consensus::tx_inputs![TransactionInput {
                prevout: blvm_consensus::types::OutPoint {
                    hash: [i as u8; 32],
                    index: 0,
                },
                script_sig: vec![blvm_consensus::opcodes::PUSH_65_BYTES, 0x04],
                sequence: 0xffffffff,
            }],
            outputs: blvm_consensus::tx_outputs![TransactionOutput {
                value: 1000,
                script_pubkey: vec![blvm_consensus::opcodes::OP_1],
            }],
            lock_time: 0,
        });
    }

    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: transactions.into_boxed_slice(),
    };

    let hash = calculate_block_hash(&block.header);
    (hash, block)
}

// ============================================================================
// Phase 1: SendCmpct Negotiation Tests
// ============================================================================

#[test]
fn test_sendcmpct_version_1() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let sendcmpct = SendCmpctMessage {
        version: 1,
        prefer_cmpct: 1,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::SendCmpct(sendcmpct),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_sendcmpct_version_2() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let sendcmpct = SendCmpctMessage {
        version: 2,
        prefer_cmpct: 1,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::SendCmpct(sendcmpct),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_sendcmpct_invalid_version() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let sendcmpct = SendCmpctMessage {
        version: 3, // Invalid (must be 1 or 2)
        prefer_cmpct: 1,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::SendCmpct(sendcmpct),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Invalid compact block version"));
        }
        _ => panic!("Expected Reject for invalid version"),
    }
}

#[test]
fn test_sendcmpct_prefer_cmpct_zero() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let sendcmpct = SendCmpctMessage {
        version: 2,
        prefer_cmpct: 0, // Prefer full blocks
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::SendCmpct(sendcmpct),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

// ============================================================================
// Phase 2: CmpctBlock Message Tests
// ============================================================================

#[test]
fn test_cmpctblock_message_processing() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let cmpctblock = CmpctBlockMessage {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        nonce: 0,
        short_ids: vec![],
        prefilled_txs: vec![],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::CmpctBlock(cmpctblock),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should acknowledge (actual reconstruction would happen in full implementation)
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_cmpctblock_with_prefilled_txs() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let tx = Transaction {
        version: 1,
        inputs: blvm_consensus::tx_inputs![TransactionInput {
            prevout: blvm_consensus::types::OutPoint {
                hash: [0u8; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x01, 0x00],
            sequence: 0xffffffff,
        }],
        outputs: blvm_consensus::tx_outputs![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![blvm_consensus::opcodes::OP_1],
        }],
        lock_time: 0,
    };

    let cmpctblock = CmpctBlockMessage {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        nonce: 0,
        short_ids: vec![],
        prefilled_txs: vec![PrefilledTransaction {
            index: 0,
            tx,
            witness: None,
        }],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::CmpctBlock(cmpctblock),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

// ============================================================================
// Phase 3: GetBlockTxn/BlockTxn Tests
// ============================================================================

#[test]
fn test_getblocktxn_basic() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();
    let mut chain = MockChainForCompactBlocks::new();

    let (block_hash, block) = create_test_block_with_txs(5);
    chain.add_block(block_hash, block);

    let getblocktxn = GetBlockTxnMessage {
        block_hash,
        indices: vec![1, 2, 3], // Request transactions at indices 1, 2, 3
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBlockTxn(getblocktxn),
        &mut peer_state,
        Some(&chain),
        None,
        None,
    )
    .unwrap();

    match response {
        NetworkResponse::SendMessage(msg) => match *msg {
            NetworkMessage::BlockTxn(blocktxn) => {
                assert_eq!(blocktxn.block_hash, block_hash);
                assert_eq!(blocktxn.transactions.len(), 3);
            }
            _ => panic!("Expected BlockTxn message"),
        },
        _ => panic!("Expected SendMessage with BlockTxn"),
    }
}

#[test]
fn test_getblocktxn_too_many_indices() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let indices: Vec<u16> = (0..10001).collect(); // Exceeds protocol limit of 10000

    let getblocktxn = GetBlockTxnMessage {
        block_hash: [0u8; 32],
        indices,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBlockTxn(getblocktxn),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many transaction indices"));
        }
        _ => panic!("Expected Reject for too many indices"),
    }
}

#[test]
fn test_getblocktxn_invalid_block_hash() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();
    let chain = MockChainForCompactBlocks::new();

    let getblocktxn = GetBlockTxnMessage {
        block_hash: [0xff; 32], // Non-existent block
        indices: vec![1, 2],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBlockTxn(getblocktxn),
        &mut peer_state,
        Some(&chain),
        None,
        None,
    )
    .unwrap();

    // Should return Ok (no transactions found)
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_getblocktxn_out_of_bounds_indices() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();
    let mut chain = MockChainForCompactBlocks::new();

    let (block_hash, block) = create_test_block_with_txs(3); // Only 4 transactions total (1 coinbase + 3)
    chain.add_block(block_hash, block);

    let getblocktxn = GetBlockTxnMessage {
        block_hash,
        indices: vec![1, 2, 3, 4, 5], // Request indices beyond block size
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBlockTxn(getblocktxn),
        &mut peer_state,
        Some(&chain),
        None,
        None,
    )
    .unwrap();

    // Should return only valid transactions
    match response {
        NetworkResponse::SendMessage(msg) => {
            match *msg {
                NetworkMessage::BlockTxn(blocktxn) => {
                    // Should only have transactions at valid indices
                    assert!(blocktxn.transactions.len() <= 4);
                }
                _ => panic!("Expected BlockTxn message"),
            }
        }
        _ => panic!("Expected SendMessage with BlockTxn"),
    }
}

#[test]
fn test_blocktxn_message_processing() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let transactions = vec![Transaction {
        version: 1,
        inputs: blvm_consensus::tx_inputs![TransactionInput {
            prevout: blvm_consensus::types::OutPoint {
                hash: [0u8; 32],
                index: 0,
            },
            script_sig: vec![blvm_consensus::opcodes::PUSH_65_BYTES, 0x04],
            sequence: 0xffffffff,
        }],
        outputs: blvm_consensus::tx_outputs![TransactionOutput {
            value: 1000,
            script_pubkey: vec![blvm_consensus::opcodes::OP_1],
        }],
        lock_time: 0,
    }];

    let blocktxn = BlockTxnMessage {
        block_hash: [0u8; 32],
        transactions,
        witnesses: None,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::BlockTxn(blocktxn),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

// ============================================================================
// Phase 4: Compact Block Reconstruction Edge Cases
// ============================================================================

#[test]
fn test_cmpctblock_empty_short_ids() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();

    let cmpctblock = CmpctBlockMessage {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        nonce: 0,
        short_ids: vec![], // Empty short IDs (all transactions prefilled)
        prefilled_txs: vec![],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::CmpctBlock(cmpctblock),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_getblocktxn_empty_indices() {
    let engine = create_test_engine();
    let mut peer_state = PeerState::new();
    let chain = MockChainForCompactBlocks::new();

    let getblocktxn = GetBlockTxnMessage {
        block_hash: [0u8; 32],
        indices: vec![], // Empty indices
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBlockTxn(getblocktxn),
        &mut peer_state,
        Some(&chain),
        None,
        None,
    )
    .unwrap();

    // Should return Ok (no transactions requested)
    assert!(matches!(response, NetworkResponse::Ok));
}

// ============================================================================
// CompactBlock (bip152) <-> CmpctBlockMessage wire shape
// ============================================================================

#[test]
fn test_compact_block_to_cmpctblock_sorts_prefilled() {
    use blvm_protocol::bip152::CompactBlock;
    use std::convert::TryFrom;

    let tx = Transaction {
        version: 1,
        inputs: blvm_consensus::tx_inputs![TransactionInput {
            prevout: blvm_consensus::types::OutPoint {
                hash: [0u8; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x01, 0x00],
            sequence: 0xffffffff,
        }],
        outputs: blvm_consensus::tx_outputs![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![blvm_consensus::opcodes::OP_1],
        }],
        lock_time: 0,
    };

    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0u8; 32],
        merkle_root: [1u8; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    let cb = CompactBlock {
        header: header.clone(),
        nonce: 42,
        short_ids: vec![],
        prefilled_txs: vec![(2, tx.clone()), (0, tx.clone())],
    };

    let cmpct = CmpctBlockMessage::try_from(cb).unwrap();
    assert_eq!(cmpct.prefilled_txs[0].index, 0);
    assert_eq!(cmpct.prefilled_txs[1].index, 2);
    assert_eq!(cmpct.nonce, 42);

    let back = CompactBlock::from(&cmpct);
    assert_eq!(back.header, header);
    assert_eq!(back.nonce, 42);
    assert_eq!(back.prefilled_txs.len(), 2);
    assert_eq!(back.prefilled_txs[0].0, 0);
    assert_eq!(back.prefilled_txs[1].0, 2);
}

#[test]
fn test_compact_block_duplicate_prefilled_rejected() {
    use blvm_protocol::bip152::CompactBlock;
    use blvm_protocol::network::CompactBlockWireConvertError;
    use std::convert::TryFrom;

    let tx = Transaction {
        version: 1,
        inputs: blvm_consensus::tx_inputs![],
        outputs: blvm_consensus::tx_outputs![],
        lock_time: 0,
    };

    let cb = CompactBlock {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        nonce: 0,
        short_ids: vec![],
        prefilled_txs: vec![(1, tx.clone()), (1, tx)],
    };

    let err = CmpctBlockMessage::try_from(cb).unwrap_err();
    assert!(matches!(
        err,
        CompactBlockWireConvertError::DuplicatePrefilledIndex(1)
    ));
}

#[test]
fn test_compact_block_prefilled_index_u16_overflow() {
    use blvm_protocol::bip152::CompactBlock;
    use blvm_protocol::network::CompactBlockWireConvertError;
    use std::convert::TryFrom;

    let tx = Transaction {
        version: 1,
        inputs: blvm_consensus::tx_inputs![],
        outputs: blvm_consensus::tx_outputs![],
        lock_time: 0,
    };

    let cb = CompactBlock {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        nonce: 0,
        short_ids: vec![],
        prefilled_txs: vec![(65536, tx)],
    };

    let err = CmpctBlockMessage::try_from(cb).unwrap_err();
    assert!(matches!(
        err,
        CompactBlockWireConvertError::PrefilledIndexTooLarge(65536)
    ));
}
