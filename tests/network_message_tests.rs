//! Tests for network message processing
//!
//! Tests for `process_network_message` and individual message handlers.
//! These tests verify protocol-level message handling, limits, and responses.

use blvm_consensus::{Block, BlockHeader, Hash, Transaction};
use blvm_protocol::network::{
    AddrMessage, ChainStateAccess, FeeFilterMessage, GetBlocksMessage, GetDataMessage,
    HeadersMessage, InvMessage, NetworkAddress, NetworkMessage, NetworkResponse, NotFoundMessage,
    PeerState, PingMessage, PongMessage, RejectMessage, VersionMessage, process_network_message,
};
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};
use std::collections::HashMap;
use std::sync::Arc;

/// Mock chain state access for testing
struct MockChainStateAccess {
    blocks: HashMap<Hash, Block>,
    transactions: HashMap<Hash, Transaction>,
    headers: Vec<BlockHeader>,
    mempool: Vec<Transaction>,
}

impl MockChainStateAccess {
    fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            transactions: HashMap::new(),
            headers: Vec::new(),
            mempool: Vec::new(),
        }
    }

    fn add_block(&mut self, hash: Hash, block: Block) {
        let header = block.header.clone();
        self.blocks.insert(hash, block);
        self.headers.push(header);
    }

    fn add_transaction(&mut self, hash: Hash, tx: Transaction) {
        self.transactions.insert(hash, tx);
    }

    fn add_mempool_tx(&mut self, tx: Transaction) {
        self.mempool.push(tx);
    }
}

impl ChainStateAccess for MockChainStateAccess {
    fn has_object(&self, hash: &Hash) -> bool {
        self.blocks.contains_key(hash) || self.transactions.contains_key(hash)
    }

    fn get_object(&self, hash: &Hash) -> Option<blvm_protocol::network::ChainObject> {
        if let Some(block) = self.blocks.get(hash) {
            Some(blvm_protocol::network::ChainObject::Block(Arc::new(
                block.clone(),
            )))
        } else if let Some(tx) = self.transactions.get(hash) {
            Some(blvm_protocol::network::ChainObject::Transaction(Arc::new(
                tx.clone(),
            )))
        } else {
            None
        }
    }

    fn get_headers_for_locator(&self, _locator: &[Hash], _stop: &Hash) -> Vec<BlockHeader> {
        self.headers.clone()
    }

    fn get_mempool_transactions(&self) -> Vec<Transaction> {
        self.mempool.clone()
    }
}

fn create_test_engine() -> BitcoinProtocolEngine {
    BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap()
}

fn create_test_peer_state() -> PeerState {
    PeerState::new()
}

fn create_test_version_message() -> VersionMessage {
    VersionMessage {
        version: 70015,
        services: 1,
        timestamp: 1234567890,
        addr_recv: NetworkAddress {
            services: 1,
            ip: [0u8; 16],
            port: 8333,
        },
        addr_from: NetworkAddress {
            services: 1,
            ip: [0u8; 16],
            port: 8333,
        },
        nonce: 12345,
        user_agent: "test/1.0".to_string(),
        start_height: 0,
        relay: true,
    }
}

#[test]
fn test_process_version_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let version = create_test_version_message();

    let response = process_network_message(
        &engine,
        &NetworkMessage::Version(version.clone()),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should send verack
    match response {
        NetworkResponse::SendMessage(msg) => {
            assert!(matches!(*msg, NetworkMessage::VerAck));
        }
        _ => panic!("Expected SendMessage with VerAck"),
    }

    // Peer state should be updated
    assert_eq!(peer_state.version, version.version);
    assert_eq!(peer_state.services, version.services);
    assert_eq!(peer_state.user_agent, version.user_agent);
    assert_eq!(peer_state.start_height, version.start_height);
}

#[test]
fn test_process_version_message_too_old() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let mut version = create_test_version_message();
    version.version = 60000; // Too old

    let response = process_network_message(
        &engine,
        &NetworkMessage::Version(version),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Version too old"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_process_verack_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    peer_state.handshake_complete = false;

    let response = process_network_message(
        &engine,
        &NetworkMessage::VerAck,
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
    assert!(peer_state.handshake_complete);
}

#[test]
fn test_process_addr_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let addresses = vec![
        NetworkAddress {
            services: 1,
            ip: [0u8; 16],
            port: 8333,
        },
        NetworkAddress {
            services: 1,
            ip: [0u8; 16],
            port: 8334,
        },
    ];

    let response = process_network_message(
        &engine,
        &NetworkMessage::Addr(AddrMessage {
            addresses: addresses.clone(),
        }),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
    assert_eq!(peer_state.known_addresses.len(), addresses.len());
}

#[test]
fn test_process_addr_message_too_many() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let addresses: Vec<NetworkAddress> = (0..1001)
        .map(|i| NetworkAddress {
            services: 1,
            ip: [0u8; 16],
            port: 8333 + i as u16,
        })
        .collect();

    let response = process_network_message(
        &engine,
        &NetworkMessage::Addr(AddrMessage { addresses }),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject due to protocol limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many addresses"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_process_inv_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let mut chain_access = MockChainStateAccess::new();
    let hash = [1u8; 32];

    // Add a block to chain
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![].into(),
    };
    chain_access.add_block(hash, block);

    let inv = InvMessage {
        inventory: vec![blvm_protocol::network::InventoryVector {
            inv_type: 2, // MSG_BLOCK
            hash,
        }],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Inv(inv),
        &mut peer_state,
        Some(&chain_access),
        None,
        None,
    )
    .unwrap();

    // Should acknowledge (we already have the block)
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_process_inv_message_too_many() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let inventory: Vec<blvm_protocol::network::InventoryVector> = (0..50001)
        .map(|i| blvm_protocol::network::InventoryVector {
            inv_type: 2,
            hash: [i as u8; 32],
        })
        .collect();

    let response = process_network_message(
        &engine,
        &NetworkMessage::Inv(InvMessage { inventory }),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject due to protocol limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many inventory items"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_process_ping_pong() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let ping = PingMessage { nonce: 12345 };

    // Process ping
    let response = process_network_message(
        &engine,
        &NetworkMessage::Ping(ping.clone()),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should send pong
    match response {
        NetworkResponse::SendMessage(msg) => match *msg {
            NetworkMessage::Pong(pong) => {
                assert_eq!(pong.nonce, ping.nonce);
            }
            _ => panic!("Expected Pong message"),
        },
        _ => panic!("Expected SendMessage with Pong"),
    }

    // Process pong
    let pong = PongMessage { nonce: 12345 };
    peer_state.ping_nonce = Some(12345);
    let response = process_network_message(
        &engine,
        &NetworkMessage::Pong(pong),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
    assert!(peer_state.last_pong.is_some());
    assert_eq!(peer_state.ping_nonce, None);
}

#[test]
fn test_process_feefilter_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let feefilter = FeeFilterMessage { feerate: 1000 };

    let response = process_network_message(
        &engine,
        &NetworkMessage::FeeFilter(feefilter),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
    assert_eq!(peer_state.min_fee_rate, Some(1000));
}

#[test]
fn test_process_getaddr_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    peer_state.known_addresses = vec![
        NetworkAddress {
            services: 1,
            ip: [0u8; 16],
            port: 8333,
        },
        NetworkAddress {
            services: 1,
            ip: [0u8; 16],
            port: 8334,
        },
    ];

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetAddr,
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should send addr message with known addresses
    match response {
        NetworkResponse::SendMessage(msg) => match *msg {
            NetworkMessage::Addr(addr) => {
                assert_eq!(addr.addresses.len(), 2);
            }
            _ => panic!("Expected Addr message"),
        },
        _ => panic!("Expected SendMessage with Addr"),
    }
}

#[test]
fn test_process_getblocks_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let mut chain_access = MockChainStateAccess::new();
    let hash = [1u8; 32];

    // Add a block to chain
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![].into(),
    };
    chain_access.add_block(hash, block);

    let getblocks = GetBlocksMessage {
        version: 70015,
        block_locator_hashes: vec![hash],
        hash_stop: [0u8; 32],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBlocks(getblocks),
        &mut peer_state,
        Some(&chain_access),
        None,
        None,
    )
    .unwrap();

    // Should send inv message with found blocks
    match response {
        NetworkResponse::SendMessage(msg) => match *msg {
            NetworkMessage::Inv(inv) => {
                assert!(!inv.inventory.is_empty());
            }
            _ => panic!("Expected Inv message"),
        },
        _ => panic!("Expected SendMessage with Inv"),
    }
}

#[test]
fn test_process_getblocks_message_too_many_locators() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let locator_hashes: Vec<Hash> = (0..102).map(|i| [i as u8; 32]).collect();

    let getblocks = GetBlocksMessage {
        version: 70015,
        block_locator_hashes: locator_hashes,
        hash_stop: [0u8; 32],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBlocks(getblocks),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject due to protocol limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many locator hashes"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_process_notfound_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let notfound = NotFoundMessage {
        inventory: vec![blvm_protocol::network::InventoryVector {
            inv_type: 2,
            hash: [1u8; 32],
        }],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::NotFound(notfound),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_process_notfound_message_too_many() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let inventory: Vec<blvm_protocol::network::InventoryVector> = (0..50001)
        .map(|i| blvm_protocol::network::InventoryVector {
            inv_type: 2,
            hash: [i as u8; 32],
        })
        .collect();

    let response = process_network_message(
        &engine,
        &NetworkMessage::NotFound(NotFoundMessage { inventory }),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject due to protocol limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many notfound items"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_process_reject_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let reject = RejectMessage {
        message: "block".to_string(),
        code: 0x10, // Invalid
        reason: "Invalid block".to_string(),
        extra_data: Some([1u8; 32]),
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Reject(reject),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_process_reject_message_invalid_name() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let reject = RejectMessage {
        message: "verylongmessagename".to_string(), // > 12 chars
        code: 0x10,
        reason: "Invalid".to_string(),
        extra_data: None,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Reject(reject),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject due to protocol limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Invalid reject message name"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_process_sendheaders_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let response = process_network_message(
        &engine,
        &NetworkMessage::SendHeaders,
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_process_headers_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let headers = HeadersMessage {
        headers: vec![BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        }],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Headers(headers),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_process_headers_message_too_many() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let headers: Vec<BlockHeader> = (0..2001)
        .map(|i| BlockHeader {
            version: 1,
            prev_block_hash: [i as u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505u64 + i as u64,
            bits: 0x1d00ffff,
            nonce: 0,
        })
        .collect();

    let response = process_network_message(
        &engine,
        &NetworkMessage::Headers(HeadersMessage { headers }),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject due to protocol limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many headers"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_process_getdata_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let mut chain_access = MockChainStateAccess::new();
    let hash = [1u8; 32];

    // Add a transaction to chain
    use blvm_consensus::{tx_inputs, tx_outputs};
    let tx = Transaction {
        version: 1,
        inputs: tx_inputs![],
        outputs: tx_outputs![],
        lock_time: 0,
    };
    chain_access.add_transaction(hash, tx);

    let getdata = GetDataMessage {
        inventory: vec![blvm_protocol::network::InventoryVector {
            inv_type: 1, // MSG_TX
            hash,
        }],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetData(getdata),
        &mut peer_state,
        Some(&chain_access),
        None,
        None,
    )
    .unwrap();

    // Should send transaction
    match response {
        NetworkResponse::SendMessages(msgs) => {
            assert!(!msgs.is_empty());
            assert!(matches!(msgs[0], NetworkMessage::Tx(_)));
        }
        _ => panic!("Expected SendMessages with Tx"),
    }
}

#[test]
fn test_process_getdata_message_too_many() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let inventory: Vec<blvm_protocol::network::InventoryVector> = (0..50001)
        .map(|i| blvm_protocol::network::InventoryVector {
            inv_type: 1,
            hash: [i as u8; 32],
        })
        .collect();

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetData(GetDataMessage { inventory }),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject due to protocol limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many getdata items"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[test]
fn test_process_mempool_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();
    let mut chain_access = MockChainStateAccess::new();

    // Add transactions to mempool
    use blvm_consensus::{tx_inputs, tx_outputs};
    let tx1 = Transaction {
        version: 1,
        inputs: tx_inputs![],
        outputs: tx_outputs![],
        lock_time: 0,
    };
    let tx2 = Transaction {
        version: 1,
        inputs: tx_inputs![],
        outputs: tx_outputs![],
        lock_time: 0,
    };
    chain_access.add_mempool_tx(tx1);
    chain_access.add_mempool_tx(tx2);

    let response = process_network_message(
        &engine,
        &NetworkMessage::MemPool,
        &mut peer_state,
        Some(&chain_access),
        None,
        None,
    )
    .unwrap();

    // Should send mempool transactions
    match response {
        NetworkResponse::SendMessages(msgs) => {
            assert_eq!(msgs.len(), 2);
            for msg in msgs {
                assert!(matches!(msg, NetworkMessage::Tx(_)));
            }
        }
        _ => panic!("Expected SendMessages with Tx"),
    }
}
