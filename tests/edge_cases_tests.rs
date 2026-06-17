//! Edge Cases and Boundary Condition Tests
//!
//! Tests for maximum sizes, boundary conditions, and extreme scenarios
//! to ensure protocol limits are properly enforced.

use blvm_consensus::{BlockHeader, Hash};
use blvm_protocol::network::{
    AddrMessage, GetBlocksMessage, GetHeadersMessage, HeadersMessage, InvMessage, NetworkAddress,
    NetworkMessage, NetworkResponse, PeerState, process_network_message,
};
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

fn create_test_engine() -> BitcoinProtocolEngine {
    BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap()
}

fn create_test_peer_state() -> PeerState {
    PeerState::new()
}

// ============================================================================
// Phase 1: Maximum Size Tests
// ============================================================================

#[test]
fn test_addr_message_maximum_size() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // Protocol limit: 1000 addresses
    let addresses: Vec<NetworkAddress> = (0..1000)
        .map(|i| NetworkAddress {
            services: 1,
            ip: [i as u8; 16],
            port: 8333,
        })
        .collect();

    let addr = AddrMessage { addresses };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Addr(addr),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should accept exactly at the limit
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_inv_message_maximum_size() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // Protocol limit: 50000 inventory items
    let inventory: Vec<blvm_protocol::network::InventoryVector> = (0..50000)
        .map(|i| blvm_protocol::network::InventoryVector {
            inv_type: 1,
            hash: [i as u8; 32],
        })
        .collect();

    let inv = InvMessage { inventory };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Inv(inv),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should accept exactly at the limit
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_headers_message_maximum_size() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // Protocol limit: 2000 headers
    let headers: Vec<BlockHeader> = (0..2000)
        .map(|i| BlockHeader {
            version: 1,
            prev_block_hash: [i as u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505 + (i as u64),
            bits: 0x1d00ffff,
            nonce: 0,
        })
        .collect();

    let headers_msg = HeadersMessage { headers };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Headers(headers_msg),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should accept exactly at the limit
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_getheaders_message_maximum_locators() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // Protocol limit: 100 locator hashes
    let locator: Vec<Hash> = (0..100)
        .map(|i| {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            hash
        })
        .collect();

    let getheaders = GetHeadersMessage {
        version: 70015,
        block_locator_hashes: locator,
        hash_stop: [0u8; 32],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetHeaders(getheaders),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should accept exactly at the limit (returns Reject when no chain access, SendMessage when chain access provided)
    match response {
        NetworkResponse::Reject(_) | NetworkResponse::SendMessage(_) => {}
        _ => panic!(
            "Expected Reject (no chain access) or SendMessage, got {:?}",
            response
        ),
    }
}

#[test]
fn test_getblocks_message_maximum_locators() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // Protocol limit: 100 locator hashes
    let locator: Vec<Hash> = (0..100)
        .map(|i| {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            hash
        })
        .collect();

    let getblocks = GetBlocksMessage {
        version: 70015,
        block_locator_hashes: locator,
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

    // Should accept exactly at the limit (returns Ok when no chain access, SendMessage when chain access provided)
    match response {
        NetworkResponse::Ok | NetworkResponse::SendMessage(_) => {}
        _ => panic!(
            "Expected Ok (no chain access) or SendMessage, got {:?}",
            response
        ),
    }
}

// ============================================================================
// Phase 2: Boundary Condition Tests
// ============================================================================

#[test]
fn test_addr_message_one_over_limit() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // One over the limit (1001 addresses)
    let addresses: Vec<NetworkAddress> = (0..1001)
        .map(|i| NetworkAddress {
            services: 1,
            ip: [i as u8; 16],
            port: 8333,
        })
        .collect();

    let addr = AddrMessage { addresses };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Addr(addr),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject one over the limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many") || reason.contains("limit"));
        }
        _ => panic!("Expected Reject for one over limit"),
    }
}

#[test]
fn test_inv_message_one_over_limit() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // One over the limit (50001 items)
    let inventory: Vec<blvm_protocol::network::InventoryVector> = (0..50001)
        .map(|i| blvm_protocol::network::InventoryVector {
            inv_type: 1,
            hash: [i as u8; 32],
        })
        .collect();

    let inv = InvMessage { inventory };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Inv(inv),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject one over the limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many") || reason.contains("limit"));
        }
        _ => panic!("Expected Reject for one over limit"),
    }
}

#[test]
fn test_headers_message_one_over_limit() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // One over the limit (2001 headers)
    let headers: Vec<BlockHeader> = (0..2001)
        .map(|i| BlockHeader {
            version: 1,
            prev_block_hash: [i as u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505 + (i as u64),
            bits: 0x1d00ffff,
            nonce: 0,
        })
        .collect();

    let headers_msg = HeadersMessage { headers };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Headers(headers_msg),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should reject one over the limit
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many headers") || reason.contains("limit"));
        }
        _ => panic!("Expected Reject for one over limit"),
    }
}

// ============================================================================
// Phase 3: Minimum Size Tests
// ============================================================================

#[test]
fn test_addr_message_single_address() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let addr = AddrMessage {
        addresses: vec![NetworkAddress {
            services: 1,
            ip: [0u8; 16],
            port: 8333,
        }],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Addr(addr),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should accept single address
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_inv_message_single_item() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let inv = InvMessage {
        inventory: vec![blvm_protocol::network::InventoryVector {
            inv_type: 1,
            hash: [0u8; 32],
        }],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Inv(inv),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should accept single inventory item
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_headers_message_single_header() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let headers_msg = HeadersMessage {
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
        &NetworkMessage::Headers(headers_msg),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should accept single header
    assert!(matches!(response, NetworkResponse::Ok));
}

// ============================================================================
// Phase 4: Extreme Value Tests
// ============================================================================

#[test]
fn test_version_message_maximum_start_height() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let version = blvm_protocol::network::VersionMessage {
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
        nonce: u64::MAX,
        user_agent: "test/1.0".to_string(),
        start_height: u32::MAX as i32, // Maximum start height
        relay: true,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Version(version),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should handle maximum values
    match response {
        NetworkResponse::SendMessage(_) | NetworkResponse::Ok => {}
        _ => panic!("Expected SendMessage or Ok for valid version with max values"),
    }
}

#[test]
fn test_getheaders_message_empty_locator() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let getheaders = GetHeadersMessage {
        version: 70015,
        block_locator_hashes: vec![], // Empty locator (genesis block)
        hash_stop: [0u8; 32],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetHeaders(getheaders),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should handle empty locator (request from genesis) - returns Reject when no chain access, SendMessage when chain access provided
    match response {
        NetworkResponse::Reject(_) | NetworkResponse::SendMessage(_) => {}
        _ => panic!(
            "Expected Reject (no chain access) or SendMessage, got {:?}",
            response
        ),
    }
}

#[test]
fn test_getblocks_message_empty_locator() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let getblocks = GetBlocksMessage {
        version: 70015,
        block_locator_hashes: vec![], // Empty locator (genesis block)
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

    // Should handle empty locator (request from genesis) - returns Ok when no chain access, SendMessage when chain access provided
    match response {
        NetworkResponse::Ok | NetworkResponse::SendMessage(_) => {}
        _ => panic!(
            "Expected Ok (no chain access) or SendMessage, got {:?}",
            response
        ),
    }
}

// ============================================================================
// Phase 5: Zero/Empty Value Tests
// ============================================================================

#[test]
fn test_addr_message_empty() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let addr = AddrMessage {
        addresses: vec![], // Empty
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Addr(addr),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should handle empty address list gracefully
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_inv_message_empty() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let inv = InvMessage {
        inventory: vec![], // Empty
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Inv(inv),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should handle empty inventory gracefully
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_headers_message_empty() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let headers_msg = HeadersMessage {
        headers: vec![], // Empty
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::Headers(headers_msg),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should handle empty headers gracefully
    assert!(matches!(response, NetworkResponse::Ok));
}
