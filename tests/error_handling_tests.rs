//! Error Handling Tests
//!
//! Tests for handling malformed messages, protocol mismatches,
//! invalid data, and error recovery scenarios.

use blvm_consensus::{BlockHeader, Hash};
use blvm_protocol::network::{
    AddrMessage, GetDataMessage, GetHeadersMessage, HeadersMessage, InvMessage, NetworkAddress,
    NetworkMessage, NetworkResponse, PeerState, RejectMessage, VersionMessage,
    process_network_message,
};
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

fn create_test_engine() -> BitcoinProtocolEngine {
    BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap()
}

fn create_test_peer_state() -> PeerState {
    PeerState::new()
}

// ============================================================================
// Phase 1: Malformed Version Message Tests
// ============================================================================

#[test]
fn test_version_message_too_old() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let version = VersionMessage {
        version: 60000, // Too old (minimum is 70001)
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

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("version") || reason.contains("old"));
        }
        _ => panic!("Expected Reject for old version"),
    }
}

#[test]
fn test_version_message_invalid_user_agent_length() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let long_user_agent = "a".repeat(10000); // Exceeds protocol limit

    let version = VersionMessage {
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
        user_agent: long_user_agent,
        start_height: 0,
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

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(
                reason.contains("user_agent")
                    || reason.contains("too long")
                    || reason.contains("256")
            );
        }
        _ => panic!("Expected Reject for invalid user agent length"),
    }
}

// ============================================================================
// Phase 2: Malformed Address Message Tests
// ============================================================================

#[test]
fn test_addr_message_too_many_addresses() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

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

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many addresses") || reason.contains("limit"));
        }
        _ => panic!("Expected Reject for too many addresses"),
    }
}

// ============================================================================
// Phase 3: Malformed Inventory Message Tests
// ============================================================================

#[test]
fn test_inv_message_too_many_items() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

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

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many") || reason.contains("inventory"));
        }
        _ => panic!("Expected Reject for too many inventory items"),
    }
}

#[test]
fn test_inv_message_invalid_type() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let inventory = vec![blvm_protocol::network::InventoryVector {
        inv_type: 99, // Invalid type (valid: 1=tx, 2=block, 3=filtered block, 4=compact block)
        hash: [0u8; 32],
    }];

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

    // Should handle gracefully (may reject or ignore)
    match response {
        NetworkResponse::Reject(_) | NetworkResponse::Ok => {}
        _ => panic!("Expected Reject or Ok for invalid inventory type"),
    }
}

// ============================================================================
// Phase 4: Malformed GetData Message Tests
// ============================================================================

#[test]
fn test_getdata_message_too_many_items() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let inventory: Vec<blvm_protocol::network::InventoryVector> = (0..50001)
        .map(|i| blvm_protocol::network::InventoryVector {
            inv_type: 1,
            hash: [i as u8; 32],
        })
        .collect();

    let getdata = GetDataMessage { inventory };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetData(getdata),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many") || reason.contains("getdata"));
        }
        _ => panic!("Expected Reject for too many getdata items"),
    }
}

// ============================================================================
// Phase 5: Malformed Headers Message Tests
// ============================================================================

#[test]
fn test_headers_message_too_many_headers() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

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

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many headers") || reason.contains("limit"));
        }
        _ => panic!("Expected Reject for too many headers"),
    }
}

#[test]
fn test_getheaders_message_too_many_locators() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let locator: Vec<Hash> = (0..101)
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

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("Too many locator") || reason.contains("max 100"));
        }
        _ => panic!("Expected Reject for too many locators"),
    }
}

// ============================================================================
// Phase 6: Malformed Reject Message Tests
// ============================================================================

#[test]
fn test_reject_message_invalid_name_length() {
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

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("message name") || reason.contains("too long"));
        }
        _ => panic!("Expected Reject for invalid message name length"),
    }
}

#[test]
fn test_reject_message_reason_too_long() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let long_reason = "a".repeat(1000); // Exceeds protocol limit

    let reject = RejectMessage {
        message: "block".to_string(),
        code: 0x10,
        reason: long_reason,
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

    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains("reason") || reason.contains("too long"));
        }
        _ => panic!("Expected Reject for reason too long"),
    }
}

// ============================================================================
// Phase 7: Protocol Mismatch Tests
// ============================================================================

#[test]
fn test_version_message_wrong_network() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    // Test with testnet engine but mainnet version message
    // (In practice, this would be caught by magic bytes, but we test the version handling)
    let version = VersionMessage {
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
    };

    // Should accept valid version regardless of network (network is determined by magic bytes)
    let response = process_network_message(
        &engine,
        &NetworkMessage::Version(version),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should return VerAck for valid version
    match response {
        NetworkResponse::SendMessage(_) | NetworkResponse::Ok => {}
        _ => panic!("Expected SendMessage or Ok for valid version"),
    }
}

// ============================================================================
// Phase 8: Edge Case Error Recovery Tests
// ============================================================================

#[test]
fn test_empty_inventory_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let inv = InvMessage {
        inventory: vec![], // Empty inventory
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
fn test_empty_getdata_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let getdata = GetDataMessage {
        inventory: vec![], // Empty inventory
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetData(getdata),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    // Should handle empty getdata gracefully
    assert!(matches!(response, NetworkResponse::Ok));
}

#[test]
fn test_empty_headers_message() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let headers_msg = HeadersMessage {
        headers: vec![], // Empty headers
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
