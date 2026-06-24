//! Commons-Specific Protocol Message Tests
//!
//! Comprehensive tests for Commons-specific protocol extensions:
//! - UTXO Commitments (GetUTXOSet, UTXOSet)
//! - Filtered Blocks (GetFilteredBlock, FilteredBlock)
//! - Ban List Sharing (GetBanList, BanList)

use blvm_consensus::{BlockHeader, Transaction};
#[cfg(feature = "utxo-commitments")]
use blvm_primitives::{TransactionInput, TransactionOutput};
use blvm_protocol::commons::{BanEntry, BanListMessage, GetBanListMessage};
#[cfg(feature = "utxo-commitments")]
use blvm_protocol::commons::{
    FilterPreferences, FilteredBlockMessage, GetFilteredBlockMessage, GetUTXOSetMessage,
    SpamSummary, UTXOCommitment, UTXOSetMessage,
};
use blvm_protocol::network::{NetworkMessage, NetworkResponse, PeerState, process_network_message};
use blvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

fn create_test_engine() -> BitcoinProtocolEngine {
    BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap()
}

fn create_test_peer_state() -> PeerState {
    PeerState::new()
}

fn assert_reject_contains(response: NetworkResponse, needle: &str) {
    match response {
        NetworkResponse::Reject(reason) => {
            assert!(reason.contains(needle), "unexpected reject: {reason}")
        }
        other => panic!("Expected Reject containing {needle:?}, got {other:?}"),
    }
}

// ============================================================================
// Phase 1: UTXO Commitments Tests
// ============================================================================

#[cfg(feature = "utxo-commitments")]
#[test]
fn test_getutxoset_message_processing() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let getutxoset = GetUTXOSetMessage {
        height: 700000,
        block_hash: [0x12; 32],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetUTXOSet(getutxoset),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "UTXO set relay");
}

#[cfg(feature = "utxo-commitments")]
#[test]
fn test_getutxoset_zero_height() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let getutxoset = GetUTXOSetMessage {
        height: 0, // Genesis block
        block_hash: [0u8; 32],
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetUTXOSet(getutxoset),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "UTXO set relay");
}

#[cfg(feature = "utxo-commitments")]
#[test]
fn test_utxoset_message_processing() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let commitment = UTXOCommitment {
        merkle_root: [0xab; 32],
        total_supply: 21_000_000 * 100_000_000,
        utxo_count: 50_000_000,
        block_height: 700000,
        block_hash: [0x12; 32],
    };

    let utxoset = UTXOSetMessage {
        request_id: 12345,
        commitment,
        utxo_count: 50_000_000,
        is_complete: true,
        chunk_id: None,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::UTXOSet(utxoset),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "UTXO set relay");
}

#[cfg(feature = "utxo-commitments")]
#[test]
fn test_utxoset_chunked_response() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let commitment = UTXOCommitment {
        merkle_root: [0xab; 32],
        total_supply: 21_000_000 * 100_000_000,
        utxo_count: 100_000_000,
        block_height: 700000,
        block_hash: [0x12; 32],
    };

    // First chunk
    let utxoset = UTXOSetMessage {
        request_id: 12345,
        commitment: commitment.clone(),
        utxo_count: 100_000_000,
        is_complete: false,
        chunk_id: Some(0),
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::UTXOSet(utxoset),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "UTXO set relay");
}

// ============================================================================
// Phase 2: Filtered Block Tests
// ============================================================================

#[cfg(feature = "utxo-commitments")]
#[test]
fn test_getfilteredblock_message_processing() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let filter_prefs = FilterPreferences {
        filter_ordinals: true,
        filter_dust: true,
        filter_brc20: true,
        min_output_value: 546, // Dust threshold
    };

    let getfiltered = GetFilteredBlockMessage {
        request_id: 67890,
        block_hash: [0x34; 32],
        filter_preferences: filter_prefs,
        include_bip158_filter: true,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetFilteredBlock(getfiltered),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Filtered block relay");
}

#[cfg(feature = "utxo-commitments")]
#[test]
fn test_getfilteredblock_no_bip158_filter() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let filter_prefs = FilterPreferences {
        filter_ordinals: false,
        filter_dust: false,
        filter_brc20: false,
        min_output_value: 0,
    };

    let getfiltered = GetFilteredBlockMessage {
        request_id: 67891,
        block_hash: [0x35; 32],
        filter_preferences: filter_prefs,
        include_bip158_filter: false,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetFilteredBlock(getfiltered),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Filtered block relay");
}

#[cfg(feature = "utxo-commitments")]
#[test]
fn test_filteredblock_message_processing() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0u8; 32],
        merkle_root: [1u8; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    let commitment = UTXOCommitment {
        merkle_root: [0xcd; 32],
        total_supply: 21_000_000 * 100_000_000,
        utxo_count: 50_000_000,
        block_height: 700000,
        block_hash: [0x34; 32],
    };

    let filtered_tx = Transaction {
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
            value: 10000, // Above dust threshold
            script_pubkey: vec![blvm_consensus::opcodes::OP_1],
        }],
        lock_time: 0,
    };

    let spam_summary = SpamSummary {
        filtered_count: 5,
        filtered_value: 5000,
        filter_reasons: 0b111, // All filter types triggered
    };

    let filtered = FilteredBlockMessage {
        request_id: 67890,
        header,
        commitment,
        transactions: vec![filtered_tx],
        transaction_indices: vec![1],
        spam_summary,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::FilteredBlock(filtered),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Filtered block relay");
}

#[cfg(feature = "utxo-commitments")]
#[test]
fn test_filteredblock_empty_transactions() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0u8; 32],
        merkle_root: [1u8; 32],
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    let commitment = UTXOCommitment {
        merkle_root: [0xcd; 32],
        total_supply: 21_000_000 * 100_000_000,
        utxo_count: 50_000_000,
        block_height: 700000,
        block_hash: [0x34; 32],
    };

    let spam_summary = SpamSummary {
        filtered_count: 10,
        filtered_value: 10000,
        filter_reasons: 0b111,
    };

    // All transactions filtered out
    let filtered = FilteredBlockMessage {
        request_id: 67892,
        header,
        commitment,
        transactions: vec![], // All filtered
        transaction_indices: vec![],
        spam_summary,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::FilteredBlock(filtered),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Filtered block relay");
}

// ============================================================================
// Phase 3: Ban List Sharing Tests
// ============================================================================

#[test]
fn test_getbanlist_message_processing() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let getbanlist = GetBanListMessage {
        request_id: 99999,
        min_score: Some(100), // Only bans with score >= 100
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBanList(getbanlist),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Ban list relay");
}

#[test]
fn test_getbanlist_no_min_score() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let getbanlist = GetBanListMessage {
        request_id: 99998,
        min_score: None, // Get all bans
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::GetBanList(getbanlist),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Ban list relay");
}

#[test]
fn test_banlist_message_processing() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let mut ip = [0u8; 16];
    ip[15] = 192; // IPv4-mapped: ::ffff:192.168.1.1
    ip[14] = 168;
    ip[13] = 1;
    ip[12] = 1;

    let ban_entry = BanEntry {
        ip,
        score: 150,
        reason: 1, // Spam
        timestamp: 1234567890,
        signature: None,
    };

    let banlist = BanListMessage {
        request_id: 99999,
        entries: vec![ban_entry],
        list_signature: None,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::BanList(banlist),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Ban list relay");
}

#[test]
fn test_banlist_empty_entries() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let banlist = BanListMessage {
        request_id: 99997,
        entries: vec![], // No bans
        list_signature: None,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::BanList(banlist),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Ban list relay");
}

#[test]
fn test_banlist_with_signature() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let mut ip = [0u8; 16];
    ip[15] = 192;
    ip[14] = 168;
    ip[13] = 1;
    ip[12] = 1;

    let ban_entry = BanEntry {
        ip,
        score: 200,
        reason: 2, // DoS attack
        timestamp: 1234567890,
        signature: Some(vec![0xab; 64]), // Signature for this entry
    };

    let banlist = BanListMessage {
        request_id: 99996,
        entries: vec![ban_entry],
        list_signature: Some(vec![0xcd; 64]), // Signature over entire list
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::BanList(banlist),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Ban list relay");
}

#[test]
fn test_banlist_multiple_entries() {
    let engine = create_test_engine();
    let mut peer_state = create_test_peer_state();

    let mut entries = Vec::new();
    for i in 0..10 {
        let mut ip = [0u8; 16];
        ip[15] = 192;
        ip[14] = 168;
        ip[13] = 1;
        ip[12] = i as u8;

        entries.push(BanEntry {
            ip,
            score: 100 + (i as u32),
            reason: 1,
            timestamp: 1234567890 + (i as u64),
            signature: None,
        });
    }

    let banlist = BanListMessage {
        request_id: 99995,
        entries,
        list_signature: None,
    };

    let response = process_network_message(
        &engine,
        &NetworkMessage::BanList(banlist),
        &mut peer_state,
        None,
        None,
        None,
    )
    .unwrap();

    assert_reject_contains(response, "Ban list relay");
}
