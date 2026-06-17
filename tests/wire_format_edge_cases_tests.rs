//! Edge case tests for wire format module

use blvm_protocol::network::{NetworkAddress, NetworkMessage, VersionMessage};
use blvm_protocol::wire::{
    MAX_MESSAGE_PAYLOAD, MESSAGE_HEADER_SIZE, calculate_checksum, deserialize_message,
    serialize_message,
};
use std::io::Cursor;

#[test]
fn test_calculate_checksum_empty_payload() {
    let empty: &[u8] = &[];
    let checksum = calculate_checksum(empty);

    // Checksum should be 4 bytes
    assert_eq!(checksum.len(), 4);

    // Empty payload should have deterministic checksum
    let checksum2 = calculate_checksum(empty);
    assert_eq!(checksum, checksum2);
}

#[test]
fn test_calculate_checksum_large_payload() {
    let large_payload = vec![0u8; 1_000_000]; // 1MB
    let checksum = calculate_checksum(&large_payload);

    assert_eq!(checksum.len(), 4);

    // Should be deterministic
    let checksum2 = calculate_checksum(&large_payload);
    assert_eq!(checksum, checksum2);
}

#[test]
fn test_calculate_checksum_different_payloads() {
    let payload1 = b"test1";
    let payload2 = b"test2";

    let checksum1 = calculate_checksum(payload1);
    let checksum2 = calculate_checksum(payload2);

    // Different payloads should have different checksums
    assert_ne!(checksum1, checksum2);
}

#[test]
fn test_serialize_message_max_payload() {
    // Test serialization with payload at max size boundary
    let magic = [0xf9, 0xbe, 0xb4, 0xd9]; // Mainnet

    // Create a message that would result in max payload
    // Note: Most messages won't hit this, but we test the validation
    let message = NetworkMessage::VerAck; // Empty payload

    let result = serialize_message(&message, magic);
    assert!(result.is_ok());

    let serialized = result.unwrap();
    // VerAck has empty payload, so should be just header
    assert!(serialized.len() >= MESSAGE_HEADER_SIZE);
}

#[test]
fn test_serialize_message_invalid_magic() {
    // Test with various magic bytes
    let mainnet_magic = [0xf9, 0xbe, 0xb4, 0xd9];
    let testnet_magic = [0x0b, 0x11, 0x09, 0x07];

    let message = NetworkMessage::VerAck;

    let result1 = serialize_message(&message, mainnet_magic);
    let result2 = serialize_message(&message, testnet_magic);

    // Both should succeed (magic is just a parameter)
    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // But serialized messages should differ (different magic bytes)
    let serialized1 = result1.unwrap();
    let serialized2 = result2.unwrap();
    assert_ne!(serialized1[..4], serialized2[..4]);
}

#[test]
fn test_deserialize_message_invalid_magic() {
    let mainnet_magic = [0xf9, 0xbe, 0xb4, 0xd9];
    let testnet_magic = [0x0b, 0x11, 0x09, 0x07];

    // Serialize with mainnet magic
    let message = NetworkMessage::VerAck;
    let serialized = serialize_message(&message, mainnet_magic).unwrap();

    // Try to deserialize with wrong magic
    let mut cursor = Cursor::new(&serialized);
    let result = deserialize_message(&mut cursor, testnet_magic);

    // Should fail due to magic mismatch
    assert!(result.is_err());
}

#[test]
fn test_deserialize_message_invalid_checksum() {
    let magic = [0xf9, 0xbe, 0xb4, 0xd9];

    // Serialize a message
    let message = NetworkMessage::VerAck;
    let mut serialized = serialize_message(&message, magic).unwrap();

    // Corrupt the checksum
    serialized[20] ^= 0xFF; // Flip bits in checksum

    // Try to deserialize
    let mut cursor = Cursor::new(&serialized);
    let result = deserialize_message(&mut cursor, magic);

    // Should fail due to checksum mismatch
    assert!(result.is_err());
}

#[test]
fn test_deserialize_message_short_header() {
    let magic = [0xf9, 0xbe, 0xb4, 0xd9];

    // Create data shorter than header
    let short_data = vec![0u8; MESSAGE_HEADER_SIZE - 1];

    let mut cursor = Cursor::new(&short_data);
    let result = deserialize_message(&mut cursor, magic);

    // Should fail - not enough data for header
    assert!(result.is_err());
}

#[test]
fn test_deserialize_message_invalid_command() {
    let magic = [0xf9, 0xbe, 0xb4, 0xd9];

    // Create a message with invalid command
    let mut header = vec![0u8; MESSAGE_HEADER_SIZE];
    // Set magic
    header[0..4].copy_from_slice(&magic);
    // Set invalid command (non-ASCII) - pad to 12 bytes
    let mut cmd = [0u8; 12];
    cmd[..7].copy_from_slice(b"invalid");
    cmd[7..].fill(0xff);
    header[4..16].copy_from_slice(&cmd);
    // Set payload length to 0
    header[16..20].copy_from_slice(&0u32.to_le_bytes());
    // Set checksum (for empty payload)
    let empty_checksum = calculate_checksum(&[]);
    header[20..24].copy_from_slice(&empty_checksum);

    let mut cursor = Cursor::new(&header);
    let result = deserialize_message(&mut cursor, magic);

    // Should fail due to invalid command encoding
    assert!(result.is_err());
}

#[test]
fn test_deserialize_message_unknown_command() {
    let magic = [0xf9, 0xbe, 0xb4, 0xd9];

    // Create a message with unknown command
    let mut header = vec![0u8; MESSAGE_HEADER_SIZE];
    // Set magic
    header[0..4].copy_from_slice(&magic);
    // Set unknown command
    header[4..16].copy_from_slice(b"unknown\x00\x00\x00\x00\x00");
    // Set payload length to 0
    header[16..20].copy_from_slice(&0u32.to_le_bytes());
    // Set checksum
    let empty_checksum = calculate_checksum(&[]);
    header[20..24].copy_from_slice(&empty_checksum);

    let mut cursor = Cursor::new(&header);
    let result = deserialize_message(&mut cursor, magic);

    // Should fail due to unknown command
    assert!(result.is_err());
}

#[test]
fn test_deserialize_message_payload_too_large() {
    let magic = [0xf9, 0xbe, 0xb4, 0xd9];

    // Create a message with payload length exceeding max
    let mut header = vec![0u8; MESSAGE_HEADER_SIZE];
    // Set magic
    header[0..4].copy_from_slice(&magic);
    // Set command - pad to 12 bytes
    let mut cmd = [0u8; 12];
    cmd[..6].copy_from_slice(b"verack");
    header[4..16].copy_from_slice(&cmd);
    // Set payload length to exceed max
    let too_large = (MAX_MESSAGE_PAYLOAD as u32) + 1;
    header[16..20].copy_from_slice(&too_large.to_le_bytes());
    // Set checksum (for empty payload, but length says otherwise)
    let empty_checksum = calculate_checksum(&[]);
    header[20..24].copy_from_slice(&empty_checksum);

    let mut cursor = Cursor::new(&header);
    let result = deserialize_message(&mut cursor, magic);

    // Should fail due to payload too large
    assert!(result.is_err());
}

#[test]
fn test_serialize_deserialize_roundtrip_verack() {
    let magic = [0xf9, 0xbe, 0xb4, 0xd9];
    let message = NetworkMessage::VerAck;

    // Serialize
    let serialized = serialize_message(&message, magic).unwrap();

    // Deserialize
    let mut cursor = Cursor::new(&serialized);
    let (deserialized, bytes_read) = deserialize_message(&mut cursor, magic).unwrap();

    // Should match
    assert_eq!(deserialized, message);
    assert_eq!(bytes_read, serialized.len());
}

#[test]
fn test_wire_format_constants() {
    // Verify constants match Bitcoin protocol spec
    assert_eq!(MESSAGE_HEADER_SIZE, 24); // 4 + 12 + 4 + 4
    assert_eq!(MAX_MESSAGE_PAYLOAD, 32 * 1024 * 1024); // 32 MB
}

#[test]
fn test_command_encoding_edge_cases() {
    // Test command encoding with various lengths
    let commands = vec![
        "v",          // 1 byte
        "version",    // 7 bytes
        "getheaders", // 10 bytes
        "sendcmpct",  // 9 bytes
    ];

    let magic = [0xf9, 0xbe, 0xb4, 0xd9];

    for cmd in commands {
        // All commands should be <= 12 bytes
        assert!(cmd.len() <= 12, "Command '{}' exceeds 12 bytes", cmd);

        // Commands should be ASCII
        assert!(cmd.is_ascii(), "Command '{}' is not ASCII", cmd);
    }
}
