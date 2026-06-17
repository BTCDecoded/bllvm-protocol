//! Varint Encoding Edge Case Tests
//!
//! Additional edge cases for variable-length integer encoding.

use blvm_protocol::varint::{MAX_VARINT, read_varint, varint_size, write_varint};
use std::io::Cursor;

#[test]
fn test_varint_boundary_values() {
    // Test all boundary values for varint encoding

    // Single byte (0x00 - 0xfc)
    let test_values = vec![0u64, 1, 0xfc];
    for value in test_values {
        let mut buf = Vec::new();
        write_varint(&mut buf, value).unwrap();
        assert_eq!(buf.len(), 1);
        assert_eq!(varint_size(value), 1);

        let mut cursor = Cursor::new(&buf);
        let decoded = read_varint(&mut cursor).unwrap();
        assert_eq!(value, decoded);
    }

    // Two-byte encoding (0xfd - 0xffff)
    let test_values = vec![0xfd, 0xffff];
    for value in test_values {
        let mut buf = Vec::new();
        write_varint(&mut buf, value).unwrap();
        assert_eq!(buf.len(), 3); // 0xfd + 2 bytes
        assert_eq!(varint_size(value), 3);

        let mut cursor = Cursor::new(&buf);
        let decoded = read_varint(&mut cursor).unwrap();
        assert_eq!(value, decoded);
    }

    // Four-byte encoding (0x10000 - 0xffffffff)
    let test_values = vec![0x10000, 0xffffffff];
    for value in test_values {
        let mut buf = Vec::new();
        write_varint(&mut buf, value).unwrap();
        assert_eq!(buf.len(), 5); // 0xfe + 4 bytes
        assert_eq!(varint_size(value), 5);

        let mut cursor = Cursor::new(&buf);
        let decoded = read_varint(&mut cursor).unwrap();
        assert_eq!(value, decoded);
    }

    // Eight-byte encoding (0x100000000 - u64::MAX)
    let test_values = vec![0x1_0000_0000, MAX_VARINT];
    for value in test_values {
        let mut buf = Vec::new();
        write_varint(&mut buf, value).unwrap();
        assert_eq!(buf.len(), 9); // 0xff + 8 bytes
        assert_eq!(varint_size(value), 9);

        let mut cursor = Cursor::new(&buf);
        let decoded = read_varint(&mut cursor).unwrap();
        assert_eq!(value, decoded);
    }
}

#[test]
fn test_varint_max_value() {
    // Test maximum varint value
    let max_value = MAX_VARINT;

    let mut buf = Vec::new();
    write_varint(&mut buf, max_value).unwrap();
    assert_eq!(buf.len(), 9);

    let mut cursor = Cursor::new(&buf);
    let decoded = read_varint(&mut cursor).unwrap();
    assert_eq!(max_value, decoded);
}

#[test]
fn test_varint_size_calculation() {
    // Test varint_size function for all encoding sizes

    assert_eq!(varint_size(0), 1);
    assert_eq!(varint_size(0xfc), 1);
    assert_eq!(varint_size(0xfd), 3);
    assert_eq!(varint_size(0xffff), 3);
    assert_eq!(varint_size(0x10000), 5);
    assert_eq!(varint_size(0xffffffff), 5);
    assert_eq!(varint_size(0x1_0000_0000), 9);
    assert_eq!(varint_size(u64::MAX), 9);
}

#[test]
fn test_varint_roundtrip_all_boundaries() {
    // Test roundtrip for all encoding boundary values

    let boundaries = vec![
        0,
        0xfc,          // Last single-byte
        0xfd,          // First two-byte
        0xffff,        // Last two-byte
        0x10000,       // First four-byte
        0xffffffff,    // Last four-byte
        0x1_0000_0000, // First eight-byte
        u64::MAX,      // Maximum value
    ];

    for value in boundaries {
        let mut buf = Vec::new();
        write_varint(&mut buf, value).unwrap();
        let mut cursor = Cursor::new(&buf);
        let decoded = read_varint(&mut cursor).unwrap();
        assert_eq!(value, decoded, "Roundtrip failed for value {}", value);
    }
}

#[test]
fn test_varint_encoding_efficiency() {
    // Test that varint encoding is efficient (smaller values use fewer bytes)

    let small_value = 100u64;
    let large_value = u64::MAX;

    let mut buf_small = Vec::new();
    write_varint(&mut buf_small, small_value).unwrap();

    let mut buf_large = Vec::new();
    write_varint(&mut buf_large, large_value).unwrap();

    // Small value should use fewer bytes
    assert!(buf_small.len() < buf_large.len());
    assert_eq!(buf_small.len(), 1);
    assert_eq!(buf_large.len(), 9);
}
