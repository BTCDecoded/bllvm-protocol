//! Script Type Detection for Adaptive Spam Filtering
//!
//! This module provides script type detection to enable adaptive witness size thresholds
//! based on the script type (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, MultiSig, etc.).
//!
//! Heuristic thresholds are tuned for witness-size–based relay policy (not a consensus BIP).

use blvm_consensus::opcodes::*;
use blvm_consensus::types::ByteString;

/// Script type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptType {
    /// Pay-to-Public-Key-Hash (legacy)
    P2PKH,
    /// Pay-to-Script-Hash
    P2SH,
    /// Pay-to-Witness-Public-Key-Hash (SegWit v0)
    P2WPKH,
    /// Pay-to-Witness-Script-Hash (SegWit v0)
    P2WSH,
    /// Pay-to-Taproot (SegWit v1)
    P2TR,
    /// Multi-signature script (n-of-m)
    MultiSig { n: u8, m: u8 },
    /// Payment channel (HTLC patterns)
    PaymentChannel,
    /// Unknown or complex script
    Unknown,
}

impl ScriptType {
    /// Detect script type from scriptPubKey
    ///
    /// This analyzes the output script to determine its type.
    /// For input scripts (scriptSig), use `detect_input_script_type` instead.
    pub fn detect(script_pubkey: &ByteString) -> Self {
        if script_pubkey.is_empty() {
            return Self::Unknown;
        }

        // P2TR: OP_1 + PUSH_32_BYTES + 32-byte x-only pubkey = 34 bytes
        if script_pubkey.len() == 34
            && script_pubkey[0] == OP_1
            && script_pubkey[1] == PUSH_32_BYTES
        {
            return Self::P2TR;
        }

        // P2WPKH: OP_0 + PUSH_20_BYTES + 20-byte hash = 22 bytes
        if script_pubkey.len() == 22
            && script_pubkey[0] == OP_0
            && script_pubkey[1] == PUSH_20_BYTES
        {
            return Self::P2WPKH;
        }

        // P2WSH: OP_0 + PUSH_32_BYTES + 32-byte hash = 34 bytes
        if script_pubkey.len() == 34
            && script_pubkey[0] == OP_0
            && script_pubkey[1] == PUSH_32_BYTES
        {
            return Self::P2WSH;
        }

        // P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        if script_pubkey.len() == 25
            && script_pubkey[0] == OP_DUP
            && script_pubkey[1] == OP_HASH160
            && script_pubkey[2] == PUSH_20_BYTES
            && script_pubkey[23] == OP_EQUALVERIFY
            && script_pubkey[24] == OP_CHECKSIG
        {
            return Self::P2PKH;
        }

        // P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL
        // Format: [0xa9, 0x14, <20 bytes>, 0x87]
        if script_pubkey.len() == 23
            && script_pubkey[0] == OP_HASH160  // OP_HASH160
            && script_pubkey[1] == PUSH_20_BYTES  // push 20 bytes
            && script_pubkey[22] == OP_EQUAL
        // OP_EQUAL
        {
            return Self::P2SH;
        }

        // Multi-sig detection: Check for OP_CHECKMULTISIG pattern
        // Format: OP_n <pubkey1> <pubkey2> ... <pubkeym> OP_m OP_CHECKMULTISIG
        if let Some(multisig) = Self::detect_multisig(script_pubkey) {
            return multisig;
        }

        // Payment channel detection: HTLC opcode patterns on executable path only
        if Self::has_htlc_pattern(script_pubkey) {
            return Self::PaymentChannel;
        }

        Self::Unknown
    }

    /// Detect multi-signature script type
    ///
    /// Returns `Some(MultiSig { n, m })` if script is a multi-sig, `None` otherwise.
    fn detect_multisig(script: &ByteString) -> Option<Self> {
        if script.len() < 3 {
            return None;
        }

        // Multi-sig format: OP_n <pubkey1> ... <pubkeym> OP_m OP_CHECKMULTISIG
        // OP_CHECKMULTISIG = 0xae
        if script[script.len() - 1] != OP_CHECKMULTISIG {
            return None;
        }

        // Parse m (number of required signatures)
        let m_opcode = script[script.len() - 2];
        let m = if (OP_1..=OP_16).contains(&m_opcode) {
            m_opcode - OP_1 + 1
        } else {
            return None;
        };

        // Parse n (number of public keys) - first opcode
        let n_opcode = script[0];
        let n = if (OP_1..=OP_16).contains(&n_opcode) {
            n_opcode - OP_1 + 1
        } else {
            return None;
        };

        // Validate: n >= m (can't require more signatures than available keys)
        if n < m {
            return None;
        }

        // Validate: typical pubkey size is 33 or 65 bytes
        // Rough check: script should be approximately n * 33 + overhead
        let expected_min_size = (n as usize) * 33 + 3; // n pubkeys + n opcode + m opcode + OP_CHECKMULTISIG
        if script.len() < expected_min_size {
            return None;
        }

        Some(Self::MultiSig { n, m })
    }

    /// Check if script has HTLC (Hash Time Lock Contract) pattern on the executable path.
    ///
    /// HTLCs are used in payment channels (Lightning Network). Requires conditional branch,
    /// time lock, hash, and equality opcodes as executable instructions (not inside push data).
    fn has_htlc_pattern(script: &ByteString) -> bool {
        if script.len() < 20 {
            return false;
        }

        let has_conditional = script_has_executable_opcode(script, OP_IF)
            || script_has_executable_opcode(script, OP_NOTIF);
        let has_time_lock = script_has_executable_opcode(script, OP_CHECKLOCKTIMEVERIFY)
            || script_has_executable_opcode(script, OP_CHECKSEQUENCEVERIFY);
        let has_hash = script_has_executable_opcode(script, OP_HASH160)
            || script_has_executable_opcode(script, OP_SHA256);
        let has_equal = script_has_executable_opcode(script, OP_EQUALVERIFY);

        has_conditional && has_time_lock && has_hash && has_equal
    }

    /// Get expected witness size range for this script type
    ///
    /// Returns (min_bytes, typical_bytes, max_bytes) for normal usage.
    /// These values are based on typical transaction patterns and will be
    /// refined with real-world data collection.
    pub fn expected_witness_size_range(&self) -> (usize, usize, usize) {
        match self {
            Self::P2PKH => (0, 0, 0),        // No witness
            Self::P2SH => (0, 0, 0),         // No witness (unless nested SegWit)
            Self::P2WPKH => (107, 107, 107), // 1 signature (71-73 bytes) + 1 pubkey (33 bytes) + varints
            Self::P2WSH => (200, 300, 500),  // Variable: depends on redeem script
            Self::P2TR => (64, 64, 64),      // 1 Schnorr signature (64 bytes) + varint
            Self::MultiSig { n, m } => {
                // n signatures + m pubkeys + redeem script + varints
                let sig_size = (*n as usize) * 73; // Max signature size
                let pubkey_size = (*m as usize) * 33; // Compressed pubkeys
                let script_size = 3 + (*m as usize) * 33; // OP_n + m pubkeys + OP_m + OP_CHECKMULTISIG
                let total = sig_size + pubkey_size + script_size + 10; // +10 for varints
                (total / 2, total, total * 2) // Conservative range
            }
            Self::PaymentChannel => (300, 500, 1000), // HTLC scripts can be complex
            Self::Unknown => (0, 200, 1000),          // Unknown - use conservative default
        }
    }

    /// Get recommended threshold for this script type
    ///
    /// Returns the recommended maximum witness size threshold based on script type.
    /// These values will be refined with real-world data collection.
    ///
    /// Derived from [`Self::expected_witness_size_range`] plus a per-type policy margin,
    /// except for [`Self::MultiSig`] which uses the legacy n/m heuristic.
    pub fn recommended_threshold(&self) -> usize {
        if let Self::MultiSig { n, m } = self {
            let base = (*n as usize) * 73 + (*m as usize) * 33 + 50; // Signatures + pubkeys + overhead
            return base + (base / 2); // Add 50% buffer
        }

        let (_min, _typical, soft_max) = self.expected_witness_size_range();
        match self {
            Self::P2PKH | Self::P2SH => 0,
            Self::P2WPKH => soft_max.saturating_add(43), // ~150 for typical 107-byte witness
            Self::P2WSH => soft_max.saturating_add(300), // ~800 for max 500 in range
            Self::P2TR => soft_max.saturating_add(36),   // ~100 for 64-byte Schnorr sig
            Self::PaymentChannel => soft_max.saturating_add(500), // ~1500
            Self::Unknown => soft_max,
            Self::MultiSig { .. } => unreachable!("handled above"),
        }
    }
}

/// Returns true when `opcode` appears as an executable instruction (not inside push data).
fn script_has_executable_opcode(script: &ByteString, opcode: u8) -> bool {
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        if op > 0 && op < OP_PUSHDATA1 {
            i += 1 + op as usize;
            continue;
        }
        match op {
            OP_PUSHDATA1 => {
                if i + 1 >= script.len() {
                    break;
                }
                let len = script[i + 1] as usize;
                i += 2 + len;
            }
            OP_PUSHDATA2 => {
                if i + 2 >= script.len() {
                    break;
                }
                let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                i += 3 + len;
            }
            OP_PUSHDATA4 => {
                if i + 4 >= script.len() {
                    break;
                }
                let len = u32::from_le_bytes([
                    script[i + 1],
                    script[i + 2],
                    script[i + 3],
                    script[i + 4],
                ]) as usize;
                i += 5 + len;
            }
            _ => {
                if op == opcode {
                    return true;
                }
                i += 1;
            }
        }
    }
    false
}

/// Detect script type from input script (scriptSig)
///
/// This analyzes the input script to infer the script type of the output being spent.
/// This is less reliable than analyzing scriptPubKey directly, but useful when
/// scriptPubKey is not available.
pub fn detect_input_script_type(script_sig: &ByteString) -> Option<ScriptType> {
    if script_sig.is_empty() {
        // Empty scriptSig suggests SegWit (P2WPKH, P2WSH, or P2TR)
        return Some(ScriptType::P2WPKH); // Most common SegWit type
    }

    // Check for multi-sig pattern in scriptSig
    if let Some(multisig) = ScriptType::detect_multisig(script_sig) {
        return Some(multisig);
    }

    // P2PKH scriptSig: <signature> <pubkey>
    // Typical sizes: signature ~71-73 bytes, pubkey 33 or 65 bytes
    if script_sig.len() >= 100 && script_sig.len() <= 150 {
        // Could be P2PKH
        return Some(ScriptType::P2PKH);
    }

    None
}

/// Transaction type classification for edge case handling
///
/// This helps reduce false positives by identifying legitimate transaction patterns
/// that might otherwise be flagged as spam (e.g., consolidations, CoinJoins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    /// Normal payment transaction
    Payment,
    /// Consolidation transaction (many inputs, few outputs)
    Consolidation,
    /// CoinJoin transaction (many inputs, many outputs, similar values)
    CoinJoin,
    /// Payment channel (Lightning Network)
    PaymentChannel,
    /// Unknown or complex transaction
    Unknown,
}

impl TransactionType {
    /// Detect transaction type from transaction structure
    ///
    /// This analyzes the transaction to determine its likely purpose.
    /// Used to adjust spam detection thresholds for legitimate use cases.
    pub fn detect(tx: &crate::types::Transaction) -> Self {
        let input_count = tx.inputs.len();
        let output_count = tx.outputs.len();

        // Consolidation: many inputs, few outputs
        // Typical pattern: 10+ inputs, 1-3 outputs
        if input_count >= 10 && output_count <= 3 {
            return Self::Consolidation;
        }

        // CoinJoin: many inputs, many outputs, similar output values
        // Typical pattern: 5+ inputs, 5+ outputs, output values within 10% of each other
        if input_count >= 5 && output_count >= 5 {
            let output_values: Vec<i64> = tx.outputs.iter().map(|out| out.value).collect();
            if Self::has_similar_values(&output_values, 0.1) {
                return Self::CoinJoin;
            }
        }

        // Payment channel: heuristic pattern match (see has_payment_channel_pattern).
        if Self::has_payment_channel_pattern(tx) {
            return Self::PaymentChannel;
        }

        // Default to payment for normal transactions
        if input_count <= 5 && output_count <= 5 {
            return Self::Payment;
        }

        Self::Unknown
    }

    /// Check if output values are similar (within percentage threshold)
    fn has_similar_values(values: &[i64], threshold: f64) -> bool {
        if values.is_empty() {
            return false;
        }

        let avg: f64 = values.iter().sum::<i64>() as f64 / values.len() as f64;

        for &value in values {
            let diff = (value as f64 - avg).abs() / avg;
            if diff > threshold {
                return false;
            }
        }

        true
    }

    /// Check if transaction has payment channel patterns
    fn has_payment_channel_pattern(tx: &crate::types::Transaction) -> bool {
        // Payment channels typically have:
        // - Complex scripts (HTLC patterns)
        // - Time locks
        // - Multiple outputs with similar values

        // Check for complex scripts in outputs
        let mut has_complex_script = false;
        for output in &tx.outputs {
            if output.script_pubkey.len() > 100 {
                has_complex_script = true;
                break;
            }
        }

        has_complex_script && tx.outputs.len() >= 2
    }

    /// Get recommended size-to-value ratio threshold for this transaction type
    ///
    /// Consolidations and CoinJoins legitimately have high size-to-value ratios,
    /// so we use higher thresholds for these transaction types.
    pub fn recommended_size_value_ratio(&self) -> f64 {
        match self {
            Self::Payment => 1000.0,        // Standard threshold
            Self::Consolidation => 5000.0,  // Consolidations can have high ratios
            Self::CoinJoin => 3000.0,       // CoinJoins have moderate ratios
            Self::PaymentChannel => 2000.0, // Payment channels can be complex
            Self::Unknown => 1000.0,        // Conservative default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_p2pkh() {
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let script = ByteString::from(vec![
            OP_DUP,
            OP_HASH160,
            PUSH_20_BYTES, // OP_DUP OP_HASH160 push 20 bytes
            OP_0,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0x11,
            0x12,
            0x13,
            OP_EQUALVERIFY,
            OP_CHECKSIG, // OP_EQUALVERIFY OP_CHECKSIG
        ]);
        assert_eq!(ScriptType::detect(&script), ScriptType::P2PKH);
    }

    #[test]
    fn test_detect_p2sh() {
        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        let script = ByteString::from(vec![
            OP_HASH160,
            PUSH_20_BYTES, // OP_HASH160 push 20 bytes
            OP_0,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0x11,
            0x12,
            0x13,
            OP_EQUAL, // OP_EQUAL
        ]);
        assert_eq!(ScriptType::detect(&script), ScriptType::P2SH);
    }

    #[test]
    fn test_detect_p2wpkh() {
        // P2WPKH: OP_0 <20-byte-hash>
        let script = ByteString::from(vec![
            OP_0,
            PUSH_20_BYTES, // OP_0 push 20 bytes
            OP_0,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0x11,
            0x12,
            0x13,
        ]);
        assert_eq!(ScriptType::detect(&script), ScriptType::P2WPKH);
    }

    #[test]
    fn test_detect_p2wsh() {
        // P2WSH: OP_0 <32-byte-hash>
        let script = ByteString::from(vec![
            OP_0,
            PUSH_32_BYTES, // OP_0 push 32 bytes
            OP_0,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0x11,
            0x12,
            0x13,
            PUSH_20_BYTES,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1a,
            0x1b,
            0x1c,
            0x1d,
            0x1e,
            0x1f,
        ]);
        assert_eq!(ScriptType::detect(&script), ScriptType::P2WSH);
    }

    #[test]
    fn test_detect_p2tr() {
        // P2TR: OP_1 <32-byte-hash>
        let script = ByteString::from(vec![
            OP_1,
            PUSH_32_BYTES, // OP_1 push 32 bytes
            OP_0,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0x11,
            0x12,
            0x13,
            PUSH_20_BYTES,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1a,
            0x1b,
            0x1c,
            0x1d,
            0x1e,
            0x1f,
        ]);
        assert_eq!(ScriptType::detect(&script), ScriptType::P2TR);
    }

    #[test]
    fn test_detect_multisig() {
        // 2-of-3 multi-sig: OP_3 <pubkey1> <pubkey2> <pubkey3> OP_2 OP_CHECKMULTISIG
        // Format: OP_n (n keys) <pubkey1>...<pubkeyn> OP_m (m required) OP_CHECKMULTISIG
        let mut script = vec![OP_3]; // n=3 keys
        // Add 3 pubkeys (33 bytes each)
        for _ in 0..3 {
            script.push(PUSH_33_BYTES);
            script.extend(vec![0u8; 33]);
        }
        script.push(OP_2); // m=2 required signatures
        script.push(OP_CHECKMULTISIG);

        let script_type = ScriptType::detect(&ByteString::from(script));
        match script_type {
            ScriptType::MultiSig { n, m } => {
                assert_eq!(n, 3);
                assert_eq!(m, 2);
            }
            _ => panic!("Expected MultiSig, got {:?}", script_type),
        }
    }

    #[test]
    fn test_expected_witness_size_range() {
        let p2wpkh = ScriptType::P2WPKH;
        let (min, typical, max) = p2wpkh.expected_witness_size_range();
        assert!(min <= typical && typical <= max);
        assert!(typical > 0);

        let p2tr = ScriptType::P2TR;
        let (min, typical, max) = p2tr.expected_witness_size_range();
        assert!(min <= typical && typical <= max);
        assert_eq!(typical, 64); // Schnorr signature is always 64 bytes
    }

    #[test]
    fn test_recommended_threshold() {
        let p2wpkh = ScriptType::P2WPKH;
        assert!(p2wpkh.recommended_threshold() > 0);

        let p2tr = ScriptType::P2TR;
        assert!(p2tr.recommended_threshold() > 0);

        let multisig = ScriptType::MultiSig { n: 2, m: 3 };
        assert!(multisig.recommended_threshold() > 0);
    }
}
