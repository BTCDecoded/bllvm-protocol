//! BIP324: Version 2 P2P Encrypted Transport Protocol
//!
//! This module implements the encrypted transport protocol for Bitcoin P2P connections.
//! It provides ElligatorSwift encoding, X-only ECDH key exchange, and ChaCha20Poly1305 encryption.

use crate::Result;
use crate::error::ProtocolError;
use blvm_secp256k1::ellswift::{ellswift_create, ellswift_xdh};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use getrandom::getrandom;
use std::borrow::Cow;

/// BIP324 v2 transport encryption state
pub struct V2Transport {
    /// Send key material (updated on rekey per BIP324 FSChaCha20Poly1305)
    send_key: [u8; 32],
    /// Receive key material (updated on rekey)
    recv_key: [u8; 32],
    /// Send cipher (encrypt outgoing messages)
    send_cipher: ChaCha20Poly1305,
    /// Receive cipher (decrypt incoming messages)
    recv_cipher: ChaCha20Poly1305,
    /// Send nonce counter
    send_nonce: u64,
    /// Receive nonce counter
    recv_nonce: u64,
}

/// BIP324 handshake state
pub enum V2Handshake {
    /// Initiator handshake (client connecting)
    Initiator {
        private_key: [u8; 32],
        ellswift: [u8; 64],
    },
    /// Responder handshake (server accepting)
    Responder {
        private_key: [u8; 32],
        initiator_ellswift: Option<[u8; 64]>,
    },
}

/// BIP324: rekey after this many AEAD operations per direction (`REKEY_INTERVAL`).
const REKEY_INTERVAL: u64 = 224;

fn rekey_derive_next_key(key: &[u8; 32], rekey_epoch: u64) -> Result<[u8; 32]> {
    let mut rekey_nonce = [0u8; 12];
    rekey_nonce[0..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    rekey_nonce[4..12].copy_from_slice(&rekey_epoch.to_le_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&rekey_nonce), [0u8; 32].as_slice())
        .map_err(|e| {
            ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
                Cow::Owned(format!("BIP324 rekey encrypt failed: {e}")),
            ))
        })?;
    let mut new_key = [0u8; 32];
    new_key.copy_from_slice(&ct[..32]);
    Ok(new_key)
}

impl V2Transport {
    /// Create a new v2 transport with established keys
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        let send_cipher = ChaCha20Poly1305::new(Key::from_slice(&send_key));
        let recv_cipher = ChaCha20Poly1305::new(Key::from_slice(&recv_key));

        Self {
            send_key,
            recv_key,
            send_cipher,
            recv_cipher,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    /// Encrypt a message for sending
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // BIP324 packet format: [16-byte poly1305 tag][3-byte length][1-byte ignored][encrypted payload]
        // Nonce format: 12 bytes (8-byte counter + 4-byte zero padding)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.send_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt plaintext
        let ciphertext = self.send_cipher.encrypt(nonce, plaintext).map_err(|e| {
            ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
                Cow::Owned(format!("Encryption failed: {e}")),
            ))
        })?;

        // Increment nonce counter
        self.send_nonce += 1;

        // BIP324 FSChaCha20Poly1305: rekey every REKEY_INTERVAL packets
        if self.send_nonce % REKEY_INTERVAL == 0 {
            let rekey_epoch = (self.send_nonce / REKEY_INTERVAL) - 1;
            self.send_key = rekey_derive_next_key(&self.send_key, rekey_epoch)?;
            self.send_cipher = ChaCha20Poly1305::new(Key::from_slice(&self.send_key));
        }

        // Build packet: [tag(16)][length(3)][ignored(1)][payload(var)]
        let mut packet = Vec::with_capacity(20 + ciphertext.len());

        // Extract tag (last 16 bytes of ciphertext are the tag)
        if ciphertext.len() < 16 {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(Cow::Owned(
                    "Ciphertext too short".to_string(),
                )),
            ));
        }
        let tag_start = ciphertext.len() - 16;
        packet.extend_from_slice(&ciphertext[tag_start..]);

        // Length (3 bytes, little-endian, max 2^24-1)
        let payload_len = ciphertext.len() - 16; // Exclude tag
        if payload_len > 0xFFFFFF {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(Cow::Owned(
                    "Payload too large".to_string(),
                )),
            ));
        }
        let len_bytes = (payload_len as u32).to_le_bytes();
        packet.extend_from_slice(&len_bytes[..3]);

        // Ignored byte (set to 0)
        packet.push(0);

        // Payload (ciphertext without tag)
        packet.extend_from_slice(&ciphertext[..tag_start]);

        Ok(packet)
    }

    /// Decrypt a received message
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // BIP324 packet format: [16-byte poly1305 tag][3-byte length][1-byte ignored][encrypted payload]
        if packet.len() < 20 {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(Cow::Owned(
                    "Packet too short".to_string(),
                )),
            ));
        }

        // Extract components
        let tag = &packet[0..16];
        let length_bytes = [packet[16], packet[17], packet[18], 0];
        let payload_len = u32::from_le_bytes(length_bytes) as usize;
        // Ignore byte at packet[19]
        let payload_start = 20;
        let payload_end = payload_start + payload_len;

        if packet.len() < payload_end {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(Cow::Owned(
                    "Packet incomplete".to_string(),
                )),
            ));
        }

        // Reconstruct ciphertext: payload + tag
        let mut ciphertext = Vec::with_capacity(payload_len + 16);
        ciphertext.extend_from_slice(&packet[payload_start..payload_end]);
        ciphertext.extend_from_slice(tag);

        // Nonce format: 12 bytes (8-byte counter + 4-byte zero padding)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.recv_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt
        let plaintext = self
            .recv_cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| {
                ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned(format!("Decryption failed: {e}")),
                ))
            })?;

        // Increment nonce counter
        self.recv_nonce += 1;

        if self.recv_nonce % REKEY_INTERVAL == 0 {
            let rekey_epoch = (self.recv_nonce / REKEY_INTERVAL) - 1;
            self.recv_key = rekey_derive_next_key(&self.recv_key, rekey_epoch)?;
            self.recv_cipher = ChaCha20Poly1305::new(Key::from_slice(&self.recv_key));
        }

        Ok(plaintext)
    }
}

impl V2Handshake {
    /// Create a new initiator handshake
    pub fn new_initiator() -> (Vec<u8>, Self) {
        let mut key_bytes = [0u8; 32];
        getrandom(&mut key_bytes).expect("Failed to generate random bytes");
        let mut aux_rand = [0u8; 32];
        getrandom(&mut aux_rand).expect("Failed to generate aux_rand");
        let ellswift = ellswift_create(&key_bytes, Some(&aux_rand))
            .expect("Failed to create ElligatorSwift encoding");
        (
            ellswift.to_vec(),
            Self::Initiator {
                private_key: key_bytes,
                ellswift,
            },
        )
    }

    /// Create a new responder handshake
    pub fn new_responder() -> Self {
        let mut key_bytes = [0u8; 32];
        getrandom(&mut key_bytes).expect("Failed to generate random bytes");
        Self::Responder {
            private_key: key_bytes,
            initiator_ellswift: None,
        }
    }

    /// Process initiator message (responder side)
    pub fn process_initiator_message(
        &mut self,
        initiator_msg: &[u8],
    ) -> Result<(Vec<u8>, V2Transport)> {
        if initiator_msg.len() != 64 {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(Cow::Owned(
                    "Invalid initiator message length".to_string(),
                )),
            ));
        }

        let mut initiator_ell64 = [0u8; 64];
        initiator_ell64.copy_from_slice(initiator_msg);

        let responder_private = match self {
            Self::Responder { private_key, .. } => *private_key,
            _ => {
                return Err(ProtocolError::Consensus(
                    blvm_consensus::error::ConsensusError::Serialization(Cow::Owned(
                        "Not a responder handshake".to_string(),
                    )),
                ));
            }
        };

        let mut aux_rand = [0u8; 32];
        getrandom(&mut aux_rand).expect("Failed to generate aux_rand");

        let responder_ell64 = ellswift_create(&responder_private, Some(&aux_rand))
            .expect("Failed to create ElligatorSwift encoding");

        // X-only ECDH: responder is party B (party = true).
        let shared_x = ellswift_xdh(
            &initiator_ell64,
            &responder_ell64,
            &responder_private,
            true, // B = responder
        )
        .expect("ElligatorSwift ECDH failed");

        let send_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_send");
        let recv_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_recv");
        let transport = V2Transport::new(send_key, recv_key);

        if let Self::Responder {
            initiator_ellswift, ..
        } = self
        {
            *initiator_ellswift = Some(initiator_ell64);
        }

        Ok((responder_ell64.to_vec(), transport))
    }

    /// Complete handshake (initiator side)
    pub fn complete_handshake(self, responder_msg: &[u8]) -> Result<V2Transport> {
        if responder_msg.len() != 64 {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(Cow::Owned(
                    "Invalid responder message length".to_string(),
                )),
            ));
        }

        let mut responder_ell64 = [0u8; 64];
        responder_ell64.copy_from_slice(responder_msg);

        let (private_key, initiator_ell64) = match self {
            Self::Initiator {
                private_key,
                ellswift,
            } => (private_key, ellswift),
            _ => {
                return Err(ProtocolError::Consensus(
                    blvm_consensus::error::ConsensusError::Serialization(Cow::Owned(
                        "Not an initiator handshake".to_string(),
                    )),
                ));
            }
        };

        // X-only ECDH: initiator is party A (party = false).
        let shared_x = ellswift_xdh(
            &initiator_ell64,
            &responder_ell64,
            &private_key,
            false, // A = initiator
        )
        .expect("ElligatorSwift ECDH failed");

        let send_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_send");
        let recv_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_recv");
        Ok(V2Transport::new(send_key, recv_key))
    }
}

/// HKDF-SHA256 key derivation (BIP324).
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    let hk = Hkdf::<sha2::Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expansion failed (should never happen for 32-byte output)");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_transport_encrypt_decrypt() {
        // Use the same key for both send and recv for testing
        // In a real BIP324 connection, send_key_A == recv_key_B (derived from shared secret)
        let key = [0x42; 32];
        let mut transport = V2Transport::new(key, key);

        let plaintext = b"Hello, Bitcoin!";
        let encrypted = transport.encrypt(plaintext).unwrap();
        let decrypted = transport.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_v2_transport_rekey_round_trip() {
        let key = [0x11; 32];
        let mut enc = V2Transport::new(key, key);
        let mut dec = V2Transport::new(key, key);
        for i in 0..300 {
            let pt = format!("msg{i}").into_bytes();
            let pkt = enc.encrypt(&pt).unwrap();
            let out = dec.decrypt(&pkt).unwrap();
            assert_eq!(pt, out, "round-trip failed at i={i}");
        }
    }

    #[test]
    fn test_elligator_swift_encode_decode() {
        use blvm_secp256k1::ellswift::{ellswift_create, ellswift_xdh};
        // Create from a known secret key (no randomness for determinism).
        let seckey = [0x01u8; 32];
        let ell = ellswift_create(&seckey, None).expect("valid key");
        assert_eq!(ell.len(), 64);
        // Verify XDH with itself is consistent (reflexive sanity check).
        let shared = ellswift_xdh(&ell, &ell, &seckey, false);
        assert!(shared.is_some(), "XDH should not fail on valid inputs");
    }
}
