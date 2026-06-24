//! Network Integration Helpers for UTXO Commitments
//!
//! Provides helper functions and types for integrating UTXO commitments
//! with the P2P network layer in blvm-node.

#[cfg(feature = "utxo-commitments")]
use crate::spam_filter::{SpamFilter, SpamSummary};
#[cfg(feature = "utxo-commitments")]
use crate::utxo_commitments::data_structures::{
    UtxoCommitment, UtxoCommitmentError, UtxoCommitmentResult,
};
#[cfg(feature = "utxo-commitments")]
use blvm_consensus::types::{BlockHeader, Hash as HashType, Natural, Transaction};
#[cfg(feature = "utxo-commitments")]
/// Filtered block structure
#[derive(Debug, Clone)]
pub struct FilteredBlock {
    pub header: BlockHeader,
    pub commitment: UtxoCommitment,
    pub transactions: Vec<Transaction>,
    pub transaction_indices: Vec<u32>,
    pub spam_summary: SpamSummary,
}

/// Network client interface for UTXO commitments
///
/// In a full implementation, this would be implemented by the blvm-node's
/// network manager to send/receive P2P messages.
///
/// Note: This trait is designed for static dispatch. For dynamic dispatch,
/// use the helper functions below or wrap in a type-erased async trait.
pub trait UtxoCommitmentsNetworkClient: Send + Sync {
    /// Request UTXO set from a peer at specific height
    ///
    /// This is a synchronous interface that returns a Future.
    /// In practice, implementers will use async/await internally.
    fn request_utxo_set(
        &self,
        peer_id: &str,
        height: Natural,
        block_hash: HashType,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = UtxoCommitmentResult<UtxoCommitment>> + Send + '_>,
    >;

    /// Request filtered block from a peer
    fn request_filtered_block(
        &self,
        peer_id: &str,
        block_hash: HashType,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = UtxoCommitmentResult<FilteredBlock>> + Send + '_>,
    >;

    /// Request full block from a peer (with witnesses)
    ///
    /// Returns the full block and its witnesses for complete validation.
    /// This is required for full transaction validation during sync forward.
    fn request_full_block(
        &self,
        peer_id: &str,
        block_hash: HashType,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = UtxoCommitmentResult<FullBlock>> + Send + '_>,
    >;

    /// Get list of connected peer IDs
    fn get_peer_ids(&self) -> Vec<String>;
}

/// Full block structure with witnesses
///
/// Used for complete block validation during sync forward.
/// The commitment is computed after validation, not included here.
#[derive(Debug, Clone)]
pub struct FullBlock {
    pub block: blvm_consensus::types::Block,
    pub witnesses: Vec<Vec<blvm_consensus::segwit::Witness>>,
}

/// Helper function to request UTXO sets from multiple peers
///
/// Takes a function that can request UTXO sets (for flexibility)
pub async fn request_utxo_sets_from_peers_fn<F, Fut>(
    request_fn: F,
    peers: &[String],
    height: Natural,
    block_hash: HashType,
) -> Vec<(String, UtxoCommitmentResult<UtxoCommitment>)>
where
    F: Fn(&str, Natural, HashType) -> Fut,
    Fut: std::future::Future<Output = UtxoCommitmentResult<UtxoCommitment>>,
{
    let mut results = Vec::new();

    for peer_id in peers {
        let result = request_fn(peer_id, height, block_hash).await;
        results.push((peer_id.clone(), result));
    }

    results
}

/// Helper to process filtered block and verify commitment
pub fn process_and_verify_filtered_block(
    filtered_block: &FilteredBlock,
    expected_height: Natural,
    spam_filter: &SpamFilter,
) -> UtxoCommitmentResult<bool> {
    // Verify block header height matches expected
    // (In real implementation, would verify full header chain)

    // Verify commitment height matches
    if filtered_block.commitment.block_height != expected_height {
        return Err(UtxoCommitmentError::VerificationFailed(format!(
            "Commitment height mismatch: expected {}, got {}",
            expected_height, filtered_block.commitment.block_height
        )));
    }

    // Verify transactions are non-spam (re-apply local filter; fail closed on mismatch).
    verify_filtered_block_spam_filtering(filtered_block, spam_filter)?;

    // Verify commitment block hash matches header
    let computed_hash = compute_block_hash(&filtered_block.header);
    if filtered_block.commitment.block_hash != computed_hash {
        return Err(UtxoCommitmentError::VerificationFailed(format!(
            "Block hash mismatch: expected {:?}, got {:?}",
            computed_hash, filtered_block.commitment.block_hash
        )));
    }

    Ok(true)
}

/// Re-apply the spam filter to a peer-supplied filtered block.
///
/// The wire `FilteredBlock` carries only non-spam transactions; we verify each
/// included transaction passes the local filter. Summary counts for removed spam
/// cannot be checked without the full block — peers must not include spam txs.
fn verify_filtered_block_spam_filtering(
    filtered_block: &FilteredBlock,
    spam_filter: &SpamFilter,
) -> UtxoCommitmentResult<()> {
    for (index, tx) in filtered_block.transactions.iter().enumerate() {
        if spam_filter.is_spam(tx).is_spam {
            return Err(UtxoCommitmentError::VerificationFailed(format!(
                "Filtered block transaction {index} failed local spam filter"
            )));
        }
    }

    let (retained, recomputed_summary) = spam_filter.filter_block(&filtered_block.transactions);
    if retained.len() != filtered_block.transactions.len() {
        return Err(UtxoCommitmentError::VerificationFailed(
            "Filtered block transactions fail local spam re-filter".to_string(),
        ));
    }
    if recomputed_summary.filtered_count != 0 {
        return Err(UtxoCommitmentError::VerificationFailed(
            "Filtered block included transactions classified as spam locally".to_string(),
        ));
    }

    // Summary for removed spam txs is informational when the full block is absent.
    let _ = &filtered_block.spam_summary;

    Ok(())
}

/// Compute block header hash (double SHA256)
fn compute_block_hash(header: &BlockHeader) -> HashType {
    use sha2::{Digest, Sha256};

    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(&header.version.to_le_bytes());
    bytes.extend_from_slice(&header.prev_block_hash);
    bytes.extend_from_slice(&header.merkle_root);
    bytes.extend_from_slice(&header.timestamp.to_le_bytes());
    bytes.extend_from_slice(&header.bits.to_le_bytes());
    bytes.extend_from_slice(&header.nonce.to_le_bytes());

    let first_hash = Sha256::digest(&bytes);
    let second_hash = Sha256::digest(first_hash);

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&second_hash);
    hash
}

#[cfg(all(test, feature = "utxo-commitments"))]
mod verify_tests {
    use super::*;
    use blvm_consensus::types::{OutPoint, Transaction, TransactionInput, TransactionOutput};

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1_700_000_000,
            bits: 0x207fffff,
            nonce: 0,
        }
    }

    fn sample_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: blvm_consensus::tx_inputs![TransactionInput {
                prevout: OutPoint {
                    hash: [2u8; 32],
                    index: 0,
                },
                script_sig: vec![0x51],
                sequence: 0xffff_ffff,
            }],
            outputs: blvm_consensus::tx_outputs![TransactionOutput {
                value: 50_000,
                script_pubkey: vec![0x76, 0xa9, 0x14].repeat(20),
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn process_and_verify_filtered_block_reapplies_spam_filter() {
        let header = sample_header();
        let hash = compute_block_hash(&header);
        let spam_filter = SpamFilter::new();
        let filtered_block = FilteredBlock {
            header: header.clone(),
            commitment: UtxoCommitment {
                merkle_root: [3u8; 32],
                total_supply: 21_000_000,
                utxo_count: 1,
                block_height: 100,
                block_hash: hash,
            },
            transactions: vec![sample_tx()],
            transaction_indices: vec![0],
            spam_summary: SpamSummary::default(),
        };

        assert!(process_and_verify_filtered_block(&filtered_block, 100, &spam_filter).unwrap());
    }
}
