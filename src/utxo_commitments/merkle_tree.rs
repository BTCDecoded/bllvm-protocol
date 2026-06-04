//! UTXO Merkle Tree Implementation
//!
//! Wraps sparse-merkle-tree to provide UTXO-specific operations.
//! Handles incremental updates (insert/remove) and proof generation.

#[cfg(feature = "utxo-commitments")]
use crate::utxo_commitments::data_structures::{
    UtxoCommitment, UtxoCommitmentError, UtxoCommitmentResult,
};
#[cfg(feature = "utxo-commitments")]
use blvm_consensus::types::{Hash, Natural, OutPoint, UTXO};
#[cfg(feature = "utxo-commitments")]
use blvm_spec_lock::spec_locked;
#[cfg(feature = "utxo-commitments")]
use sha2::{Digest, Sha256};
#[cfg(feature = "utxo-commitments")]
use sparse_merkle_tree::default_store::DefaultStore;
#[cfg(feature = "utxo-commitments")]
use sparse_merkle_tree::traits::{Hasher, Value};
#[cfg(feature = "utxo-commitments")]
use sparse_merkle_tree::{SparseMerkleTree, H256};
#[cfg(feature = "utxo-commitments")]
use std::collections::HashMap;

/// SHA256 hasher for UTXO Merkle tree
#[cfg(feature = "utxo-commitments")]
#[derive(Default, Clone, Debug)]
pub struct UtxoHasher {
    hasher: Sha256,
}

#[cfg(feature = "utxo-commitments")]
impl Hasher for UtxoHasher {
    fn write_h256(&mut self, h: &H256) {
        // H256 has as_slice() method
        self.hasher.update(h.as_slice());
    }

    fn write_byte(&mut self, b: u8) {
        self.hasher.update(&[b]);
    }

    fn finish(self) -> H256 {
        let hash = self.hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        H256::from(bytes)
    }
}

/// UTXO value type for sparse merkle tree
#[cfg(feature = "utxo-commitments")]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct UtxoValue {
    pub data: Vec<u8>,
}

#[cfg(feature = "utxo-commitments")]
impl Value for UtxoValue {
    fn to_h256(&self) -> H256 {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        H256::from(bytes)
    }

    fn zero() -> Self {
        Self { data: Vec::new() }
    }
}

/// UTXO Merkle Tree
///
/// Provides incremental updates for UTXO set with Merkle tree commitments.
/// Wraps sparse-merkle-tree to provide UTXO-specific operations.
#[cfg(feature = "utxo-commitments")]
pub struct UtxoMerkleTree {
    tree: SparseMerkleTree<UtxoHasher, UtxoValue, DefaultStore<UtxoValue>>,
    #[allow(dead_code)] // Reserved for future use: Map OutPoint to leaf position
    utxo_index: HashMap<OutPoint, usize>,
    total_supply: u64,
    utxo_count: u64,
}

#[cfg(feature = "utxo-commitments")]
impl UtxoMerkleTree {
    /// Create a new empty UTXO Merkle tree
    pub fn new() -> UtxoCommitmentResult<Self> {
        let store = DefaultStore::default();
        let tree = SparseMerkleTree::new_with_store(store).map_err(|e| {
            UtxoCommitmentError::MerkleTreeError(format!("Failed to create tree: {:?}", e))
        })?;

        Ok(Self {
            tree,
            utxo_index: HashMap::new(),
            total_supply: 0,
            utxo_count: 0,
        })
    }

    /// Get the Merkle root of the UTXO set
    pub fn root(&self) -> Hash {
        let root_h256 = self.tree.root();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(root_h256.as_slice());
        hash
    }

    /// Insert a UTXO into the tree
    pub fn insert(&mut self, outpoint: OutPoint, utxo: UTXO) -> UtxoCommitmentResult<Hash> {
        // Hash the OutPoint to get a key
        let key = self.hash_outpoint(&outpoint);

        // Serialize UTXO to value
        let value = self.serialize_utxo(&utxo)?;
        let utxo_value = UtxoValue { data: value };

        // Update tree
        let root_h256 = self
            .tree
            .update(key, utxo_value)
            .map_err(|e| UtxoCommitmentError::MerkleTreeError(format!("Update failed: {:?}", e)))?;

        // Update tracking with checked arithmetic
        let old_supply = self.total_supply;
        self.total_supply = self
            .total_supply
            .checked_add(utxo.value as u64)
            .ok_or_else(|| {
                UtxoCommitmentError::MerkleTreeError("Total supply overflow".to_string())
            })?;
        self.utxo_count = self.utxo_count.checked_add(1).ok_or_else(|| {
            UtxoCommitmentError::MerkleTreeError("UTXO count overflow".to_string())
        })?;

        // Runtime assertion: Supply must increase
        debug_assert!(
            self.total_supply >= old_supply,
            "Total supply ({}) must be >= previous supply ({})",
            self.total_supply,
            old_supply
        );

        // Convert H256 to Hash
        let mut hash = [0u8; 32];
        hash.copy_from_slice(root_h256.as_slice());
        Ok(hash)
    }

    /// Remove a UTXO from the tree (by updating with zero value)
    pub fn remove(&mut self, outpoint: &OutPoint, utxo: &UTXO) -> UtxoCommitmentResult<Hash> {
        // Hash the OutPoint to get a key
        let key = self.hash_outpoint(outpoint);

        // For sparse merkle tree, we update with zero value to delete
        let zero_value = UtxoValue::zero();

        // Update tree (effectively removes the UTXO)
        let root_h256 = self
            .tree
            .update(key, zero_value)
            .map_err(|e| UtxoCommitmentError::MerkleTreeError(format!("Remove failed: {:?}", e)))?;

        // Update tracking with checked arithmetic
        let old_supply = self.total_supply;
        let old_count = self.utxo_count;

        self.total_supply = self.total_supply.saturating_sub(utxo.value as u64);
        self.utxo_count = self.utxo_count.saturating_sub(1);

        // Runtime assertion: Supply must decrease (or saturate at 0)
        debug_assert!(
            self.total_supply <= old_supply,
            "Total supply ({}) must be <= previous supply ({})",
            self.total_supply,
            old_supply
        );

        // Runtime assertion: Count must decrease (or saturate at 0)
        debug_assert!(
            self.utxo_count <= old_count,
            "UTXO count ({}) must be <= previous count ({})",
            self.utxo_count,
            old_count
        );

        // Runtime assertion: Supply and count must be non-negative
        debug_assert!(
            // total_supply is u64, so this check is always true - removed
            true,
            "Total supply ({}) must be within u64 bounds",
            self.total_supply
        );
        debug_assert!(
            // utxo_count is u64, so this check is always true - removed
            true,
            "UTXO count ({}) must be within u64 bounds",
            self.utxo_count
        );

        // Convert H256 to Hash
        let mut hash = [0u8; 32];
        hash.copy_from_slice(root_h256.as_slice());
        Ok(hash)
    }

    /// Get a UTXO from the tree
    pub fn get(&self, outpoint: &OutPoint) -> UtxoCommitmentResult<Option<UTXO>> {
        let key = self.hash_outpoint(outpoint);

        match self.tree.get(&key) {
            Ok(value) => {
                // Check if value is zero (empty)
                if value.to_h256() == H256::zero() || value.to_h256() == UtxoValue::zero().to_h256()
                {
                    Ok(None)
                } else {
                    // Extract serialized data from UtxoValue and deserialize
                    let serialized_data = &value.data;

                    // Deserialize the UTXO data
                    match self.deserialize_utxo(serialized_data) {
                        Ok(utxo) => Ok(Some(utxo)),
                        Err(e) => {
                            // Deserialization failed - this might indicate corrupted data
                            Err(UtxoCommitmentError::InvalidUtxo(format!(
                                "Failed to deserialize UTXO: {}",
                                e
                            )))
                        }
                    }
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Generate a UTXO commitment
    #[spec_locked("11.4", "GenerateCommitment")]
    #[blvm_spec_lock::ensures(result.block_height == block_height)]
    #[blvm_spec_lock::ensures(result.block_hash == block_hash)]
    pub fn generate_commitment(&self, block_hash: Hash, block_height: Natural) -> UtxoCommitment {
        let merkle_root = self.root();
        UtxoCommitment::new(
            merkle_root,
            self.total_supply,
            self.utxo_count,
            block_height,
            block_hash,
        )
    }

    /// Get total supply
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    /// Get UTXO count
    pub fn utxo_count(&self) -> u64 {
        self.utxo_count
    }

    /// Generate a Merkle proof for a specific UTXO
    ///
    /// Returns a proof that can be used to verify the UTXO exists in the tree.
    pub fn generate_proof(
        &self,
        outpoint: &OutPoint,
    ) -> UtxoCommitmentResult<sparse_merkle_tree::MerkleProof> {
        let key = self.hash_outpoint(outpoint);
        let keys = vec![key];

        self.tree.merkle_proof(keys).map_err(|e| {
            UtxoCommitmentError::MerkleTreeError(format!("Failed to generate proof: {:?}", e))
        })
    }

    /// Serialize a Merkle proof to bytes for wire transmission.
    ///
    /// Call this from network handlers (e.g. blvm-node) to avoid serde trait
    /// resolution issues when multiple serde versions exist in the dependency tree.
    pub fn serialize_proof_for_wire(
        proof: sparse_merkle_tree::MerkleProof,
    ) -> UtxoCommitmentResult<Vec<u8>> {
        let (leaves_bitmap, merkle_path) = proof.take();
        // Custom format: length-prefixed H256 arrays. H256::as_slice() gives 32 bytes each.
        let mut buf = Vec::new();
        buf.extend_from_slice(&(leaves_bitmap.len() as u32).to_le_bytes());
        for h in &leaves_bitmap {
            buf.extend_from_slice(h.as_slice());
        }
        buf.extend_from_slice(&(merkle_path.len() as u32).to_le_bytes());
        for mv in &merkle_path {
            match mv {
                sparse_merkle_tree::merge::MergeValue::Value(v) => {
                    buf.push(0);
                    buf.extend_from_slice(v.as_slice());
                }
                sparse_merkle_tree::merge::MergeValue::MergeWithZero {
                    base_node,
                    zero_bits,
                    zero_count,
                } => {
                    buf.push(1);
                    buf.extend_from_slice(base_node.as_slice());
                    buf.extend_from_slice(zero_bits.as_slice());
                    buf.push(*zero_count);
                }
            }
        }
        Ok(buf)
    }

    /// Deserialize a Merkle proof from bytes (inverse of serialize_proof_for_wire).
    pub fn deserialize_proof_from_wire(
        bytes: &[u8],
    ) -> UtxoCommitmentResult<sparse_merkle_tree::MerkleProof> {
        use sparse_merkle_tree::merge::MergeValue;
        if bytes.len() < 8 {
            return Err(UtxoCommitmentError::MerkleTreeError(
                "proof too short".to_string(),
            ));
        }
        let mut pos = 0;
        let leaves_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        // `leaves_len` digest-sized leaves, then 4 bytes for `path_len` (untrusted / malicious wire).
        let min_after_header = match leaves_len.checked_mul(32).and_then(|b| b.checked_add(4)) {
            Some(n) => n,
            None => {
                return Err(UtxoCommitmentError::MerkleTreeError(
                    "invalid proof: leaves count overflow".to_string(),
                ));
            }
        };
        let end = match pos.checked_add(min_after_header) {
            Some(e) => e,
            None => {
                return Err(UtxoCommitmentError::MerkleTreeError(
                    "invalid proof: size overflow".to_string(),
                ));
            }
        };
        if end > bytes.len() {
            return Err(UtxoCommitmentError::MerkleTreeError(
                "proof truncated at leaves_bitmap".to_string(),
            ));
        }
        let mut leaves_bitmap = Vec::with_capacity(leaves_len);
        for _ in 0..leaves_len {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[pos..pos + 32]);
            leaves_bitmap.push(H256::from(arr));
            pos += 32;
        }
        let path_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        // Each path entry is at least 33 bytes (tag + 32-byte H256 for Value).
        let max_path = (bytes.len().saturating_sub(pos)) / 33;
        if path_len > max_path {
            return Err(UtxoCommitmentError::MerkleTreeError(
                "proof truncated or path count impossible for input size".to_string(),
            ));
        }
        let mut merkle_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            if pos >= bytes.len() {
                return Err(UtxoCommitmentError::MerkleTreeError(
                    "proof truncated at merkle_path".to_string(),
                ));
            }
            let tag = bytes[pos];
            pos += 1;
            match tag {
                0 => {
                    if pos + 32 > bytes.len() {
                        return Err(UtxoCommitmentError::MerkleTreeError(
                            "proof truncated at MergeValue::Value".to_string(),
                        ));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[pos..pos + 32]);
                    merkle_path.push(MergeValue::Value(H256::from(arr)));
                    pos += 32;
                }
                1 => {
                    if pos + 65 > bytes.len() {
                        return Err(UtxoCommitmentError::MerkleTreeError(
                            "proof truncated at MergeValue::MergeWithZero".to_string(),
                        ));
                    }
                    let mut base = [0u8; 32];
                    base.copy_from_slice(&bytes[pos..pos + 32]);
                    let mut bits = [0u8; 32];
                    bits.copy_from_slice(&bytes[pos + 32..pos + 64]);
                    let zc = bytes[pos + 64];
                    merkle_path.push(MergeValue::MergeWithZero {
                        base_node: H256::from(base),
                        zero_bits: H256::from(bits),
                        zero_count: zc,
                    });
                    pos += 65;
                }
                _ => {
                    return Err(UtxoCommitmentError::MerkleTreeError(format!(
                        "invalid proof tag: {}",
                        tag
                    )));
                }
            }
        }
        Ok(sparse_merkle_tree::MerkleProof::new(
            leaves_bitmap,
            merkle_path,
        ))
    }

    /// Verify a UTXO commitment matches expected supply
    ///
    /// Compares the total supply in the commitment against the expected
    /// Bitcoin supply at the given block height.
    pub fn verify_commitment_supply(
        &self,
        commitment: &UtxoCommitment,
    ) -> UtxoCommitmentResult<bool> {
        use blvm_consensus::economic::total_supply;

        let expected_supply = total_supply(commitment.block_height) as u64;
        let matches = commitment.total_supply == expected_supply;

        if !matches {
            return Err(UtxoCommitmentError::VerificationFailed(format!(
                "Supply mismatch: commitment has {}, expected {}",
                commitment.total_supply, expected_supply
            )));
        }

        Ok(true)
    }

    /// Rebuild tree from UtxoSet
    ///
    /// Used after connect_block() to update the Merkle tree
    /// with the validated UTXO set. This rebuilds the entire tree.
    pub fn from_utxo_set(utxo_set: &crate::types::UtxoSet) -> UtxoCommitmentResult<Self> {
        let mut tree = Self::new()?;
        for (outpoint, utxo) in utxo_set {
            tree.insert(outpoint.clone(), utxo.as_ref().clone())?;
        }
        Ok(tree)
    }

    /// Update tree from UtxoSet (incremental update)
    ///
    /// Compares current tree state with new UtxoSet and applies
    /// only the differences. More efficient than full rebuild.
    ///
    /// **Note**: This function requires knowing the previous UtxoSet to
    /// efficiently detect removals. If the previous set is not available,
    /// use `from_utxo_set()` to rebuild the tree.
    ///
    /// # Arguments
    ///
    /// * `new_utxo_set` - The new UTXO set (from connect_block)
    /// * `old_utxo_set` - The previous UTXO set (for detecting removals)
    pub fn update_from_utxo_set(
        &mut self,
        new_utxo_set: &crate::types::UtxoSet,
        old_utxo_set: &crate::types::UtxoSet,
    ) -> UtxoCommitmentResult<Hash> {
        // Find removed UTXOs (in old but not in new)
        for (outpoint, old_utxo) in old_utxo_set {
            if !new_utxo_set.contains_key(outpoint) {
                self.remove(outpoint, old_utxo.as_ref())?;
            }
        }

        // Find added/modified UTXOs
        for (outpoint, new_utxo) in new_utxo_set {
            match old_utxo_set.get(outpoint) {
                Some(old_utxo) if old_utxo == new_utxo => {}
                _ => {
                    if let Some(old_utxo) = old_utxo_set.get(outpoint) {
                        self.remove(outpoint, old_utxo.as_ref())?;
                    }
                    self.insert(outpoint.clone(), new_utxo.as_ref().clone())?;
                }
            }
        }

        Ok(self.root())
    }

    /// Convert UtxoMerkleTree to UtxoSet
    ///
    /// Iterates through the tree and builds a UtxoSet.
    /// Note: This is expensive as sparse merkle trees don't support
    /// efficient iteration. Use only when necessary.
    pub fn to_utxo_set(&self) -> UtxoCommitmentResult<crate::types::UtxoSet> {
        // Sparse merkle tree does not support efficient iteration.
        // Conversion would require utxo_index or a separate HashMap<OutPoint, UTXO>
        // kept in sync with the tree. Use update_from_utxo_set() for tree updates.
        Err(UtxoCommitmentError::MerkleTreeError(
            "UtxoMerkleTree iteration not efficiently supported. Use update_from_utxo_set() instead.".to_string()
        ))
    }

    /// Verify a commitment's Merkle root matches the tree's root
    pub fn verify_commitment_root(&self, commitment: &UtxoCommitment) -> bool {
        let tree_root = self.root();
        commitment.merkle_root == tree_root
    }

    /// Verify a UTXO Merkle proof against a commitment's root
    ///
    /// This is a static/associated function - it doesn't need a tree instance,
    /// only the commitment's merkle root for verification.
    ///
    /// This function cryptographically verifies that a UTXO exists in the
    /// commitment's UTXO set without requiring the full tree.
    ///
    /// # Arguments
    /// * `commitment` - The UTXO commitment containing the merkle root
    /// * `outpoint` - The outpoint to verify
    /// * `utxo` - The UTXO data to verify
    /// * `proof` - The Merkle proof (takes ownership)
    ///
    /// # Returns
    /// `Ok(true)` if proof is valid, `Ok(false)` or `Err` if invalid
    pub fn verify_utxo_proof(
        commitment: &UtxoCommitment,
        outpoint: &OutPoint,
        utxo: &UTXO,
        proof: sparse_merkle_tree::MerkleProof,
    ) -> UtxoCommitmentResult<bool> {
        // 1. Hash outpoint to get key (H256)
        let key = Self::hash_outpoint_static(outpoint);

        // 2. Serialize UTXO to bytes
        let utxo_bytes = Self::serialize_utxo_static(utxo)?;

        // 3. Hash UTXO bytes to get value (H256)
        // The verify() method expects H256 (hashed value), not raw bytes
        let utxo_value = UtxoValue { data: utxo_bytes };
        let value_h256 = utxo_value.to_h256();

        // 4. Convert commitment root to H256
        let root_h256 = H256::from(commitment.merkle_root);

        // 5. Create leaves vector: [(key, value_hash)]
        let leaves = vec![(key, value_h256)];

        // 6. Verify proof using library's verify method
        let is_valid = proof
            .verify::<UtxoHasher>(&root_h256, leaves)
            .map_err(|e| {
                UtxoCommitmentError::VerificationFailed(format!(
                    "Proof verification failed: {:?}",
                    e
                ))
            })?;

        Ok(is_valid)
    }

    // Helper methods

    /// Hash an OutPoint to H256 key
    fn hash_outpoint(&self, outpoint: &OutPoint) -> H256 {
        Self::hash_outpoint_static(outpoint)
    }

    /// Static helper: Hash an OutPoint to H256 key
    ///
    /// This is used by both instance methods and the static verify function.
    fn hash_outpoint_static(outpoint: &OutPoint) -> H256 {
        let mut hasher = Sha256::new();
        hasher.update(&outpoint.hash);
        hasher.update(&outpoint.index.to_be_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        H256::from(bytes)
    }

    /// Serialize UTXO to bytes
    fn serialize_utxo(&self, utxo: &UTXO) -> UtxoCommitmentResult<Vec<u8>> {
        Self::serialize_utxo_static(utxo)
    }

    /// Static helper: Serialize UTXO to bytes
    ///
    /// Serialization format: value (8 bytes) + height (8 bytes) + is_coinbase (1 byte) + script_len (1 byte) + script_pubkey (variable)
    ///
    /// This is used by both instance methods and the static verify function.
    fn serialize_utxo_static(utxo: &UTXO) -> UtxoCommitmentResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(17 + utxo.script_pubkey.len());
        bytes.extend_from_slice(&utxo.value.to_be_bytes());
        bytes.extend_from_slice(&utxo.height.to_be_bytes());
        bytes.push(if utxo.is_coinbase { 1 } else { 0 });
        bytes.push(utxo.script_pubkey.len() as u8);
        bytes.extend_from_slice(utxo.script_pubkey.as_ref());
        Ok(bytes)
    }

    /// Deserialize bytes to UTXO
    fn deserialize_utxo(&self, data: &[u8]) -> UtxoCommitmentResult<UTXO> {
        if data.len() < 18 {
            return Err(UtxoCommitmentError::InvalidUtxo(
                "Data too short".to_string(),
            ));
        }

        let mut offset = 0;
        let value = i64::from_be_bytes(
            data[offset..offset + 8]
                .try_into()
                .map_err(|_| UtxoCommitmentError::InvalidUtxo("Invalid value".to_string()))?,
        );
        offset += 8;

        let height = u64::from_be_bytes(
            data[offset..offset + 8]
                .try_into()
                .map_err(|_| UtxoCommitmentError::InvalidUtxo("Invalid height".to_string()))?,
        );
        offset += 8;

        let is_coinbase = data[offset] != 0;
        offset += 1;

        let script_len = data[offset] as usize;
        offset += 1;

        if data.len() < offset + script_len {
            return Err(UtxoCommitmentError::InvalidUtxo(
                "Script length mismatch".to_string(),
            ));
        }

        let script_pubkey =
            crate::types::SharedByteString::from(&data[offset..offset + script_len]);

        Ok(UTXO {
            value,
            script_pubkey,
            height,
            is_coinbase,
        })
    }
}

#[cfg(feature = "utxo-commitments")]
impl Default for UtxoMerkleTree {
    /// Prefer [`UtxoMerkleTree::new`] in code that can handle allocation failure.
    ///
    /// `Default` panics if the underlying sparse Merkle tree cannot be constructed (e.g. severe
    /// memory pressure). This matches “default must be infallible” call sites but is not ideal for
    /// untrusted or resource-constrained environments.
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            panic!(
                "Failed to create default UtxoMerkleTree: {:?}. This indicates a critical system error.",
                e
            )
        })
    }
}

// Placeholder implementation when feature is disabled
#[cfg(not(feature = "utxo-commitments"))]
pub struct UtxoMerkleTree;

#[cfg(not(feature = "utxo-commitments"))]
impl UtxoMerkleTree {
    pub fn new() -> Result<Self, String> {
        Err("UTXO commitments feature not enabled".to_string())
    }
}

#[cfg(all(test, feature = "utxo-commitments"))]
mod deserialize_proof_from_wire_tests {
    use super::UtxoMerkleTree;

    /// 39 B: `leaves_len=1` + 32 B leaf, only 3 B left; must not index `path_len` past end.
    #[test]
    fn wire_proof_rejects_without_space_for_path_length() {
        const DATA: [u8; 39] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(UtxoMerkleTree::deserialize_proof_from_wire(&DATA).is_err());
    }
}

// ============================================================================
// FORMAL VERIFICATION
// ============================================================================

/// Mathematical Specification for UTXO Merkle Tree:
/// ∀ tree ∈ UtxoMerkleTree, outpoint ∈ OutPoint, utxo ∈ UTXO:
/// - insert(tree, outpoint, utxo) = tree' where tree'.total_supply = tree.total_supply + utxo.value
/// - remove(tree, outpoint, utxo) = tree' where tree'.total_supply = tree.total_supply - utxo.value
/// - root(tree) is deterministic (same tree → same root)
/// - Commitment consistency: commitment.total_supply matches tree.total_supply
///
/// Invariants:
/// - Supply tracking is accurate (never negative, matches UTXO set)
/// - Merkle root is deterministic for same UTXO set
/// - Tree operations preserve consistency
#[doc(hidden)]
const _UTXO_MERKLE_TREE_SPEC: () = ();

// End of module
