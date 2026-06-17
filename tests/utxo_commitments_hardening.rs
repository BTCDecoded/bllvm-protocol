#![cfg(feature = "utxo-commitments")]

//! Hardening tests: dual-path Merkle updates, negatives, and consensus → commitment bridge.
//!
//! See `docs/utxo-commitments-testing-plan.md` (minimal 90% path).

mod tests {
    use blvm_consensus::block::BlockValidationContext;
    use blvm_consensus::test_utils::{create_coinbase_tx, create_test_header};
    use blvm_consensus::types::{Block, Network, OutPoint, UTXO, UtxoSet, ValidationResult};
    use blvm_protocol::block::connect_block;
    use blvm_protocol::mining::calculate_merkle_root;
    use blvm_protocol::segwit::Witness;
    use blvm_protocol::utxo_commitments::merkle_tree::UtxoMerkleTree;
    use std::sync::Arc;

    fn sample_utxo_a() -> UTXO {
        UTXO {
            value: 10_000,
            script_pubkey: vec![0x51].into(),
            height: 0,
            is_coinbase: false,
        }
    }

    fn sample_utxo_b() -> UTXO {
        UTXO {
            value: 20_000,
            script_pubkey: vec![0x52].into(),
            height: 0,
            is_coinbase: false,
        }
    }

    /// Two independent trees with the same insert sequence must agree (regression anchor).
    #[test]
    fn golden_independent_trees_same_sequence_same_root() {
        let op1 = OutPoint {
            hash: [0x11; 32],
            index: 0,
        };
        let op2 = OutPoint {
            hash: [0x22; 32],
            index: 1,
        };

        let mut t1 = UtxoMerkleTree::new().unwrap();
        t1.insert(op1.clone(), sample_utxo_a()).unwrap();
        t1.insert(op2.clone(), sample_utxo_b()).unwrap();

        let mut t2 = UtxoMerkleTree::new().unwrap();
        t2.insert(op1.clone(), sample_utxo_a()).unwrap();
        t2.insert(op2.clone(), sample_utxo_b()).unwrap();

        assert_eq!(t1.root(), t2.root());
        assert_eq!(t1.total_supply(), t2.total_supply());
        assert_eq!(t1.utxo_count(), t2.utxo_count());
    }

    /// Incremental updates vs full `from_utxo_set` rebuild must match.
    #[test]
    fn dual_path_incremental_matches_full_rebuild() {
        let op1 = OutPoint {
            hash: [0xAA; 32],
            index: 0,
        };
        let op2 = OutPoint {
            hash: [0xBB; 32],
            index: 0,
        };
        let u1 = sample_utxo_a();
        let u2 = sample_utxo_b();

        let mut incremental = UtxoMerkleTree::new().unwrap();
        incremental.insert(op1.clone(), u1.clone()).unwrap();
        incremental.insert(op2.clone(), u2.clone()).unwrap();

        let mut utxo_set = UtxoSet::default();
        utxo_set.insert(op1, Arc::new(u1));
        utxo_set.insert(op2, Arc::new(u2));

        let rebuilt = UtxoMerkleTree::from_utxo_set(&utxo_set).unwrap();

        assert_eq!(incremental.root(), rebuilt.root());
        assert_eq!(incremental.total_supply(), rebuilt.total_supply());
        assert_eq!(incremental.utxo_count(), rebuilt.utxo_count());
    }

    /// `update_from_utxo_set` from empty → full must match `from_utxo_set`.
    #[test]
    fn dual_path_update_from_sets_matches_rebuild() {
        let op1 = OutPoint {
            hash: [0xCC; 32],
            index: 0,
        };
        let op2 = OutPoint {
            hash: [0xDD; 32],
            index: 2,
        };
        let u1 = sample_utxo_a();
        let u2 = sample_utxo_b();

        let mut new_set = UtxoSet::default();
        new_set.insert(op1.clone(), Arc::new(u1.clone()));
        new_set.insert(op2.clone(), Arc::new(u2.clone()));

        let old_set = UtxoSet::default();
        let mut tree = UtxoMerkleTree::new().unwrap();
        tree.update_from_utxo_set(&new_set, &old_set).unwrap();

        let rebuilt = UtxoMerkleTree::from_utxo_set(&new_set).unwrap();

        assert_eq!(tree.root(), rebuilt.root());
    }

    #[test]
    fn negative_proof_fails_with_wrong_utxo_payload() {
        let op = OutPoint {
            hash: [0xEE; 32],
            index: 0,
        };
        let utxo = sample_utxo_a();

        let mut tree = UtxoMerkleTree::new().unwrap();
        tree.insert(op.clone(), utxo.clone()).unwrap();

        let block_hash = [0x01; 32];
        let commitment = tree.generate_commitment(block_hash, 0);
        let proof = tree.generate_proof(&op).unwrap();

        let mut wrong = utxo.clone();
        wrong.value += 1;

        let ok = UtxoMerkleTree::verify_utxo_proof(&commitment, &op, &wrong, proof).unwrap();
        assert!(!ok, "tampered UTXO must not verify");
    }

    #[test]
    fn negative_proof_fails_with_wrong_commitment_root() {
        let op = OutPoint {
            hash: [0xFF; 32],
            index: 0,
        };
        let utxo = sample_utxo_a();

        let mut tree = UtxoMerkleTree::new().unwrap();
        tree.insert(op.clone(), utxo.clone()).unwrap();

        let mut commitment = tree.generate_commitment([0x02; 32], 1);
        commitment.merkle_root[0] ^= 0xFF;

        let proof = tree.generate_proof(&op).unwrap();
        let ok = UtxoMerkleTree::verify_utxo_proof(&commitment, &op, &utxo, proof).unwrap();
        assert!(!ok, "wrong merkle root must not verify");
    }

    /// Single coinbase block at height 0 → Merkle proof round-trip on an output in `UtxoSet`.
    #[test]
    fn connect_block_coinbase_then_merkle_proof_round_trip() {
        // Subsidy at height 0 is 5_000_000_000 satoshis (50 BTC); coinbase must not exceed subsidy + fees.
        let coinbase = create_coinbase_tx(5_000_000_000);
        let transactions = vec![coinbase];
        let merkle_root = calculate_merkle_root(&transactions).expect("merkle root");
        let mut header = create_test_header(1_231_006_505, [0u8; 32]);
        header.merkle_root = merkle_root;
        let block = Block {
            header,
            transactions: transactions.into(),
        };

        let witnesses: Vec<Vec<Witness>> = vec![Vec::new()];
        let ctx = BlockValidationContext::for_network(Network::Mainnet);
        let utxo_set = UtxoSet::default();

        let (result, new_utxo_set, _undo) =
            connect_block(&block, &witnesses, utxo_set, 0, &ctx).expect("connect_block");

        assert!(
            matches!(result, ValidationResult::Valid),
            "expected valid coinbase-only block, got {:?}",
            result
        );
        assert!(
            !new_utxo_set.is_empty(),
            "coinbase should create at least one UTXO"
        );

        let tree = UtxoMerkleTree::from_utxo_set(&new_utxo_set).expect("tree");
        let bh = [0x5e; 32];
        let height = 1u64;
        let commitment = tree.generate_commitment(bh, height);

        let (outpoint, utxo_arc) = new_utxo_set.iter().next().expect("one utxo");
        let utxo = utxo_arc.as_ref().clone();
        let proof = tree.generate_proof(outpoint).expect("proof");

        let ok =
            UtxoMerkleTree::verify_utxo_proof(&commitment, outpoint, &utxo, proof).expect("verify");
        assert!(ok);
    }
}
