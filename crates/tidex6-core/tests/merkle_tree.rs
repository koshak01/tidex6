//! Integration tests for `tidex6_core::merkle`.

use tidex6_core::merkle::{DEFAULT_DEPTH, MerkleError, MerkleTree, verify_proof};
use tidex6_core::poseidon;
use tidex6_core::types::{Commitment, MerkleRoot, Nullifier, Secret};

/// A fresh tree has `next_leaf_index == 0` and its root is the hash
/// of an all-zero tree at the requested depth.
#[test]
fn empty_tree_has_deterministic_root() {
    let tree_small = MerkleTree::new(4).expect("new tree");
    assert_eq!(tree_small.depth(), 4);
    assert_eq!(tree_small.next_leaf_index(), 0);
    assert_eq!(tree_small.capacity(), 16);

    // Two fresh trees of the same depth must have the same root,
    // because the "all zeros" tree is canonical.
    let other = MerkleTree::new(4).expect("new tree");
    assert_eq!(tree_small.root(), other.root());

    // Trees of different depth must have different roots, because
    // the zero subtree grows with depth.
    let tree_bigger = MerkleTree::new(5).expect("new tree");
    assert_ne!(tree_small.root(), tree_bigger.root());
}

/// Inserting a single leaf changes the root, and the new leaf lands
/// at index 0.
#[test]
fn insert_single_leaf_changes_root() {
    let mut tree = MerkleTree::new(4).expect("new tree");
    let empty_root = tree.root();

    let leaf = Commitment::from_bytes([1u8; 32]);
    let (index, new_root) = tree.insert(leaf).expect("insert");

    assert_eq!(index, 0);
    assert_eq!(tree.next_leaf_index(), 1);
    assert_ne!(new_root, empty_root);
    assert_eq!(tree.root(), new_root);
}

/// Inserting two leaves in a row and then querying the proof for
/// each must produce proofs that verify against the current root.
#[test]
fn two_leaf_insertions_produce_verifiable_proofs() {
    let mut tree = MerkleTree::new(4).expect("new tree");

    let leaf_0 = Commitment::from_bytes([1u8; 32]);
    let leaf_1 = Commitment::from_bytes([2u8; 32]);

    let (index_0, _) = tree.insert(leaf_0).expect("insert 0");
    let (index_1, _) = tree.insert(leaf_1).expect("insert 1");
    assert_eq!(index_0, 0);
    assert_eq!(index_1, 1);

    let root = tree.root();

    let proof_0 = tree.proof(index_0).expect("proof 0");
    let proof_1 = tree.proof(index_1).expect("proof 1");

    assert!(verify_proof(leaf_0, &proof_0, root, tree.depth()).expect("verify"));
    assert!(verify_proof(leaf_1, &proof_1, root, tree.depth()).expect("verify"));
}

/// A proof must not verify against a root that the tree had before
/// the leaf was inserted.
#[test]
fn proof_does_not_verify_against_stale_root() {
    let mut tree = MerkleTree::new(4).expect("new tree");
    let stale_root = tree.root();

    let leaf = Commitment::from_bytes([3u8; 32]);
    tree.insert(leaf).expect("insert");
    let proof = tree.proof(0).expect("proof");

    let ok = verify_proof(leaf, &proof, stale_root, tree.depth()).expect("verify");
    assert!(
        !ok,
        "proof should not verify against the pre-insertion root"
    );
}

/// A proof tied to one leaf must not verify for a different leaf,
/// even if the different leaf is at the same index.
#[test]
fn proof_does_not_verify_for_wrong_leaf() {
    let mut tree = MerkleTree::new(4).expect("new tree");
    let leaf = Commitment::from_bytes([1u8; 32]);
    tree.insert(leaf).expect("insert");
    let proof = tree.proof(0).expect("proof");

    let wrong_leaf = Commitment::from_bytes([9u8; 32]);
    let ok = verify_proof(wrong_leaf, &proof, tree.root(), tree.depth()).expect("verify");
    assert!(!ok, "proof must be bound to the original leaf");
}

/// Insert leaves up to the full capacity of a small tree and check
/// that every intermediate proof verifies.
#[test]
fn fill_small_tree_and_verify_every_proof() {
    let depth = 3usize; // capacity 8
    let mut tree = MerkleTree::new(depth).expect("new tree");

    let mut leaves = Vec::new();
    for i in 0..tree.capacity() {
        let mut bytes = [0u8; 32];
        bytes[31] = (i as u8).wrapping_add(1);
        let leaf = Commitment::from_bytes(bytes);
        tree.insert(leaf).expect("insert");
        leaves.push(leaf);
    }

    // Every leaf must produce a proof that verifies against the
    // current root.
    let final_root = tree.root();
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof(i as u64).expect("proof");
        assert!(
            verify_proof(*leaf, &proof, final_root, depth).expect("verify"),
            "proof for leaf {i} must verify against the final root",
        );
    }

    // Inserting one more leaf must fail because the tree is full.
    let extra = Commitment::from_bytes([0xFFu8; 32]);
    let result = tree.insert(extra);
    assert!(matches!(result, Err(MerkleError::TreeFull { .. })));
}

/// Requesting a proof for a leaf index that was never inserted must
/// return `LeafOutOfRange`.
#[test]
fn proof_for_future_leaf_is_rejected() {
    let tree = MerkleTree::new(4).expect("new tree");
    let result = tree.proof(0);
    assert!(matches!(result, Err(MerkleError::LeafOutOfRange { .. })));
}

/// A proof whose sibling list is the wrong length must be rejected
/// at verification time rather than silently computing the wrong
/// root.
#[test]
fn verify_rejects_wrong_proof_depth() {
    let mut tree = MerkleTree::new(4).expect("new tree");
    let leaf = Commitment::from_bytes([1u8; 32]);
    tree.insert(leaf).expect("insert");

    let mut proof = tree.proof(0).expect("proof");
    proof.siblings.pop(); // now length 3, not 4

    let result = verify_proof(leaf, &proof, tree.root(), tree.depth());
    assert!(matches!(
        result,
        Err(MerkleError::ProofDepthMismatch { .. })
    ));
}

/// End-to-end flow with domain types: derive a commitment from a
/// secret-nullifier pair, insert it, then verify an inclusion proof
/// against the resulting root. Exercises the whole Day-2 / Day-3
/// primitive layer together.
#[test]
fn commitment_and_merkle_flow_together() {
    let secret = Secret::from_bytes([0x11u8; 32]);
    let nullifier = Nullifier::from_bytes([0x22u8; 32]);

    let commitment = Commitment::derive(&secret, &nullifier).expect("derive commitment");

    let mut tree = MerkleTree::new(DEFAULT_DEPTH).expect("new default-depth tree");
    let (leaf_index, root) = tree.insert(commitment).expect("insert");
    assert_eq!(leaf_index, 0);

    let proof = tree.proof(leaf_index).expect("proof");
    assert!(
        verify_proof(commitment, &proof, root, DEFAULT_DEPTH).expect("verify"),
        "inclusion proof for the depositor's commitment must verify against the pool root",
    );
}

/// The root after a single insertion at index 0 in a depth-1 tree
/// equals Poseidon(leaf, zero_leaf). This exercises the leaf-level
/// hashing path directly against the Poseidon primitive.
#[test]
fn depth_one_root_matches_direct_poseidon() {
    let mut tree = MerkleTree::new(1).expect("new tree");

    let leaf = Commitment::from_bytes([0x07u8; 32]);
    let (_, root) = tree.insert(leaf).expect("insert");

    let zero_leaf = [0u8; 32];
    let expected = poseidon::hash_pair(leaf.as_bytes(), &zero_leaf).expect("hash_pair");

    assert_eq!(root, MerkleRoot::from_bytes(expected));
}
