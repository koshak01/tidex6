//! Offchain Merkle tree used by the shielded pool.
//!
//! The tree is append-only, of fixed depth, and hashes its internal
//! nodes with the same circom-compatible Poseidon parameters as the
//! onchain `sol_poseidon` syscall (see `tidex6_core::poseidon`). The
//! onchain program stores only a ring buffer of recent roots and a
//! next-leaf-index counter — the full tree lives here and is
//! rebuilt by the indexer from `DepositEvent` logs. ADR-002.
//!
//! # Empty subtree optimisation
//!
//! A depth-20 tree has 2²⁰ ≈ 1 048 576 leaf slots, of which the
//! overwhelming majority are zero for any realistic pool state. This
//! implementation therefore precomputes the "zero subtree" hash at
//! every level — the hash you get when every leaf below that level
//! is `Commitment::zero()`. Inserting a new leaf then only has to
//! recompute the path from that leaf up to the root, touching at
//! most `depth` intermediate nodes regardless of how many leaves are
//! already in the tree.
//!
//! # Leaf / internal node encoding
//!
//! - A leaf is a `Commitment` (32 bytes, a BN254 scalar field element).
//! - An internal node is `Poseidon(left, right)` using `hash_pair`.
//! - An empty leaf is `Commitment::zero()`.

use crate::poseidon::{self, PoseidonError};
use crate::types::{Commitment, MerkleRoot};

/// Default Merkle tree depth used by the shielded pool.
///
/// Depth 20 gives a capacity of 2²⁰ = 1 048 576 leaves. The onchain
/// verifier only stores recent roots, so the tree itself lives
/// offchain and the cost of growing it is bounded by this constant
/// rather than by account-size limits.
pub const DEFAULT_DEPTH: usize = 20;

/// Errors produced by `MerkleTree` operations.
#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    /// The Poseidon primitive returned an error while hashing an
    /// internal node. In practice this should never happen because
    /// every value in the tree is a hash output and therefore a
    /// valid field element.
    #[error("poseidon hash failed while updating the tree: {0}")]
    Poseidon(#[from] PoseidonError),

    /// An attempt was made to insert a leaf into a tree that is
    /// already full, or to read a proof for an out-of-range leaf
    /// index.
    #[error("tree is full at {capacity} leaves")]
    TreeFull { capacity: u64 },

    /// A Merkle proof request referred to a leaf index that has not
    /// been written yet.
    #[error("leaf index {requested} is out of range; next_leaf_index is {next_leaf_index}")]
    LeafOutOfRange {
        requested: u64,
        next_leaf_index: u64,
    },

    /// A Merkle proof was supplied with a sibling list whose length
    /// does not match the tree depth.
    #[error("merkle proof has {got} siblings but tree depth is {expected}")]
    ProofDepthMismatch { got: usize, expected: usize },
}

/// One authenticated inclusion proof for a leaf in a Merkle tree.
///
/// The `siblings` vector contains the `depth` sibling hashes from
/// the leaf up to (but not including) the root, ordered from the
/// bottom level towards the top. `leaf_index` is needed because each
/// sibling can be either the left or the right child of its parent,
/// and the bit at position `i` of `leaf_index` tells the verifier
/// which side `siblings[i]` sits on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub siblings: Vec<Commitment>,
    pub root: MerkleRoot,
}

/// An append-only offchain Merkle tree over `Commitment` leaves.
#[derive(Clone)]
pub struct MerkleTree {
    depth: usize,
    /// `filled_subtrees[level]` is the hash of the left-most subtree
    /// at `level` that has been "committed to" by the current
    /// insertion order. Used to avoid recomputing known-good
    /// subtrees when appending a new leaf.
    filled_subtrees: Vec<Commitment>,
    /// `zero_subtrees[level]` is the hash of a subtree of height
    /// `level` whose every leaf is `Commitment::zero()`. Precomputed
    /// once at construction and never mutated afterwards.
    zero_subtrees: Vec<Commitment>,
    /// Number of leaves already inserted. Always in `0..=capacity`.
    next_leaf_index: u64,
    /// Current root of the tree.
    root: MerkleRoot,
    /// Full list of leaves, in insertion order. Kept so the tree
    /// can serve Merkle proofs without replaying the entire
    /// insertion history.
    leaves: Vec<Commitment>,
}

impl MerkleTree {
    /// Construct an empty tree of `depth` levels. Precomputes the
    /// zero-subtree hashes and sets the initial root to the hash of
    /// an all-zero tree at the requested depth.
    pub fn new(depth: usize) -> Result<Self, MerkleError> {
        assert!(depth >= 1, "tree depth must be at least 1");
        assert!(
            depth <= 32,
            "tree depth must fit in u64 capacity (depth <= 32)"
        );

        let mut zero_subtrees = Vec::with_capacity(depth + 1);
        zero_subtrees.push(Commitment::zero());
        for level in 1..=depth {
            let child = zero_subtrees[level - 1];
            let parent_bytes = poseidon::hash_pair(child.as_bytes(), child.as_bytes())?;
            zero_subtrees.push(Commitment::from_bytes(parent_bytes));
        }

        let filled_subtrees = zero_subtrees[..depth].to_vec();
        let root_commitment = zero_subtrees[depth];

        Ok(Self {
            depth,
            filled_subtrees,
            zero_subtrees,
            next_leaf_index: 0,
            root: MerkleRoot::from_bytes(root_commitment.to_bytes()),
            leaves: Vec::new(),
        })
    }

    /// The tree depth this instance was constructed with.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Maximum number of leaves the tree can hold.
    pub fn capacity(&self) -> u64 {
        1u64 << self.depth
    }

    /// Number of leaves currently inserted.
    pub fn next_leaf_index(&self) -> u64 {
        self.next_leaf_index
    }

    /// Current Merkle root.
    pub fn root(&self) -> MerkleRoot {
        self.root
    }

    /// Append a new leaf to the next free slot. Returns the leaf
    /// index the commitment was written to and the new root.
    pub fn insert(&mut self, leaf: Commitment) -> Result<(u64, MerkleRoot), MerkleError> {
        if self.next_leaf_index >= self.capacity() {
            return Err(MerkleError::TreeFull {
                capacity: self.capacity(),
            });
        }

        let leaf_index = self.next_leaf_index;
        self.leaves.push(leaf);
        self.next_leaf_index += 1;

        let mut current_index = leaf_index;
        let mut current_hash = leaf;
        for level in 0..self.depth {
            let (left, right) = if current_index & 1 == 0 {
                // current node is a left child — pair it with the
                // empty-right placeholder at this level.
                self.filled_subtrees[level] = current_hash;
                (current_hash, self.zero_subtrees[level])
            } else {
                // current node is a right child — pair it with the
                // previously stored left sibling.
                (self.filled_subtrees[level], current_hash)
            };
            let parent_bytes = poseidon::hash_pair(left.as_bytes(), right.as_bytes())?;
            current_hash = Commitment::from_bytes(parent_bytes);
            current_index >>= 1;
        }

        self.root = MerkleRoot::from_bytes(current_hash.to_bytes());
        Ok((leaf_index, self.root))
    }

    /// Produce an inclusion proof for the leaf at `leaf_index`.
    ///
    /// The proof walks the tree from the leaf to the root and
    /// records each sibling along the way. An empty position is
    /// recorded as the appropriate `zero_subtrees[level]` value, so
    /// a verifier that does not know which positions are empty can
    /// still compute the root by hashing up.
    pub fn proof(&self, leaf_index: u64) -> Result<MerkleProof, MerkleError> {
        if leaf_index >= self.next_leaf_index {
            return Err(MerkleError::LeafOutOfRange {
                requested: leaf_index,
                next_leaf_index: self.next_leaf_index,
            });
        }

        let mut siblings = Vec::with_capacity(self.depth);
        // `current_level_nodes` holds the hashes of every node at
        // the current level that we care about. We only materialise
        // the prefix that has been touched by actual insertions; the
        // rest of the level is `zero_subtrees[level]`.
        let mut current_level_nodes: Vec<Commitment> = self.leaves.clone();

        let mut index = leaf_index;
        for level in 0..self.depth {
            let sibling_index = index ^ 1;
            let sibling = current_level_nodes
                .get(sibling_index as usize)
                .copied()
                .unwrap_or(self.zero_subtrees[level]);
            siblings.push(sibling);

            // Compute the next level by pairing siblings. Pad the
            // right edge of the level with the empty-subtree value.
            let mut next_level_nodes = Vec::with_capacity(current_level_nodes.len().div_ceil(2));
            let mut chunk_start = 0usize;
            while chunk_start < current_level_nodes.len() {
                let left = current_level_nodes[chunk_start];
                let right = current_level_nodes
                    .get(chunk_start + 1)
                    .copied()
                    .unwrap_or(self.zero_subtrees[level]);
                let parent_bytes = poseidon::hash_pair(left.as_bytes(), right.as_bytes())?;
                next_level_nodes.push(Commitment::from_bytes(parent_bytes));
                chunk_start += 2;
            }
            current_level_nodes = next_level_nodes;
            index >>= 1;
        }

        Ok(MerkleProof {
            leaf_index,
            siblings,
            root: self.root,
        })
    }
}

/// Verify a `MerkleProof` against a known-good root. Returns `true`
/// iff the leaf at `proof.leaf_index` with value `leaf` hashes up to
/// `expected_root` via the proof's sibling chain.
pub fn verify_proof(
    leaf: Commitment,
    proof: &MerkleProof,
    expected_root: MerkleRoot,
    depth: usize,
) -> Result<bool, MerkleError> {
    if proof.siblings.len() != depth {
        return Err(MerkleError::ProofDepthMismatch {
            got: proof.siblings.len(),
            expected: depth,
        });
    }

    let mut index = proof.leaf_index;
    let mut current = leaf;
    for sibling in &proof.siblings {
        let (left, right) = if index & 1 == 0 {
            (current, *sibling)
        } else {
            (*sibling, current)
        };
        let parent_bytes = poseidon::hash_pair(left.as_bytes(), right.as_bytes())?;
        current = Commitment::from_bytes(parent_bytes);
        index >>= 1;
    }

    Ok(current.to_bytes() == expected_root.to_bytes())
}
