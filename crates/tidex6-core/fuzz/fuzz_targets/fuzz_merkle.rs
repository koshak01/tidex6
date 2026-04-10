//! Fuzz target for `MerkleTree::insert` and `MerkleTree::proof`.
//!
//! Goal: no sequence of insert + proof operations should cause a
//! panic. The fuzzer generates a sequence of (commitment, action)
//! pairs and feeds them into a small-depth tree.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::Commitment;

fuzz_target!(|data: &[u8]| {
    // Depth 4 = 16 leaves max, keeps each run fast.
    let depth = 4;
    let Ok(mut tree) = MerkleTree::new(depth) else {
        return;
    };

    // Each 33-byte chunk is one operation: first byte selects the
    // action (insert or proof), remaining 32 are the commitment
    // bytes.
    for chunk in data.chunks_exact(33) {
        let action = chunk[0];
        let bytes: [u8; 32] = chunk[1..33].try_into().unwrap();
        let commitment = Commitment::from_bytes(bytes);

        if action & 1 == 0 {
            // Insert — may return TreeFull, but must not panic.
            let _ = tree.insert(commitment);
        } else {
            // Proof for a random leaf index derived from the
            // commitment bytes — may return OutOfRange, but must
            // not panic.
            let leaf_index = u64::from_le_bytes(bytes[..8].try_into().unwrap())
                % (tree.capacity().max(1));
            let _ = tree.proof(leaf_index);
        }
    }
});
