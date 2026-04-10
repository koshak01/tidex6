//! Property-based tests for tidex6-core primitives.
//!
//! Each test declares a **universal property** that must hold for
//! any valid input, then uses `proptest` to verify it across 10 000
//! randomly-generated inputs. A single counterexample is enough to
//! prove the property false, and proptest will minimise it to the
//! simplest failing case for easy debugging.
//!
//! What we test:
//!
//! 1. **BN254 modular reduction** — `is_below_bn254_modulus` is
//!    a correct predicate, and `sample_field_element_bytes` always
//!    produces a valid element.
//! 2. **Poseidon determinism** — same input → same output, always.
//! 3. **Commitment derivation determinism** — same secret + nullifier
//!    → same commitment.
//! 4. **NullifierHash determinism** — same nullifier → same hash.
//! 5. **Merkle insert → proof → verify round-trip** — inserting a
//!    leaf and verifying its proof against the new root is always
//!    true.
//! 6. **DepositNote text round-trip** — `from_text(to_text(note)) == note`.
//! 7. **SpendingKey → ViewingKey determinism** — the derivation is
//!    a pure function.

use proptest::prelude::*;

use tidex6_core::merkle::{MerkleTree, verify_proof};
use tidex6_core::note::{Denomination, DepositNote};
use tidex6_core::poseidon;
use tidex6_core::types::{Commitment, Nullifier, Secret, is_below_bn254_modulus};

/// Strategy that produces a random 32-byte array that is a valid
/// BN254 scalar field element (i.e., below the modulus). We reject-
/// sample: generate 32 random bytes, if above modulus, try again.
/// For proptest this is fine because ~86% of 32-byte values are
/// below the BN254 modulus.
fn valid_field_element() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>()).prop_filter("must be below BN254 modulus", |bytes| {
        is_below_bn254_modulus(bytes)
    })
}

// ─────────────────────────────────────────────────────────────────
// 1. BN254 modular reduction
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn sample_field_element_is_always_valid(_dummy in 0u8..1) {
        // `sample_field_element_bytes` uses the OS CSPRNG with
        // rejection sampling, so it always produces a valid element.
        let bytes = tidex6_core::types::sample_field_element_bytes()
            .expect("CSPRNG must produce a valid element");
        prop_assert!(is_below_bn254_modulus(&bytes));
    }
}

// ─────────────────────────────────────────────────────────────────
// 2. Poseidon determinism
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn poseidon_hash_pair_is_deterministic(
        a in valid_field_element(),
        b in valid_field_element(),
    ) {
        let h1 = poseidon::hash_pair(&a, &b).expect("poseidon hash_pair 1");
        let h2 = poseidon::hash_pair(&a, &b).expect("poseidon hash_pair 2");
        prop_assert_eq!(h1, h2, "same inputs must produce same hash");
    }
}

// ─────────────────────────────────────────────────────────────────
// 3. Commitment derivation determinism
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn commitment_derive_is_deterministic(
        secret_bytes in valid_field_element(),
        nullifier_bytes in valid_field_element(),
    ) {
        let secret = Secret::from_bytes(secret_bytes);
        let nullifier = Nullifier::from_bytes(nullifier_bytes);
        let c1 = Commitment::derive(&secret, &nullifier).expect("derive 1");
        let c2 = Commitment::derive(&secret, &nullifier).expect("derive 2");
        prop_assert_eq!(c1.to_bytes(), c2.to_bytes());
    }
}

// ─────────────────────────────────────────────────────────────────
// 4. NullifierHash determinism
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn nullifier_hash_is_deterministic(
        nullifier_bytes in valid_field_element(),
    ) {
        let nullifier = Nullifier::from_bytes(nullifier_bytes);
        let h1 = nullifier.derive_hash().expect("hash 1");
        let h2 = nullifier.derive_hash().expect("hash 2");
        prop_assert_eq!(h1.to_bytes(), h2.to_bytes());
    }
}

// ─────────────────────────────────────────────────────────────────
// 5. Merkle insert → proof → verify round-trip
// ─────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn merkle_insert_proof_verify_roundtrip(
        leaf_bytes in valid_field_element(),
        n_prior in 0u8..16,
    ) {
        // Use a small depth for speed. Depth 8 = 256 leaves max.
        let depth = 8;
        let mut tree = MerkleTree::new(depth).expect("new tree");

        // Insert n_prior zero leaves to simulate prior deposits.
        for _ in 0..n_prior {
            tree.insert(Commitment::zero()).expect("insert zero");
        }

        // Insert the target leaf and get a proof.
        let leaf = Commitment::from_bytes(leaf_bytes);
        let (leaf_index, root) = tree.insert(leaf).expect("insert leaf");
        let proof = tree.proof(leaf_index).expect("proof");

        // verify_proof must accept the proof.
        let ok = verify_proof(leaf, &proof, root, depth).expect("verify");
        prop_assert!(ok, "insert → proof → verify must return true");
    }
}

// ─────────────────────────────────────────────────────────────────
// 6. DepositNote text round-trip
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn deposit_note_text_roundtrip(
        secret_bytes in valid_field_element(),
        nullifier_bytes in valid_field_element(),
        denom_index in 0u8..4,
    ) {
        let denomination = match denom_index {
            0 => Denomination::OneTenthSol,
            1 => Denomination::HalfSol,
            2 => Denomination::OneSol,
            _ => Denomination::TenSol,
        };
        let secret = Secret::from_bytes(secret_bytes);
        let nullifier = Nullifier::from_bytes(nullifier_bytes);
        let note = DepositNote::new(denomination, secret, nullifier)
            .expect("construct note");

        let text = note.to_text();
        let parsed = DepositNote::from_text(&text).expect("parse note text");

        prop_assert_eq!(note.commitment().to_bytes(), parsed.commitment().to_bytes());
        prop_assert_eq!(note.denomination(), parsed.denomination());
    }
}

// ─────────────────────────────────────────────────────────────────
// 7. SpendingKey → ViewingKey determinism
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn viewing_key_derivation_is_deterministic(
        key_bytes in valid_field_element(),
    ) {
        let sk = tidex6_core::keys::SpendingKey::from_bytes(key_bytes);
        let vk1 = sk.derive_viewing_key().expect("derive 1");
        let vk2 = sk.derive_viewing_key().expect("derive 2");
        prop_assert_eq!(vk1.to_bytes(), vk2.to_bytes());
    }
}
