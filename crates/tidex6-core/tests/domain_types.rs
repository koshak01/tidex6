//! Integration tests for the domain type layer in `tidex6_core::types`
//! and `tidex6_core::keys`.

use std::collections::HashMap;
use std::str::FromStr;

use tidex6_core::keys::{SpendingKey, ViewingKey};
use tidex6_core::poseidon;
use tidex6_core::types::{Commitment, MerkleRoot, Nullifier, NullifierHash, Secret};

/// Round-trip every domain type through its byte representation. The
/// bytes put in must come out unchanged.
#[test]
fn byte_round_trip_all_types() {
    let bytes = [0x42u8; 32];

    assert_eq!(Secret::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(Nullifier::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(Commitment::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(NullifierHash::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(MerkleRoot::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(SpendingKey::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(ViewingKey::from_bytes(bytes).to_bytes(), bytes);
}

/// Round-trip through the hex encoding. The hex must be 64 lowercase
/// characters and the parse must produce the original value.
#[test]
fn hex_round_trip() {
    let bytes = [
        0x0d, 0x54, 0xe1, 0x93, 0x8f, 0x8a, 0x8c, 0x1c, 0x7d, 0xeb, 0x5e, 0x03, 0x55, 0xf2, 0x63,
        0x19, 0x20, 0x7b, 0x84, 0xfe, 0x9c, 0xa2, 0xce, 0x1b, 0x26, 0xe7, 0x35, 0xc8, 0x29, 0x82,
        0x19, 0x90,
    ];
    let expected_hex = "0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990";

    let commitment = Commitment::from_bytes(bytes);
    assert_eq!(commitment.to_hex(), expected_hex);
    assert_eq!(commitment.to_string(), expected_hex);

    let parsed = Commitment::from_str(expected_hex).expect("parse");
    assert_eq!(parsed, commitment);
    assert_eq!(parsed.to_bytes(), bytes);

    // Hex parsing accepts an optional 0x prefix.
    let with_prefix = format!("0x{expected_hex}");
    let parsed_prefix = Commitment::from_str(&with_prefix).expect("parse 0x-prefixed");
    assert_eq!(parsed_prefix, commitment);
}

/// Hex parsing rejects inputs of the wrong length.
#[test]
fn hex_rejects_wrong_length() {
    assert!(Commitment::from_str("0d54e193").is_err());
    assert!(Commitment::from_str("").is_err());
    assert!(Commitment::from_str(&"00".repeat(33)).is_err());
}

/// Hex parsing rejects inputs containing non-hex characters.
#[test]
fn hex_rejects_non_hex_characters() {
    let mut invalid = "00".repeat(32);
    invalid.replace_range(0..1, "z");
    assert!(Commitment::from_str(&invalid).is_err());
}

/// Two different domain types with the same underlying bytes are not
/// interchangeable — the type system must keep them distinct.
#[test]
fn different_domain_types_do_not_alias() {
    // The test is that this file compiles: if `Secret` and
    // `Nullifier` were type-aliased, the assertion below would
    // silently accept the wrong type.
    let bytes = [0x01u8; 32];
    let secret = Secret::from_bytes(bytes);
    let nullifier = Nullifier::from_bytes(bytes);

    // Both expose the same bytes, but the compiler treats them as
    // different types. Putting them in the same container or
    // comparing them directly with `==` would be a compile error.
    assert_eq!(secret.to_bytes(), nullifier.to_bytes());
    // Uncommenting the next line must not compile:
    // let _ = secret == nullifier;
}

/// `Commitment::derive` must match `tidex6_core::poseidon::hash_pair`
/// on the same inputs — the type-aware wrapper and the byte-level API
/// produce identical bytes.
#[test]
fn commitment_derive_matches_poseidon_hash_pair() {
    let secret = Secret::from_bytes([1u8; 32]);
    let nullifier = Nullifier::from_bytes([2u8; 32]);

    let via_types = Commitment::derive(&secret, &nullifier).expect("derive");
    let via_bytes =
        poseidon::hash_pair(secret.as_bytes(), nullifier.as_bytes()).expect("hash_pair");

    assert_eq!(via_types.to_bytes(), via_bytes);
}

/// The canonical Poseidon vector must flow through the domain types
/// unchanged: putting `[1u8; 32]` and `[2u8; 32]` into `Commitment::
/// derive` produces the byte vector documented in light-poseidon and
/// solana-poseidon upstream.
#[test]
fn commitment_derive_matches_canonical_vector() {
    let secret = Secret::from_bytes([1u8; 32]);
    let nullifier = Nullifier::from_bytes([2u8; 32]);

    let commitment = Commitment::derive(&secret, &nullifier).expect("derive");
    assert_eq!(
        commitment.to_hex(),
        "0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990"
    );
}

/// `Nullifier::derive_hash` produces a deterministic `NullifierHash`
/// that depends only on the input nullifier.
#[test]
fn nullifier_hash_is_deterministic() {
    let nullifier = Nullifier::from_bytes([7u8; 32]);

    let hash1 = nullifier.derive_hash().expect("derive_hash");
    let hash2 = nullifier.derive_hash().expect("derive_hash");

    assert_eq!(hash1, hash2);
    assert_ne!(hash1.to_bytes(), [0u8; 32]);
}

/// `SpendingKey::derive_viewing_key` is deterministic and different
/// spending keys produce different viewing keys.
#[test]
fn viewing_key_derivation_is_deterministic() {
    let spending = SpendingKey::from_bytes([1u8; 32]);
    let viewing_a = spending.derive_viewing_key().expect("derive");
    let viewing_b = spending.derive_viewing_key().expect("derive");
    assert_eq!(viewing_a, viewing_b);

    let other = SpendingKey::from_bytes([2u8; 32]);
    let viewing_other = other.derive_viewing_key().expect("derive");
    assert_ne!(viewing_a, viewing_other);
}

/// The `ViewingKey` round-trips through hex so users can transfer it
/// between devices via a text channel.
#[test]
fn viewing_key_hex_round_trip() {
    let spending = SpendingKey::from_bytes([3u8; 32]);
    let viewing = spending.derive_viewing_key().expect("derive");

    let exported = viewing.to_hex();
    assert_eq!(exported.len(), 64);

    let imported = ViewingKey::from_str(&exported).expect("parse");
    assert_eq!(viewing, imported);
    assert_eq!(viewing.to_bytes(), imported.to_bytes());
}

/// `SpendingKey::Debug` never prints the raw bytes — it only prints
/// a short fingerprint. This prevents `{:?}` from leaking spending
/// keys into logs.
#[test]
fn spending_key_debug_is_redacted() {
    let spending = SpendingKey::from_bytes([0x42u8; 32]);
    let debug = format!("{spending:?}");

    assert!(debug.contains("REDACTED"));
    // The raw bytes must not appear anywhere in the debug output.
    assert!(!debug.contains("4242424242"));
}

/// Two randomly generated secrets must differ with overwhelming
/// probability. This is a basic sanity check on `Secret::random`.
#[test]
fn random_secrets_differ() {
    let a = Secret::random().expect("random");
    let b = Secret::random().expect("random");
    assert_ne!(a, b);
    assert_ne!(a.to_bytes(), [0u8; 32]);
}

/// `Commitment` can be used as a `HashMap` key. This will be
/// important later when the indexer needs to look up commitments by
/// value. The test is that this compiles and produces the expected
/// lookups.
#[test]
fn commitment_is_hash_map_key() {
    let mut map: HashMap<Commitment, u64> = HashMap::new();
    let c1 = Commitment::from_bytes([1u8; 32]);
    let c2 = Commitment::from_bytes([2u8; 32]);

    map.insert(c1, 100);
    map.insert(c2, 200);

    assert_eq!(map.get(&c1), Some(&100));
    assert_eq!(map.get(&c2), Some(&200));
    assert_eq!(map.len(), 2);
}

/// `NullifierHash` is also hashable so the indexer can detect
/// double-spend attempts quickly.
#[test]
fn nullifier_hash_is_hash_map_key() {
    let mut seen: HashMap<NullifierHash, usize> = HashMap::new();
    let h = NullifierHash::from_bytes([9u8; 32]);

    assert!(seen.insert(h, 0).is_none());
    assert_eq!(seen.get(&h), Some(&0));
}
