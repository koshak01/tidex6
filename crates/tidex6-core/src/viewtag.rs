//! X25519 view-tag — a cheap classical filter layered over the ML-KEM envelope.
//!
//! ML-KEM has no cheap "is this mine" shortcut: recovering the shared secret
//! needs a full decapsulation, so scanning a large pool means one decap per
//! envelope (hundreds of seconds in a browser at 100k envelopes). This module
//! adds a **classical** X25519 tag that a reader checks with a single
//! scalar-mult (microseconds), skipping ~255/256 foreign envelopes before any
//! ML-KEM work. The payload stays post-quantum (still ML-KEM); X25519 only
//! answers "possibly yours".
//!
//! ## One secret
//! The reader's X25519 secret is **derived from its ML-KEM secret** (a domain-
//! separated SHA-512), so the user still keeps a single secret. The reader's
//! X25519 public key travels alongside the ML-KEM public key in the address.
//!
//! ## Per-envelope flow
//! - Deposit: pick an ephemeral X25519 keypair, `shared = eph_sk · reader_pk`,
//!   `tag = H(shared)[0]`. Publish `eph_pk (32) ‖ tag (1)` next to the slot.
//! - Scan: `shared = reader_sk · eph_pk`, `tag' = H(shared)[0]`; if
//!   `tag' != tag` skip, otherwise run the ML-KEM decap.

use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 public-key length, bytes.
pub const X25519_PK_LEN: usize = 32;
/// Per-slot tag material published in the envelope: `eph_pk (32) ‖ tag (1)`.
pub const TAG_HEADER_LEN: usize = X25519_PK_LEN + 1;

/// Domain separation for deriving the X25519 secret from the ML-KEM secret.
const DERIVE_DOMAIN: &[u8] = b"tidex6-x25519-viewtag-v1";
/// Domain separation for the tag hash over the shared secret.
const TAG_DOMAIN: &[u8] = b"tidex6-viewtag-v1";

/// Derive the reader's X25519 secret from its ML-KEM secret key
/// (deterministic). The user keeps only the ML-KEM secret; this is recomputed
/// on demand for tagging and scanning.
pub fn derive_x25519_secret(mlkem_sk: &[u8]) -> StaticSecret {
    let mut h = Sha512::new();
    h.update(DERIVE_DOMAIN);
    h.update(mlkem_sk);
    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    StaticSecret::from(seed) // clamps internally
}

/// The reader's X25519 public key derived from its ML-KEM secret — goes into
/// the public address (`ML-KEM pk ‖ X25519 pk`) so senders can tag for it.
pub fn x25519_public_from_mlkem_sk(mlkem_sk: &[u8]) -> [u8; X25519_PK_LEN] {
    PublicKey::from(&derive_x25519_secret(mlkem_sk)).to_bytes()
}

/// One tag byte from a raw X25519 shared secret (domain-separated SHA-256).
fn tag_from_shared(shared: &[u8; 32]) -> u8 {
    let mut h = Sha256::new();
    h.update(TAG_DOMAIN);
    h.update(shared);
    h.finalize()[0]
}

/// Deposit side: given the reader's X25519 public key and 32 fresh random
/// bytes for the ephemeral key, produce `(ephemeral_public, tag)` to publish.
pub fn seal_tag(reader_x25519_pk: &[u8; X25519_PK_LEN], eph_bytes: [u8; 32]) -> ([u8; 32], u8) {
    let eph = StaticSecret::from(eph_bytes);
    let eph_pub = PublicKey::from(&eph);
    let reader_pub = PublicKey::from(*reader_x25519_pk);
    let shared = eph.diffie_hellman(&reader_pub);
    (eph_pub.to_bytes(), tag_from_shared(shared.as_bytes()))
}

/// Scan side: the reader's expected tag for an envelope, computed with one
/// scalar-mult. Compare to the published tag before attempting an ML-KEM decap.
pub fn open_tag(reader_x25519_sk: &StaticSecret, eph_pub: &[u8; 32]) -> u8 {
    let shared = reader_x25519_sk.diffie_hellman(&PublicKey::from(*eph_pub));
    tag_from_shared(shared.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_matches_for_the_addressed_reader() {
        // Reader's ML-KEM secret is arbitrary bytes for this test.
        let mlkem_sk = [42u8; 64];
        let reader_pk = x25519_public_from_mlkem_sk(&mlkem_sk);
        let reader_sk = derive_x25519_secret(&mlkem_sk);

        let eph_bytes = [7u8; 32];
        let (eph_pub, tag) = seal_tag(&reader_pk, eph_bytes);

        // The addressed reader recomputes the same tag.
        assert_eq!(open_tag(&reader_sk, &eph_pub), tag);
    }

    #[test]
    fn foreign_reader_almost_never_matches() {
        let mine = [1u8; 64];
        let theirs = [2u8; 64];
        let my_pk = x25519_public_from_mlkem_sk(&mine);
        let their_sk = derive_x25519_secret(&theirs);

        // Envelope tagged for `mine`; a foreign reader's tag differs (1/256
        // false-positive rate is acceptable — they just fall through to decap).
        let mut collisions = 0;
        for i in 0..64u8 {
            let (eph_pub, tag) = seal_tag(&my_pk, [i; 32]);
            if open_tag(&their_sk, &eph_pub) == tag {
                collisions += 1;
            }
        }
        assert!(collisions < 8, "too many tag collisions: {collisions}/64");
    }
}
