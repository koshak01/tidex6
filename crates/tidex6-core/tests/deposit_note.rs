//! Integration tests for `tidex6_core::note::DepositNote` (v3 hex
//! opaque format, ADR-012).

use std::str::FromStr;

use tidex6_core::note::{Denomination, DepositNote, NoteError, NOTE_TEXT_LEN};
use tidex6_core::types::{Commitment, Nullifier, Secret};

/// The four denominations have the expected lamport values, tags,
/// and round-trip through their 1-byte binary tag.
#[test]
fn denomination_values_and_tags() {
    assert_eq!(Denomination::OneTenthSol.lamports(), 100_000_000);
    assert_eq!(Denomination::HalfSol.lamports(), 500_000_000);
    assert_eq!(Denomination::OneSol.lamports(), 1_000_000_000);
    assert_eq!(Denomination::TenSol.lamports(), 10_000_000_000);

    assert_eq!(Denomination::OneTenthSol.tag(), "0.1");
    assert_eq!(Denomination::HalfSol.tag(), "0.5");
    assert_eq!(Denomination::OneSol.tag(), "1");
    assert_eq!(Denomination::TenSol.tag(), "10");

    for denom in [
        Denomination::OneTenthSol,
        Denomination::HalfSol,
        Denomination::OneSol,
        Denomination::TenSol,
    ] {
        let tag = denom.binary_tag();
        let parsed = Denomination::from_binary_tag(tag).unwrap();
        assert_eq!(parsed, denom);
    }

    assert!(Denomination::from_binary_tag(0xFF).is_err());
}

/// A freshly constructed note exposes the inputs and a derived
/// commitment that matches `Commitment::derive` on the same inputs.
#[test]
fn new_note_stores_inputs_and_derives_commitment() {
    let secret = Secret::from_bytes([1u8; 32]);
    let nullifier = Nullifier::from_bytes([2u8; 32]);

    let note = DepositNote::new(Denomination::OneSol, secret, nullifier).expect("new");

    assert_eq!(note.denomination(), Denomination::OneSol);
    assert_eq!(*note.secret(), secret);
    assert_eq!(*note.nullifier(), nullifier);

    let expected = Commitment::derive(&secret, &nullifier).expect("derive");
    assert_eq!(note.commitment(), expected);
}

/// `random` produces notes whose secret and nullifier differ
/// between invocations and whose commitment is consistent with
/// `Commitment::derive`.
#[test]
fn random_note_is_fresh_and_consistent() {
    let note_a = DepositNote::random(Denomination::OneSol).expect("random a");
    let note_b = DepositNote::random(Denomination::OneSol).expect("random b");

    assert_ne!(note_a.secret(), note_b.secret());
    assert_ne!(note_a.nullifier(), note_b.nullifier());
    assert_ne!(note_a.commitment(), note_b.commitment());

    let expected_a = Commitment::derive(note_a.secret(), note_a.nullifier()).expect("derive");
    assert_eq!(note_a.commitment(), expected_a);
}

/// Hex-format round-trip reconstructs the original note.
#[test]
fn text_round_trip() {
    let secret = Secret::from_bytes([0x0au8; 32]);
    let nullifier = Nullifier::from_bytes([0x0bu8; 32]);
    let note = DepositNote::new(Denomination::OneSol, secret, nullifier).expect("new");

    let text = note.to_text();
    assert_eq!(text.len(), NOTE_TEXT_LEN);
    assert!(!text.contains("tidex6"));
    assert!(!text.contains(":"));

    let parsed = DepositNote::from_text(&text).expect("parse");
    assert_eq!(parsed, note);

    assert_eq!(format!("{note}"), text);
    assert_eq!(DepositNote::from_str(&text).expect("from_str"), note);
}

/// Garbage input is rejected with a clear error.
#[test]
fn text_parse_rejects_malformed_input() {
    // Random non-hex.
    assert!(matches!(
        DepositNote::from_text("hello world"),
        Err(NoteError::InvalidHex)
    ));

    // Hex but wrong length.
    assert!(matches!(
        DepositNote::from_text("aabbccdd"),
        Err(NoteError::LenMismatch { .. })
    ));

    // Right length but wrong version byte.
    let mut blob = vec![0u8; 66];
    blob[0] = 0xFF;
    let bad_version = hex::encode(blob);
    assert!(matches!(
        DepositNote::from_text(&bad_version),
        Err(NoteError::UnknownVersion(_))
    ));

    // Right length, right version, unknown denomination.
    let mut blob = vec![0u8; 66];
    blob[0] = 0x02;
    blob[1] = 0xAA;
    let bad_denom = hex::encode(blob);
    assert!(matches!(
        DepositNote::from_text(&bad_denom),
        Err(NoteError::UnknownDenominationByte(_))
    ));
}

/// Leading and trailing whitespace is tolerated by `from_text` so
/// users pasting from a chat or file do not get spurious errors.
#[test]
fn text_parse_tolerates_surrounding_whitespace() {
    let secret = Secret::from_bytes([3u8; 32]);
    let nullifier = Nullifier::from_bytes([4u8; 32]);
    let note = DepositNote::new(Denomination::TenSol, secret, nullifier).expect("new");

    let padded = format!("   \n{}\n  ", note.to_text());
    let parsed = DepositNote::from_text(&padded).expect("parse");
    assert_eq!(parsed, note);
}

/// `{:?}` output of a `DepositNote` never contains the raw secret
/// or nullifier bytes. This prevents accidental leaks through logs.
#[test]
fn debug_format_is_redacted() {
    let note = DepositNote::new(
        Denomination::OneSol,
        Secret::from_bytes([0x12u8; 32]),
        Nullifier::from_bytes([0x13u8; 32]),
    )
    .expect("new");

    let debug = format!("{note:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("1212121212"));
    assert!(!debug.contains("1313131313"));
    assert!(debug.contains("DepositNote"));
}

/// The commitment stored in a note matches the one a verifier
/// would compute by hashing the secret and nullifier directly.
/// Catches any inconsistency between note construction and the
/// commitment scheme in ADR-001.
#[test]
fn note_commitment_matches_manual_derivation() {
    let secret = Secret::from_bytes([0x11u8; 32]);
    let nullifier = Nullifier::from_bytes([0x22u8; 32]);
    let note = DepositNote::new(Denomination::OneSol, secret, nullifier).expect("new");

    let manual = Commitment::derive(&secret, &nullifier).expect("derive");
    assert_eq!(note.commitment(), manual);
}
