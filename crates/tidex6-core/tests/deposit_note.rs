//! Integration tests for `tidex6_core::note::DepositNote`.

use std::str::FromStr;

use tidex6_core::note::{Denomination, DepositNote, NoteError};
use tidex6_core::types::{Commitment, Nullifier, Secret};

/// The three denominations have the expected lamport values and
/// tags, and the tag round-trips through `from_tag`.
#[test]
fn denomination_values_and_tags() {
    assert_eq!(Denomination::OneTenthSol.lamports(), 100_000_000);
    assert_eq!(Denomination::OneSol.lamports(), 1_000_000_000);
    assert_eq!(Denomination::TenSol.lamports(), 10_000_000_000);

    assert_eq!(Denomination::OneTenthSol.tag(), "0.1");
    assert_eq!(Denomination::OneSol.tag(), "1");
    assert_eq!(Denomination::TenSol.tag(), "10");

    assert_eq!(
        Denomination::from_tag("0.1").unwrap(),
        Denomination::OneTenthSol
    );
    assert_eq!(Denomination::from_tag("1").unwrap(), Denomination::OneSol);
    assert_eq!(Denomination::from_tag("10").unwrap(), Denomination::TenSol);
    assert!(Denomination::from_tag("42").is_err());
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

    // Commitment still matches the primitive.
    let expected_a = Commitment::derive(note_a.secret(), note_a.nullifier()).expect("derive");
    assert_eq!(note_a.commitment(), expected_a);
}

/// Text encoding has the exact documented format and a round-trip
/// reconstructs the original note. Uses byte values with high
/// nibble < 0x30 so the inputs remain valid BN254 scalar field
/// elements, which is a precondition for `Commitment::derive`.
#[test]
fn text_round_trip() {
    let secret = Secret::from_bytes([0x0au8; 32]);
    let nullifier = Nullifier::from_bytes([0x0bu8; 32]);
    let note = DepositNote::new(Denomination::OneSol, secret, nullifier).expect("new");

    let text = note.to_text();

    assert!(text.starts_with("tidex6-note-v1:1:"));
    // prefix(14) + ":"(1) + "1"(1) + ":"(1) + 64 hex + ":"(1) + 64 hex = 146 chars
    assert_eq!(text.len(), 146);

    let parsed = DepositNote::from_text(&text).expect("parse");
    assert_eq!(parsed, note);

    // Display / FromStr match the text form.
    assert_eq!(format!("{note}"), text);
    assert_eq!(DepositNote::from_str(&text).expect("from_str"), note);
}

/// Text parsing rejects the common mistake classes with precise
/// errors.
#[test]
fn text_parse_rejects_malformed_input() {
    // Wrong prefix.
    let wrong_prefix = format!("wrong-prefix:1:{}:{}", "00".repeat(32), "00".repeat(32));
    assert!(matches!(
        DepositNote::from_text(&wrong_prefix),
        Err(NoteError::MissingPrefix)
    ));

    // Too few fields.
    assert!(matches!(
        DepositNote::from_text("tidex6-note-v1:1"),
        Err(NoteError::MalformedStructure { .. })
    ));

    // Unknown denomination tag.
    let bad_denom = format!("tidex6-note-v1:42:{}:{}", "00".repeat(32), "00".repeat(32));
    assert!(matches!(
        DepositNote::from_text(&bad_denom),
        Err(NoteError::UnknownDenomination(_))
    ));

    // Bad hex in the secret field.
    let bad_hex = format!("tidex6-note-v1:1:{}:{}", "zz".repeat(32), "00".repeat(32));
    assert!(matches!(
        DepositNote::from_text(&bad_hex),
        Err(NoteError::InvalidHex(_))
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

    // The public commitment IS allowed to appear.
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
