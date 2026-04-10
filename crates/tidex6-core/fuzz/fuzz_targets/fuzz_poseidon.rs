//! Fuzz target for `tidex6_core::poseidon::hash` and `hash_pair`.
//!
//! Goal: `poseidon::hash` must never panic regardless of the
//! input bytes — it should either return Ok or Err, but never
//! unwind. A panic here would be a denial-of-service vector
//! because the onchain program uses the same Poseidon parameters
//! and any input that causes a Rust-side panic would crash the
//! offchain prover or indexer.
//!
//! The fuzzer feeds arbitrary bytes and we split them into 1..=12
//! chunks of 32 bytes each, replicating the hash API's input
//! surface.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tidex6_core::poseidon;

fuzz_target!(|data: &[u8]| {
    // Split the input into 32-byte chunks. If fewer than 32 bytes,
    // treat the whole thing as one (short) input; the API should
    // handle it gracefully with an error, not a panic.
    if data.is_empty() {
        return;
    }

    // hash_pair: two 32-byte inputs. Pad or truncate as needed.
    if data.len() >= 64 {
        let a: [u8; 32] = data[..32].try_into().unwrap();
        let b: [u8; 32] = data[32..64].try_into().unwrap();
        let _ = poseidon::hash_pair(&a, &b);
    }

    // hash with 1..=12 inputs: build as many 32-byte chunks as fit.
    let chunks: Vec<[u8; 32]> = data
        .chunks_exact(32)
        .take(12)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    if !chunks.is_empty() {
        let refs: Vec<&[u8; 32]> = chunks.iter().collect();
        let _ = poseidon::hash(&refs);
    }
});
