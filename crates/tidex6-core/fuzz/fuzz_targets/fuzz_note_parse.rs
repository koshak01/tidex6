//! Fuzz target for `DepositNote::from_text`.
//!
//! Goal: parsing arbitrary user-provided note text must never
//! panic. Any invalid input should return a clean `NoteError`,
//! not an unwrap or an index-out-of-bounds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tidex6_core::note::DepositNote;

fuzz_target!(|data: &[u8]| {
    // from_text takes &str, so we need valid UTF-8. If the fuzzer
    // sends non-UTF-8 bytes, just skip — the real API also
    // expects a text string from the user.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = DepositNote::from_text(text);
    }
});
