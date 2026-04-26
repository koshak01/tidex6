//! Browser-side cryptography for the tidex6 withdraw flow.
//!
//! This crate exposes everything the browser needs to take a deposit
//! note and produce a withdraw proof **without sending any secret
//! material to a server**. The flow is:
//!
//! 1. `parseNote(noteText)` — parse a v3 deposit note (132-char hex
//!    blob); returns `secret`, `nullifier`, `denomination_lamports`.
//! 2. `commitment(secret, nullifier)` — derive the public commitment
//!    so the browser can ask the indexer for the Merkle path of *this*
//!    leaf without revealing what's inside.
//! 3. `nullifierHash(nullifier)` — derive the per-deposit nullifier
//!    hash that the verifier will check against its replay-prevention
//!    PDA. Public, but computed from the secret nullifier so the
//!    browser must do this locally.
//! 4. `proveWithdraw(...)` — generate the Groth16 proof.
//!
//! The user's `secret` and `nullifier` exist only inside the WASM
//! module's linear memory and the browser tab that owns it. The
//! WASM sandbox has no access to network APIs (fetch / XHR / etc.),
//! so a hostile JS page cannot forward them — verifiable via
//! `WebAssembly.Module.imports(...)` in DevTools.

use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use js_sys::Uint8Array;
use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::withdraw::{WithdrawWitness, prove_withdraw as prove_withdraw_inner};
use tidex6_core::note::DepositNote;
use tidex6_core::poseidon;
use wasm_bindgen::prelude::*;

const DEPTH: usize = 20;
const FIELD_BYTES: usize = 32;
const PROOF_A_BYTES: usize = 64;
const PROOF_B_BYTES: usize = 128;
const PROOF_C_BYTES: usize = 64;
const PROOF_TOTAL_BYTES: usize = PROOF_A_BYTES + PROOF_B_BYTES + PROOF_C_BYTES;

/// One-time hook so Rust panics show up as `console.error` in the
/// browser. Call from JS before the first prove invocation;
/// idempotent.
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Parsed deposit note. `secret` and `nullifier` are 32-byte
/// big-endian field elements; `denominationLamports` is a `u64` cast
/// to `f64` so JS BigInt is not required (every supported
/// denomination — 0.1/0.5/1/10 SOL — is well within `Number.MAX_SAFE_INTEGER`).
#[wasm_bindgen]
pub struct ParsedNote {
    secret: [u8; FIELD_BYTES],
    nullifier: [u8; FIELD_BYTES],
    denomination_lamports: u64,
}

#[wasm_bindgen]
impl ParsedNote {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Uint8Array {
        Uint8Array::from(&self.secret[..])
    }

    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> Uint8Array {
        Uint8Array::from(&self.nullifier[..])
    }

    #[wasm_bindgen(getter, js_name = denominationLamports)]
    pub fn denomination_lamports(&self) -> f64 {
        self.denomination_lamports as f64
    }
}

/// Parse a 132-char hex deposit note (v3 layout: version + denom +
/// secret + nullifier).
#[wasm_bindgen(js_name = parseNote)]
pub fn parse_note(note_text: &str) -> Result<ParsedNote, JsError> {
    let note = DepositNote::from_text(note_text)
        .map_err(|e| JsError::new(&format!("invalid note: {e}")))?;
    Ok(ParsedNote {
        secret: *note.secret().as_bytes(),
        nullifier: *note.nullifier().as_bytes(),
        denomination_lamports: note.denomination().lamports(),
    })
}

/// `commitment = Poseidon(secret, nullifier)` — the public leaf
/// inserted into the on-chain Merkle tree. The browser uses this
/// to ask the indexer for *its* Merkle path without sending the
/// secret material.
#[wasm_bindgen(js_name = commitment)]
pub fn commitment(secret: &Uint8Array, nullifier: &Uint8Array) -> Result<Uint8Array, JsError> {
    let s = to_field_bytes(secret, "secret")?;
    let n = to_field_bytes(nullifier, "nullifier")?;
    let h = poseidon::hash_pair(&s, &n)
        .map_err(|e| JsError::new(&format!("poseidon failed: {e}")))?;
    Ok(Uint8Array::from(&h[..]))
}

/// `nullifierHash = Poseidon(nullifier)` — a single-input Poseidon
/// hash. The on-chain verifier re-derives this and checks it against
/// the per-nullifier PDA. The browser computes it locally so the
/// server never sees the raw nullifier.
#[wasm_bindgen(js_name = nullifierHash)]
pub fn nullifier_hash(nullifier: &Uint8Array) -> Result<Uint8Array, JsError> {
    let n = to_field_bytes(nullifier, "nullifier")?;
    let h = poseidon::hash(&[&n])
        .map_err(|e| JsError::new(&format!("poseidon failed: {e}")))?;
    Ok(Uint8Array::from(&h[..]))
}

/// Generate a withdraw proof entirely in the browser.
///
/// Inputs match `WithdrawWitness<20>`: every byte array except
/// `path_indices_packed` and `proving_key` is exactly 32 bytes.
///
/// `path_siblings_concat` is the 20 × 32-byte Merkle path siblings
/// concatenated, leaf-adjacent first.
///
/// `path_indices_packed` is a 20-byte array where byte `i` is `0` or
/// `1` and equals bit `i` of the leaf index, LSB first.
///
/// `proving_key` is the byte-for-byte uncompressed-unchecked
/// serialisation of `ProvingKey<Bn254>` produced by
/// `tidex6-circuits/src/bin/gen_withdraw_vk.rs`. Fetched once per
/// session from the same origin and cached.
///
/// Returns the 256-byte concatenation `proof_a || proof_b || proof_c`
/// in the on-chain `groth16-solana` byte layout.
#[wasm_bindgen(js_name = proveWithdraw)]
#[allow(clippy::too_many_arguments)]
pub fn prove_withdraw(
    secret: &Uint8Array,
    nullifier: &Uint8Array,
    path_siblings_concat: &Uint8Array,
    path_indices_packed: &Uint8Array,
    merkle_root: &Uint8Array,
    nullifier_hash: &Uint8Array,
    recipient: &Uint8Array,
    relayer_address: &Uint8Array,
    relayer_fee: &Uint8Array,
    proving_key: &Uint8Array,
) -> Result<Uint8Array, JsError> {
    let secret = to_field_bytes(secret, "secret")?;
    let nullifier = to_field_bytes(nullifier, "nullifier")?;
    let merkle_root = to_field_bytes(merkle_root, "merkle_root")?;
    let nullifier_hash = to_field_bytes(nullifier_hash, "nullifier_hash")?;
    let recipient = to_field_bytes(recipient, "recipient")?;
    let relayer_address = to_field_bytes(relayer_address, "relayer_address")?;
    let relayer_fee = to_field_bytes(relayer_fee, "relayer_fee")?;

    let siblings_buf = uint8array_to_vec(path_siblings_concat);
    if siblings_buf.len() != DEPTH * FIELD_BYTES {
        return Err(JsError::new(&format!(
            "path_siblings_concat must be {} bytes ({} levels × 32), got {}",
            DEPTH * FIELD_BYTES,
            DEPTH,
            siblings_buf.len()
        )));
    }
    let mut siblings_arrays: [[u8; FIELD_BYTES]; DEPTH] = [[0u8; FIELD_BYTES]; DEPTH];
    for (i, slot) in siblings_arrays.iter_mut().enumerate() {
        slot.copy_from_slice(&siblings_buf[i * FIELD_BYTES..(i + 1) * FIELD_BYTES]);
    }
    let siblings_refs: [&[u8; FIELD_BYTES]; DEPTH] = std::array::from_fn(|i| &siblings_arrays[i]);

    let indices_buf = uint8array_to_vec(path_indices_packed);
    if indices_buf.len() != DEPTH {
        return Err(JsError::new(&format!(
            "path_indices_packed must be {DEPTH} bytes, got {}",
            indices_buf.len()
        )));
    }
    let mut path_indices = [false; DEPTH];
    for (i, slot) in path_indices.iter_mut().enumerate() {
        *slot = match indices_buf[i] {
            0 => false,
            1 => true,
            other => {
                return Err(JsError::new(&format!(
                    "path_indices_packed[{i}] must be 0 or 1, got {other}"
                )));
            }
        };
    }

    let pk_bytes = uint8array_to_vec(proving_key);
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&pk_bytes[..])
        .map_err(|e| JsError::new(&format!("failed to deserialize proving key: {e}")))?;

    let witness = WithdrawWitness::<DEPTH> {
        secret: &secret,
        nullifier: &nullifier,
        path_siblings: siblings_refs,
        path_indices,
        merkle_root: &merkle_root,
        nullifier_hash: &nullifier_hash,
        recipient: &recipient,
        relayer_address: &relayer_address,
        relayer_fee: &relayer_fee,
    };

    let mut rng = rand::thread_rng();
    let (proof, _public_inputs) = prove_withdraw_inner::<DEPTH, _>(&pk, witness, &mut rng)
        .map_err(|e| JsError::new(&format!("prove_withdraw failed: {e}")))?;

    let Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        ..
    } = groth16_to_solana_bytes(&proof, &pk.vk)
        .map_err(|e| JsError::new(&format!("groth16_to_solana_bytes failed: {e}")))?;

    let mut out = Vec::with_capacity(PROOF_TOTAL_BYTES);
    out.extend_from_slice(&proof_a);
    out.extend_from_slice(&proof_b);
    out.extend_from_slice(&proof_c);
    debug_assert_eq!(out.len(), PROOF_TOTAL_BYTES);

    Ok(Uint8Array::from(out.as_slice()))
}

fn to_field_bytes(input: &Uint8Array, name: &str) -> Result<[u8; FIELD_BYTES], JsError> {
    let buf = uint8array_to_vec(input);
    if buf.len() != FIELD_BYTES {
        return Err(JsError::new(&format!(
            "{name} must be {FIELD_BYTES} bytes, got {}",
            buf.len()
        )));
    }
    let mut out = [0u8; FIELD_BYTES];
    out.copy_from_slice(&buf);
    Ok(out)
}

fn uint8array_to_vec(input: &Uint8Array) -> Vec<u8> {
    let mut out = vec![0u8; input.length() as usize];
    input.copy_to(&mut out);
    out
}
