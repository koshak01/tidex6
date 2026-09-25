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

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use js_sys::Uint8Array;
use tidex6_circuits::evm_solidity::groth16_proof_to_evm_bytes;
use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::withdraw::{WithdrawWitness, prove_withdraw as prove_withdraw_inner};
use tidex6_confidential::bytes::fr_to_be_bytes;
use tidex6_confidential::{note_v2, transfer, transfer_v2, withdraw as hidden, withdraw_v2};
use tidex6_core::envelope;
use tidex6_core::note::DepositNote;
use tidex6_core::poseidon;
use tidex6_core::pqc::PqcSecretKey;
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

/// Lowercase-hex encode, matching the identity file format. Kept inline
/// to avoid a `hex` dependency in this browser-only crate.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// A freshly generated tidex6 identity — the exact v3 fields the CLI's
/// `identity.json` carries. `mlkemPublic` is the addressable public key
/// (share it freely). Everything else stays with the owner; `mlkemSecret`
/// opens `/receive` and `/accountant`.
#[wasm_bindgen]
pub struct Identity {
    spending_key: String,
    viewing_key: String,
    mlkem_public: String,
    mlkem_secret: String,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(getter, js_name = spendingKey)]
    pub fn spending_key(&self) -> String {
        self.spending_key.clone()
    }
    #[wasm_bindgen(getter, js_name = viewingKey)]
    pub fn viewing_key(&self) -> String {
        self.viewing_key.clone()
    }
    #[wasm_bindgen(getter, js_name = mlkemPublic)]
    pub fn mlkem_public(&self) -> String {
        self.mlkem_public.clone()
    }
    #[wasm_bindgen(getter, js_name = mlkemSecret)]
    pub fn mlkem_secret(&self) -> String {
        self.mlkem_secret.clone()
    }
}

/// The phrase a wallet signs to derive its tidex6 identity. Exposed so the
/// page and the WASM cannot disagree about it — signing a different phrase
/// silently produces a different identity, and the user would see an empty
/// inbox instead of an error.
#[wasm_bindgen(js_name = identityMessage)]
pub fn identity_message() -> String {
    tidex6_core::identity::IDENTITY_MESSAGE.to_string()
}

/// Derive the tidex6 identity from a wallet signature over
/// [`identity_message`] (ADR-018 §3).
///
/// Same wallet, same phrase, same keys — on any device, forever. There is no
/// key file to download, back up or lose: reconnect the wallet and the identity
/// reappears. The signature itself never leaves this tab, and neither do the
/// keys derived from it.
///
/// Pass the raw signature bytes the wallet returned, unchanged: 64 from a
/// Solana wallet, 65 from an EVM one (the extra byte is secp256k1's recovery
/// id). Both go into the derivation whole — trimming one "for consistency"
/// would derive a different identity and lock its owner out of the payments
/// already sealed to the published key.
#[wasm_bindgen(js_name = identityFromSignature)]
pub fn identity_from_signature(signature: &[u8]) -> Result<Identity, JsError> {
    let derived = tidex6_core::identity::from_signature(signature)
        .map_err(|e| JsError::new(&format!("derive identity: {e}")))?;

    let address = tidex6_core::envelope::ReaderAddress::from_secret(
        derived.mlkem_public,
        &derived.mlkem_secret,
    );

    Ok(Identity {
        spending_key: to_hex(derived.spending_key.as_bytes()),
        viewing_key: to_hex(derived.viewing_key.as_bytes()),
        mlkem_public: to_hex(&address.to_bytes()),
        mlkem_secret: to_hex(derived.mlkem_secret.as_bytes()),
    })
}

/// Generate a fresh tidex6 identity entirely in the browser: a random
/// `SpendingKey`, its derived `ViewingKey`, and a post-quantum ML-KEM-768
/// keypair (ADR-014). Byte-for-byte the same shape `tidex6 keygen`
/// produces. Nothing touches the network — the WASM sandbox has no
/// fetch/XHR, verifiable via `WebAssembly.Module.imports(...)`.
///
/// Prefer [`identity_from_signature`]: an identity derived from the wallet
/// needs no storage at all, while this one produces a key file the user must
/// keep safe forever.
#[wasm_bindgen(js_name = generateIdentity)]
pub fn generate_identity() -> Result<Identity, JsError> {
    use tidex6_core::keys::SpendingKey;

    let spending_key =
        SpendingKey::random().map_err(|e| JsError::new(&format!("spending key: {e}")))?;
    let viewing_key = spending_key
        .derive_viewing_key()
        .map_err(|e| JsError::new(&format!("viewing key: {e}")))?;
    let (mlkem_public, mlkem_secret) = tidex6_core::pqc::keygen();
    // Публичный адрес = ML-KEM pk ‖ X25519 pk (X25519 деривится из ML-KEM
    // secret). Пользователь раздаёт эту строку; X25519 нужен отправителю для
    // view-tag. Секрет остаётся один (ML-KEM), X25519 регенерится при скане.
    let address = tidex6_core::envelope::ReaderAddress::from_secret(mlkem_public, &mlkem_secret);

    Ok(Identity {
        spending_key: to_hex(spending_key.as_bytes()),
        viewing_key: to_hex(viewing_key.as_bytes()),
        mlkem_public: to_hex(&address.to_bytes()),
        mlkem_secret: to_hex(mlkem_secret.as_bytes()),
    })
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
    let h =
        poseidon::hash_pair(&s, &n).map_err(|e| JsError::new(&format!("poseidon failed: {e}")))?;
    Ok(Uint8Array::from(&h[..]))
}

/// `nullifierHash = Poseidon(nullifier)` — a single-input Poseidon
/// hash. The on-chain verifier re-derives this and checks it against
/// the per-nullifier PDA. The browser computes it locally so the
/// server never sees the raw nullifier.
#[wasm_bindgen(js_name = nullifierHash)]
pub fn nullifier_hash(nullifier: &Uint8Array) -> Result<Uint8Array, JsError> {
    let n = to_field_bytes(nullifier, "nullifier")?;
    let h = poseidon::hash(&[&n]).map_err(|e| JsError::new(&format!("poseidon failed: {e}")))?;
    Ok(Uint8Array::from(&h[..]))
}

// ──────────────────────────────────────────────────────────────────────────────
// Deposit-side: note generation + ML-KEM envelope, all in the browser
// ──────────────────────────────────────────────────────────────────────────────

/// A freshly generated deposit note. `secret`/`nullifier` are the spend
/// material (kept in the tab), `commitment` is the public leaf, `noteText`
/// is the opaque 132-hex backup string. None of this reaches the server
/// except `commitment` (public) and the sealed envelope.
#[wasm_bindgen]
pub struct GeneratedNote {
    secret: [u8; FIELD_BYTES],
    nullifier: [u8; FIELD_BYTES],
    commitment: [u8; FIELD_BYTES],
    note_text: String,
}

#[wasm_bindgen]
impl GeneratedNote {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Uint8Array {
        Uint8Array::from(&self.secret[..])
    }
    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> Uint8Array {
        Uint8Array::from(&self.nullifier[..])
    }
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> Uint8Array {
        Uint8Array::from(&self.commitment[..])
    }
    #[wasm_bindgen(getter, js_name = noteText)]
    pub fn note_text(&self) -> String {
        self.note_text.clone()
    }
}

/// Generate a fresh deposit note (random secret + nullifier), entirely in
/// the browser. Hidden-amount pool: the amount is **arbitrary** and is NOT
/// part of the commitment (`commitment = Poseidon(secret, nullifier)`,
/// ADR-001) — no fixed-denomination check. The amount is sealed into the
/// ML-KEM envelope by `buildEnvelope`, not into the note. The
/// `denomination` argument is accepted for call-site symmetry and ignored.
#[wasm_bindgen(js_name = generateNote)]
pub fn generate_note(_denomination: f64) -> Result<GeneratedNote, JsError> {
    use tidex6_core::types::{Commitment, Nullifier, Secret};
    let secret = Secret::random().map_err(|e| JsError::new(&format!("secret: {e}")))?;
    let nullifier = Nullifier::random().map_err(|e| JsError::new(&format!("nullifier: {e}")))?;
    let commitment = Commitment::derive(&secret, &nullifier)
        .map_err(|e| JsError::new(&format!("commitment: {e}")))?;
    Ok(GeneratedNote {
        secret: *secret.as_bytes(),
        nullifier: *nullifier.as_bytes(),
        commitment: *commitment.as_bytes(),
        // Stealth model: nothing is handed over, so no note-text backup.
        note_text: String::new(),
    })
}

/// Build the multi-slot ML-KEM envelope for a deposit, in the browser.
/// `recipient_pub` and `auditor_pub` are 1184-byte ML-KEM-768 public
/// keys (`auditor_pub` may be empty for no auditor slot). The recipient
/// slot seals `secret ‖ nullifier ‖ memo`; the auditor slot seals
/// `denomination ‖ memo` (cannot spend).
#[wasm_bindgen(js_name = buildEnvelope)]
pub fn build_envelope(
    recipient_pub: &Uint8Array,
    secret: &Uint8Array,
    nullifier: &Uint8Array,
    denomination_lamports: f64,
    memo: &str,
    auditor_pub: &Uint8Array,
) -> Result<Uint8Array, JsError> {
    // recipient_pub / auditor_pub — полные адреса `mlkem_pk ‖ x25519_pk`.
    let recipient =
        tidex6_core::envelope::ReaderAddress::from_bytes(&uint8array_to_vec(recipient_pub))
            .map_err(|e| JsError::new(&format!("invalid recipient address: {e}")))?;
    let s = to_field_bytes(secret, "secret")?;
    let n = to_field_bytes(nullifier, "nullifier")?;

    let auditors: Vec<tidex6_core::envelope::ReaderAddress> = if auditor_pub.length() == 0 {
        Vec::new()
    } else {
        let a = tidex6_core::envelope::ReaderAddress::from_bytes(&uint8array_to_vec(auditor_pub))
            .map_err(|e| JsError::new(&format!("invalid auditor address: {e}")))?;
        vec![a]
    };

    let envelope = envelope::build(
        &recipient,
        &s,
        &n,
        denomination_lamports as u64,
        memo.as_bytes(),
        &auditors,
    )
    .map_err(|e| JsError::new(&format!("envelope build failed: {e}")))?;

    Ok(Uint8Array::from(envelope.as_slice()))
}

// ──────────────────────────────────────────────────────────────────────────────
// Client-side scan: decrypt a memo envelope locally — secret never leaves the tab
// ──────────────────────────────────────────────────────────────────────────────

/// Recipient view of a decrypted memo slot — carries the note's spend
/// material so the browser can reconstruct and withdraw.
#[wasm_bindgen]
pub struct RecipientSlot {
    secret: [u8; FIELD_BYTES],
    nullifier: [u8; FIELD_BYTES],
    denomination: f64,
    memo: String,
}

#[wasm_bindgen]
impl RecipientSlot {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Uint8Array {
        Uint8Array::from(&self.secret[..])
    }
    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> Uint8Array {
        Uint8Array::from(&self.nullifier[..])
    }
    /// Amount sealed for the recipient (base units, e.g. 1_000_000 = 1 token).
    /// `0` for legacy v1 envelopes where the amount was public.
    #[wasm_bindgen(getter, js_name = denominationLamports)]
    pub fn denomination(&self) -> f64 {
        self.denomination
    }
    #[wasm_bindgen(getter)]
    pub fn memo(&self) -> String {
        self.memo.clone()
    }
}

/// Auditor view of a decrypted memo slot — amount + memo, cannot spend.
#[wasm_bindgen]
pub struct AuditorSlot {
    denomination: f64,
    memo: String,
}

#[wasm_bindgen]
impl AuditorSlot {
    #[wasm_bindgen(getter, js_name = denominationLamports)]
    pub fn denomination(&self) -> f64 {
        self.denomination
    }
    #[wasm_bindgen(getter)]
    pub fn memo(&self) -> String {
        self.memo.clone()
    }
}

/// Try to decrypt a memo envelope as the recipient. Returns the slot if
/// this ML-KEM secret is the addressee, else `undefined`. Runs entirely
/// in the browser — the secret never leaves the tab.
#[wasm_bindgen(js_name = decryptRecipientSlot)]
pub fn decrypt_recipient_slot(
    envelope: &Uint8Array,
    secret: &Uint8Array,
) -> Result<Option<RecipientSlot>, JsError> {
    let sk = PqcSecretKey::from_bytes(&uint8array_to_vec(secret))
        .map_err(|e| JsError::new(&format!("invalid ML-KEM secret: {e}")))?;
    let env = uint8array_to_vec(envelope);
    match envelope::open_as_recipient(&env, &sk) {
        Ok(Some(v)) => Ok(Some(RecipientSlot {
            secret: v.secret,
            nullifier: v.nullifier,
            denomination: v.denomination as f64,
            memo: String::from_utf8_lossy(&v.memo).into_owned(),
        })),
        Ok(None) => Ok(None),
        Err(e) => Err(JsError::new(&format!("decrypt failed: {e}"))),
    }
}

/// Try to decrypt a memo envelope as an auditor. Returns amount+memo if
/// this ML-KEM secret is an addressed auditor, else `undefined`.
#[wasm_bindgen(js_name = decryptAuditorSlot)]
pub fn decrypt_auditor_slot(
    envelope: &Uint8Array,
    secret: &Uint8Array,
) -> Result<Option<AuditorSlot>, JsError> {
    let sk = PqcSecretKey::from_bytes(&uint8array_to_vec(secret))
        .map_err(|e| JsError::new(&format!("invalid ML-KEM secret: {e}")))?;
    let env = uint8array_to_vec(envelope);
    match envelope::open_as_auditor(&env, &sk) {
        Ok(Some(v)) => Ok(Some(AuditorSlot {
            denomination: v.denomination as f64,
            memo: String::from_utf8_lossy(&v.memo).into_owned(),
        })),
        Ok(None) => Ok(None),
        Err(e) => Err(JsError::new(&format!("decrypt failed: {e}"))),
    }
}

/// A Merkle path built in the browser, ready for [`prove_withdraw`].
#[wasm_bindgen]
pub struct MerklePath {
    root: String,
    siblings: String,
    indices: Vec<u8>,
}

#[wasm_bindgen]
impl MerklePath {
    /// Tree root after every known leaf, hex. Must match what the pool holds.
    #[wasm_bindgen(getter, js_name = rootHex)]
    pub fn root_hex(&self) -> String {
        self.root.clone()
    }

    /// The 20 sibling hashes concatenated, leaf-adjacent first, hex.
    #[wasm_bindgen(getter, js_name = siblingsConcatHex)]
    pub fn siblings_concat_hex(&self) -> String {
        self.siblings.clone()
    }

    /// One byte per level: which side the sibling sits on.
    #[wasm_bindgen(getter, js_name = indices)]
    pub fn indices(&self) -> Vec<u8> {
        self.indices.clone()
    }
}

/// Rebuild the Merkle path for one leaf from the pool's full leaf list.
///
/// On Solana an indexer answers this question, because it already watches the
/// pool. The second chain has no such service, and adding one would put a
/// server between a person and their own money: if it were down, or lying, the
/// withdrawal could not be built or would be built against a root the pool
/// never held. The browser has everything it needs — the deposit log carries
/// every leaf in order — so the path is computed here, from data the chain
/// itself handed over.
///
/// `leaves_concat` is every commitment ever deposited, in leaf order,
/// concatenated — 32 bytes each. `leaf_index` is the position of the one being
/// spent.
///
/// The root that comes back is not decoration: compare it against the pool's
/// own `isKnownRoot` before proving. A mismatch means the leaf list is
/// incomplete — a log query that silently truncated, most likely — and proving
/// against it would produce a proof the pool rejects, after the work is done.
#[wasm_bindgen(js_name = merklePathFromLeaves)]
pub fn merkle_path_from_leaves(
    leaves_concat: &Uint8Array,
    leaf_index: u32,
) -> Result<MerklePath, JsError> {
    use tidex6_core::merkle::MerkleTree;
    use tidex6_core::types::Commitment;

    let raw = uint8array_to_vec(leaves_concat);
    if raw.len() % FIELD_BYTES != 0 {
        return Err(JsError::new(&format!(
            "leaves must be a whole number of 32-byte commitments, got {} bytes",
            raw.len()
        )));
    }
    let count = raw.len() / FIELD_BYTES;
    if leaf_index as usize >= count {
        return Err(JsError::new(&format!(
            "leaf {leaf_index} is not among the {count} leaves given — the deposit log is short"
        )));
    }

    let mut tree = MerkleTree::new(DEPTH).map_err(|e| JsError::new(&format!("tree: {e}")))?;
    for i in 0..count {
        let mut bytes = [0u8; FIELD_BYTES];
        bytes.copy_from_slice(&raw[i * FIELD_BYTES..(i + 1) * FIELD_BYTES]);
        tree.insert(Commitment::from_bytes(bytes))
            .map_err(|e| JsError::new(&format!("leaf {i}: {e}")))?;
    }

    let proof = tree
        .proof(leaf_index as u64)
        .map_err(|e| JsError::new(&format!("path: {e}")))?;

    let mut siblings = String::with_capacity(DEPTH * FIELD_BYTES * 2);
    for sibling in &proof.siblings {
        siblings.push_str(&sibling.to_hex());
    }
    // Bit `i` of the leaf index says which side sibling `i` sits on, LSB first
    // — the same convention `prove_withdraw` expects.
    let indices = (0..DEPTH).map(|i| ((leaf_index >> i) & 1) as u8).collect();

    Ok(MerklePath {
        root: tree.root().to_hex(),
        siblings,
        indices,
    })
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
    prove_withdraw_impl(
        secret,
        nullifier,
        path_siblings_concat,
        path_indices_packed,
        merkle_root,
        nullifier_hash,
        recipient,
        relayer_address,
        relayer_fee,
        proving_key,
        Layout::Solana,
    )
}

/// То же доказательство, но в раскладке, которую принимает контракт на Solidity.
///
/// Отдельный вывод, а не правка солановских байтов на месте. Точки там проходят
/// через `CanonicalSerialize`, а arkworks кладёт в старшие биты последнего байта
/// свои признаки сериализации: координата BN254 меньше модуля, и эти биты в ней
/// свободны. Solana такие байты принимает, прекомпайлы EVM — нет, и отказ
/// приходит как `InvalidProof`, то есть выглядит неверным доказательством, а не
/// разницей форматов. Здесь координаты берутся числами, места для признаков в
/// них нет.
#[wasm_bindgen(js_name = proveWithdrawEvm)]
#[allow(clippy::too_many_arguments)]
pub fn prove_withdraw_evm(
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
    prove_withdraw_impl(
        secret,
        nullifier,
        path_siblings_concat,
        path_indices_packed,
        merkle_root,
        nullifier_hash,
        recipient,
        relayer_address,
        relayer_fee,
        proving_key,
        Layout::Evm,
    )
}

/// В какой цепи это доказательство будут проверять.
enum Layout {
    Solana,
    Evm,
}

#[allow(clippy::too_many_arguments)]
fn prove_withdraw_impl(
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
    layout: Layout,
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

    let out = match layout {
        Layout::Evm => groth16_proof_to_evm_bytes(&proof).to_vec(),
        Layout::Solana => {
            let Groth16SolanaBytes {
                proof_a,
                proof_b,
                proof_c,
                ..
            } = groth16_to_solana_bytes(&proof, &pk.vk)
                .map_err(|e| JsError::new(&format!("groth16_to_solana_bytes failed: {e}")))?;

            let mut bytes = Vec::with_capacity(PROOF_TOTAL_BYTES);
            bytes.extend_from_slice(&proof_a);
            bytes.extend_from_slice(&proof_b);
            bytes.extend_from_slice(&proof_c);
            bytes
        }
    };
    debug_assert_eq!(out.len(), PROOF_TOTAL_BYTES);

    Ok(Uint8Array::from(out.as_slice()))
}

/// Внести вклад в trusted-setup церемонию целиком в браузере (Путь A,
/// Rust-native — замена snarkjs `zKey.contribute`).
///
/// Вход — байты `CeremonyState` (скачанные с сервера). Свежая случайность
/// берётся из браузерного CSPRNG (`thread_rng` → getrandom/js →
/// crypto.getRandomValues) и НИКОГДА не покидает вкладку — на сервер уходит
/// только результат. Выход — новый `CeremonyState` для загрузки.
#[wasm_bindgen]
pub fn ceremony_contribute(state_bytes: &Uint8Array, name: &str) -> Result<Uint8Array, JsError> {
    use tidex6_circuits::mpc::{CeremonyState, contribute_state};

    let bytes = uint8array_to_vec(state_bytes);
    let mut state = CeremonyState::from_bytes(&bytes)
        .map_err(|e| JsError::new(&format!("failed to deserialize ceremony state: {e}")))?;

    let clean_name: String = if name.trim().is_empty() {
        "anonymous".to_string()
    } else {
        name.chars().filter(|c| !c.is_control()).take(64).collect()
    };

    // Браузерный CSPRNG — контрибьюторская «toxic waste», локальна.
    let mut rng = rand::thread_rng();
    contribute_state(&mut state, clean_name, &mut rng);

    let out = state.to_bytes();
    Ok(Uint8Array::from(out.as_slice()))
}

// ─── Hidden-amount pool (ADR-015) ───────────────────────────────────────────
//
// Notes of any size: `commitment = Poseidon(secret, nullifier, amount)`, the
// amount proven in range by the circuits in `tidex6-confidential`. Amounts are
// `u64` base units and cross the JS boundary as `BigInt`.

/// Field element from 32 big-endian bytes.
fn fr_from_be(bytes: &[u8; FIELD_BYTES]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// The Merkle path as the hidden-amount circuits take it: `DEPTH` sibling
/// field elements and `DEPTH` direction bits.
fn hidden_merkle_path(
    path_siblings_concat: &Uint8Array,
    path_indices_packed: &Uint8Array,
) -> Result<([Fr; DEPTH], [bool; DEPTH]), JsError> {
    let siblings_buf = uint8array_to_vec(path_siblings_concat);
    if siblings_buf.len() != DEPTH * FIELD_BYTES {
        return Err(JsError::new(&format!(
            "path_siblings_concat must be {} bytes ({} levels × 32), got {}",
            DEPTH * FIELD_BYTES,
            DEPTH,
            siblings_buf.len()
        )));
    }
    let siblings: [Fr; DEPTH] = std::array::from_fn(|i| {
        let mut word = [0u8; FIELD_BYTES];
        word.copy_from_slice(&siblings_buf[i * FIELD_BYTES..(i + 1) * FIELD_BYTES]);
        fr_from_be(&word)
    });

    let indices_buf = uint8array_to_vec(path_indices_packed);
    if indices_buf.len() != DEPTH {
        return Err(JsError::new(&format!(
            "path_indices_packed must be {DEPTH} bytes, got {}",
            indices_buf.len()
        )));
    }
    let mut indices = [false; DEPTH];
    for (i, slot) in indices.iter_mut().enumerate() {
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
    Ok((siblings, indices))
}

/// Deserialize a proving key the browser fetched.
fn proving_key_from(bytes: &Uint8Array) -> Result<ProvingKey<Bn254>, JsError> {
    let pk_bytes = uint8array_to_vec(bytes);
    ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&pk_bytes[..])
        .map_err(|e| JsError::new(&format!("failed to deserialize proving key: {e}")))
}

/// `Poseidon(secret, nullifier, amount)` — the leaf a hidden-amount note
/// occupies. Same function on every chain the hidden pool runs on.
#[wasm_bindgen(js_name = commitmentHidden)]
pub fn commitment_hidden(
    secret: &Uint8Array,
    nullifier: &Uint8Array,
    amount: u64,
) -> Result<Uint8Array, JsError> {
    let secret = fr_from_be(&to_field_bytes(secret, "secret")?);
    let nullifier = fr_from_be(&to_field_bytes(nullifier, "nullifier")?);
    let commitment = hidden::note_commitment(secret, nullifier, Fr::from(amount));
    Ok(Uint8Array::from(&fr_to_be_bytes(commitment)[..]))
}

/// Withdraw proof for the hidden-amount pool, in the byte layout the EVM
/// verifier reads. Recipient and relayer are 32-byte words (an address
/// left-padded with 12 zero bytes); `relayer_fee` and `amount` are base units.
///
/// The key is a ceremony key (genesis or final), so the proof is built with
/// the snarkjs-compatible reduction — `hidden::prove_ceremony`.
#[wasm_bindgen(js_name = proveHiddenWithdrawEvm)]
#[allow(clippy::too_many_arguments)]
pub fn prove_hidden_withdraw_evm(
    secret: &Uint8Array,
    nullifier: &Uint8Array,
    amount: u64,
    path_siblings_concat: &Uint8Array,
    path_indices_packed: &Uint8Array,
    merkle_root: &Uint8Array,
    recipient: &Uint8Array,
    relayer_address: &Uint8Array,
    relayer_fee: u64,
    proving_key: &Uint8Array,
) -> Result<Uint8Array, JsError> {
    let (path_siblings, path_indices) =
        hidden_merkle_path(path_siblings_concat, path_indices_packed)?;
    let witness = hidden::WithdrawWitness {
        amount,
        secret: fr_from_be(&to_field_bytes(secret, "secret")?),
        nullifier: fr_from_be(&to_field_bytes(nullifier, "nullifier")?),
        path_siblings,
        path_indices,
        merkle_root: fr_from_be(&to_field_bytes(merkle_root, "merkle_root")?),
        recipient: to_field_bytes(recipient, "recipient")?,
        relayer: to_field_bytes(relayer_address, "relayer_address")?,
        relayer_fee,
    };
    let pk = proving_key_from(proving_key)?;
    let mut rng = rand::thread_rng();
    let (proof, _public_inputs) = hidden::prove_ceremony(&pk, &witness, &mut rng)
        .map_err(|e| JsError::new(&format!("prove_hidden_withdraw failed: {e}")))?;
    Ok(Uint8Array::from(&groth16_proof_to_evm_bytes(&proof)[..]))
}

/// Join-split proof: spend one note into two, every amount hidden. Returns the
/// proof in the EVM layout; the caller computes the two output commitments
/// with `commitmentHidden` and the spent note's `nullifierHash` for the public
/// inputs `[merkle_root, nullifier_hash, commitment_out1, commitment_out2]`.
///
/// The join-split key is the seeded development setup (arkworks), so this uses
/// the default reduction. When the circuit joins the ceremony, switch to
/// `transfer::prove_ceremony` together with the verifier.
#[wasm_bindgen(js_name = proveHiddenTransferEvm)]
#[allow(clippy::too_many_arguments)]
pub fn prove_hidden_transfer_evm(
    secret_in: &Uint8Array,
    nullifier_in: &Uint8Array,
    amount_in: u64,
    path_siblings_concat: &Uint8Array,
    path_indices_packed: &Uint8Array,
    merkle_root: &Uint8Array,
    secret_out1: &Uint8Array,
    nullifier_out1: &Uint8Array,
    amount_out1: u64,
    secret_out2: &Uint8Array,
    nullifier_out2: &Uint8Array,
    amount_out2: u64,
    proving_key: &Uint8Array,
) -> Result<Uint8Array, JsError> {
    if amount_in != amount_out1.saturating_add(amount_out2)
        || amount_out1.checked_add(amount_out2).is_none()
    {
        return Err(JsError::new(
            "join-split must conserve the amount: in == out1 + out2",
        ));
    }
    let (path_siblings, path_indices) =
        hidden_merkle_path(path_siblings_concat, path_indices_packed)?;
    let witness = transfer::TransferWitness {
        amount_in,
        secret_in: fr_from_be(&to_field_bytes(secret_in, "secret_in")?),
        nullifier_in: fr_from_be(&to_field_bytes(nullifier_in, "nullifier_in")?),
        path_siblings,
        path_indices,
        amount_out1,
        secret_out1: fr_from_be(&to_field_bytes(secret_out1, "secret_out1")?),
        nullifier_out1: fr_from_be(&to_field_bytes(nullifier_out1, "nullifier_out1")?),
        amount_out2,
        secret_out2: fr_from_be(&to_field_bytes(secret_out2, "secret_out2")?),
        nullifier_out2: fr_from_be(&to_field_bytes(nullifier_out2, "nullifier_out2")?),
        merkle_root: fr_from_be(&to_field_bytes(merkle_root, "merkle_root")?),
    };
    let pk = proving_key_from(proving_key)?;
    let mut rng = rand::thread_rng();
    let (proof, _public_inputs) = transfer::prove(&pk, &witness, &mut rng)
        .map_err(|e| JsError::new(&format!("prove_hidden_transfer failed: {e}")))?;
    Ok(Uint8Array::from(&groth16_proof_to_evm_bytes(&proof)[..]))
}

// ─── Note format v2 (ADR-022) ───────────────────────────────────────────────
//
// The note belongs to an owner key, the pool files its leaf from the amount it
// received, the nullifier depends on the leaf position. Field elements cross
// the boundary as 32 big-endian bytes, amounts as `BigInt` base units. Keys are
// ceremony keys (snarkjs layout), so both provers use `prove_ceremony`.

fn field(bytes: &Uint8Array, name: &str) -> Result<Fr, JsError> {
    Ok(fr_from_be(&to_field_bytes(bytes, name)?))
}

fn field_out(value: Fr) -> Uint8Array {
    Uint8Array::from(&fr_to_be_bytes(value)[..])
}

/// Owner key published in the registry: `H(D_OWNER, spending_key)`.
#[wasm_bindgen(js_name = ownerPkV2)]
pub fn owner_pk_v2(spending_key: &Uint8Array) -> Result<Uint8Array, JsError> {
    Ok(field_out(note_v2::owner_pk(field(
        spending_key,
        "spending_key",
    )?)))
}

/// Note core the sender passes to the pool with the money.
#[wasm_bindgen(js_name = coreV2)]
pub fn core_v2(
    owner_pk: &Uint8Array,
    rho: &Uint8Array,
    aux: &Uint8Array,
) -> Result<Uint8Array, JsError> {
    Ok(field_out(note_v2::core(
        field(owner_pk, "owner_pk")?,
        field(rho, "rho")?,
        field(aux, "aux")?,
    )))
}

/// Leaf of a note: `H(H(core, amount), refund)`; `refund` is zero bytes for a
/// note without refund, else [`refund_tag_evm`].
#[wasm_bindgen(js_name = leafV2)]
pub fn leaf_v2(core: &Uint8Array, amount: u64, refund: &Uint8Array) -> Result<Uint8Array, JsError> {
    Ok(field_out(note_v2::leaf(
        note_v2::body(field(core, "core")?, amount),
        field(refund, "refund")?,
    )))
}

/// Refund tag of an EVM deposit: the funder's 20-byte address and the moment
/// the refund opens (the `refundAfter` of the Deposit event).
#[wasm_bindgen(js_name = refundTagEvm)]
pub fn refund_tag_evm(funder: &Uint8Array, refund_after: u64) -> Result<Uint8Array, JsError> {
    let bytes = uint8array_to_vec(funder);
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| JsError::new("funder must be a 20-byte address"))?;
    Ok(field_out(note_v2::refund_tag(
        note_v2::refund_addr_evm(address),
        refund_after,
    )))
}

/// Nullifier of the note at `position`, shared by withdraw and refund.
#[wasm_bindgen(js_name = nullifierV2)]
pub fn nullifier_v2(rho: &Uint8Array, position: u64) -> Result<Uint8Array, JsError> {
    Ok(field_out(note_v2::nullifier(field(rho, "rho")?, position)))
}

/// Fee of a payment: 1% rounded up, at least `floor` — the pool's formula.
#[wasm_bindgen(js_name = feeForV2)]
pub fn fee_for_v2(amount: u64, floor: u64) -> u64 {
    transfer_v2::fee_for(amount, floor)
}

/// Fresh note randomness (`rho`) from the browser CSPRNG.
#[wasm_bindgen(js_name = randomFieldV2)]
pub fn random_field_v2() -> Result<Uint8Array, JsError> {
    let secret = tidex6_core::types::Secret::random()
        .map_err(|e| JsError::new(&format!("randomness: {e}")))?;
    Ok(Uint8Array::from(&secret.as_bytes()[..]))
}

/// Withdraw proof for a v2 note in the EVM layout. Recipient and relayer are
/// 32-byte words (address left-padded with zeros); amounts are base units.
#[wasm_bindgen(js_name = proveWithdrawV2Evm)]
#[allow(clippy::too_many_arguments)]
pub fn prove_withdraw_v2_evm(
    spending_key: &Uint8Array,
    rho: &Uint8Array,
    aux: &Uint8Array,
    amount: u64,
    refund: &Uint8Array,
    path_siblings_concat: &Uint8Array,
    path_indices_packed: &Uint8Array,
    merkle_root: &Uint8Array,
    recipient: &Uint8Array,
    relayer_address: &Uint8Array,
    relayer_fee: u64,
    proving_key: &Uint8Array,
) -> Result<Uint8Array, JsError> {
    if relayer_fee > amount {
        return Err(JsError::new("relayer fee exceeds the note amount"));
    }
    let (path_siblings, path_indices) =
        hidden_merkle_path(path_siblings_concat, path_indices_packed)?;
    let witness = withdraw_v2::WithdrawV2Witness {
        sk_spend: field(spending_key, "spending_key")?,
        rho: field(rho, "rho")?,
        aux: field(aux, "aux")?,
        amount,
        refund: field(refund, "refund")?,
        path_siblings,
        path_indices,
        merkle_root: field(merkle_root, "merkle_root")?,
        recipient: to_field_bytes(recipient, "recipient")?,
        relayer: to_field_bytes(relayer_address, "relayer_address")?,
        relayer_fee,
    };
    let pk = proving_key_from(proving_key)?;
    let mut rng = rand::thread_rng();
    let (proof, _public_inputs) = withdraw_v2::prove_ceremony(&pk, &witness, &mut rng)
        .map_err(|e| JsError::new(&format!("prove_withdraw_v2 failed: {e}")))?;
    Ok(Uint8Array::from(&groth16_proof_to_evm_bytes(&proof)[..]))
}

/// An in-pool v2 transfer: the proof and the public values the pool takes.
#[wasm_bindgen]
pub struct TransferV2Proof {
    proof: Vec<u8>,
    nullifier: Fr,
    commitment_pay: Fr,
    commitment_change: Fr,
    commitment_fee: Fr,
}

#[wasm_bindgen]
impl TransferV2Proof {
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> Uint8Array {
        Uint8Array::from(self.proof.as_slice())
    }
    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> Uint8Array {
        field_out(self.nullifier)
    }
    #[wasm_bindgen(getter, js_name = commitmentPay)]
    pub fn commitment_pay(&self) -> Uint8Array {
        field_out(self.commitment_pay)
    }
    #[wasm_bindgen(getter, js_name = commitmentChange)]
    pub fn commitment_change(&self) -> Uint8Array {
        field_out(self.commitment_change)
    }
    #[wasm_bindgen(getter, js_name = commitmentFee)]
    pub fn commitment_fee(&self) -> Uint8Array {
        field_out(self.commitment_fee)
    }
}

/// In-pool forward 1 → 3: the payment to `core_pay`, change back to the
/// spender, the fee to the treasury. Checked here before proving, since a
/// Groth16 prover does not refuse an unsatisfied witness — it returns a proof
/// the pool rejects after the user has paid gas.
#[wasm_bindgen(js_name = proveTransferV2Evm)]
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer_v2_evm(
    spending_key: &Uint8Array,
    rho_in: &Uint8Array,
    aux_in: &Uint8Array,
    amount_in: u64,
    refund_in: &Uint8Array,
    path_siblings_concat: &Uint8Array,
    path_indices_packed: &Uint8Array,
    merkle_root: &Uint8Array,
    core_pay: &Uint8Array,
    amount_pay: u64,
    rho_change: &Uint8Array,
    amount_change: u64,
    rho_fee: &Uint8Array,
    amount_fee: u64,
    treasury_pk: &Uint8Array,
    fee_floor: u64,
    proving_key: &Uint8Array,
) -> Result<TransferV2Proof, JsError> {
    let total = amount_pay
        .checked_add(amount_change)
        .and_then(|sum| sum.checked_add(amount_fee));
    if total != Some(amount_in) {
        return Err(JsError::new(
            "transfer must conserve the amount: in == pay + change + fee",
        ));
    }
    if amount_fee < transfer_v2::fee_for(amount_pay, fee_floor) {
        return Err(JsError::new(
            "fee below 1% of the payment or the pool floor",
        ));
    }
    let (path_siblings, path_indices) =
        hidden_merkle_path(path_siblings_concat, path_indices_packed)?;
    let witness = transfer_v2::TransferV2Witness {
        sk_spend: field(spending_key, "spending_key")?,
        rho_in: field(rho_in, "rho_in")?,
        aux_in: field(aux_in, "aux_in")?,
        amount_in,
        refund_in: field(refund_in, "refund_in")?,
        path_siblings,
        path_indices,
        core_pay: field(core_pay, "core_pay")?,
        amount_pay,
        rho_change: field(rho_change, "rho_change")?,
        aux_change: Fr::from(0u64),
        amount_change,
        rho_fee: field(rho_fee, "rho_fee")?,
        amount_fee,
        merkle_root: field(merkle_root, "merkle_root")?,
        treasury_pk: field(treasury_pk, "treasury_pk")?,
        fee_floor,
    };
    let pk = proving_key_from(proving_key)?;
    let mut rng = rand::thread_rng();
    let (proof, public) = transfer_v2::prove_ceremony(&pk, &witness, &mut rng)
        .map_err(|e| JsError::new(&format!("prove_transfer_v2 failed: {e}")))?;
    // Public inputs: [root, nf, cm_pay, cm_change, cm_fee, treasury_pk, fee_floor].
    Ok(TransferV2Proof {
        proof: groth16_proof_to_evm_bytes(&proof).to_vec(),
        nullifier: public[1],
        commitment_pay: public[2],
        commitment_change: public[3],
        commitment_fee: public[4],
    })
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
