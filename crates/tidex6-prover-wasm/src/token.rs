//! Confidential-token proofs in the browser (ADR-023).
//!
//! Points cross the JS boundary as 64 bytes, `x ‖ y`, each a 32-byte
//! big-endian element of the BN254 scalar field — the field Baby Jubjub
//! coordinates live in. Scalars that the page must keep (the ElGamal secret,
//! a ciphertext's opening) cross as 32 bytes little-endian.
//!
//! Every proof is verified here against its own key before it is returned:
//! a Groth16 prover does not refuse an unsatisfied witness, it returns a proof
//! the contract rejects after the user has paid gas.
//!
//! The keys are development keys until the token circuits have their own
//! ceremony, so proving uses the plain Groth16 reduction those keys were made
//! with.

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BjjFr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_snark::SNARK;
use js_sys::Uint8Array;
use tidex6_confidential::token::elgamal::{self, Ciphertext, PublicKey, SecretKey};
use tidex6_confidential::token::{deposit, exit, pubkey, transfer, unwrap};
use wasm_bindgen::prelude::*;

use crate::{
    field, groth16_proof_to_evm_bytes, hidden_merkle_path, proving_key_from, uint8array_to_vec,
};

/// A confidential-token key derived from the wallet signature.
#[wasm_bindgen]
pub struct TokenKey {
    secret: [u8; 32],
    public: [u8; 64],
}

#[wasm_bindgen]
impl TokenKey {
    /// The ElGamal secret, 32 bytes little-endian. Stays in this tab.
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Uint8Array {
        Uint8Array::from(&self.secret[..])
    }

    /// The public key `P = s⁻¹·H` as `x ‖ y`.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(&self.public[..])
    }
}

/// A token proof with everything the contract call needs.
#[wasm_bindgen]
pub struct TokenProof {
    proof: Vec<u8>,
    inputs: Vec<u8>,
    opening: [u8; 32],
}

#[wasm_bindgen]
impl TokenProof {
    /// `a ‖ b ‖ c` in the EVM layout, 256 bytes.
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> Uint8Array {
        Uint8Array::from(self.proof.as_slice())
    }

    /// The public inputs in circuit order, 32 bytes big-endian each.
    #[wasm_bindgen(getter)]
    pub fn inputs(&self) -> Uint8Array {
        Uint8Array::from(self.inputs.as_slice())
    }

    /// The opening `r` of the amount commitment, 32 bytes little-endian — it
    /// goes into the envelope so the reader learns the amount without a
    /// discrete log. Zero for proofs that commit no new amount.
    #[wasm_bindgen(getter)]
    pub fn opening(&self) -> Uint8Array {
        Uint8Array::from(&self.opening[..])
    }
}

fn js(context: &str) -> impl Fn(String) -> JsError + '_ {
    move |message| JsError::new(&format!("{context}: {message}"))
}

fn secret_from(bytes: &Uint8Array) -> Result<SecretKey, JsError> {
    let raw = uint8array_to_vec(bytes);
    if raw.len() != 32 {
        return Err(JsError::new("token secret must be 32 bytes"));
    }
    let s = BjjFr::from_le_bytes_mod_order(&raw);
    if s == BjjFr::from(0u64) {
        return Err(JsError::new("token secret is zero"));
    }
    Ok(SecretKey(s))
}

fn point_from(bytes: &Uint8Array, name: &str) -> Result<EdwardsAffine, JsError> {
    let raw = uint8array_to_vec(bytes);
    if raw.len() != 64 {
        return Err(JsError::new(&format!("{name} must be 64 bytes (x ‖ y)")));
    }
    let x = Fr::from_be_bytes_mod_order(&raw[..32]);
    let y = Fr::from_be_bytes_mod_order(&raw[32..]);
    let point = EdwardsAffine::new_unchecked(x, y);
    if !point.is_on_curve() {
        return Err(JsError::new(&format!("{name} is not on Baby Jubjub")));
    }
    Ok(point)
}

fn key_from(bytes: &Uint8Array, name: &str) -> Result<PublicKey, JsError> {
    PublicKey::from_affine(point_from(bytes, name)?)
        .map_err(|e| JsError::new(&format!("{name}: {e}")))
}

fn cipher_from(commitment: &Uint8Array, handle: &Uint8Array) -> Result<Ciphertext, JsError> {
    Ok(Ciphertext {
        commitment: point_from(commitment, "commitment")?,
        handle: point_from(handle, "handle")?,
    })
}

fn point_bytes(point: &EdwardsAffine) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (half, coordinate) in [point.x, point.y].iter().enumerate() {
        let bytes = coordinate.into_bigint().to_bytes_be();
        out[half * 32 + 32 - bytes.len()..(half + 1) * 32].copy_from_slice(&bytes);
    }
    out
}

fn scalar_bytes(s: &BjjFr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = s.into_bigint().to_bytes_le();
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

/// Verify against the key's own VK, then pack for the contract.
fn finish(
    pk: &ProvingKey<Bn254>,
    proof: Proof<Bn254>,
    inputs: &[Fr],
    opening: [u8; 32],
) -> Result<TokenProof, JsError> {
    let ok = Groth16::<Bn254>::verify(&pk.vk, inputs, &proof)
        .map_err(|e| JsError::new(&format!("self-check: {e}")))?;
    if !ok {
        return Err(JsError::new(
            "the proof does not verify — the balance, amount or key do not match",
        ));
    }
    let mut packed = Vec::with_capacity(inputs.len() * 32);
    for input in inputs {
        let bytes = input.into_bigint().to_bytes_be();
        packed.extend(core::iter::repeat_n(0u8, 32 - bytes.len()));
        packed.extend_from_slice(&bytes);
    }
    Ok(TokenProof {
        proof: groth16_proof_to_evm_bytes(&proof).to_vec(),
        inputs: packed,
        opening,
    })
}

/// Derive the token key from the wallet's signature over the identity message —
/// the same signature that gives the reader key, under its own domain.
#[wasm_bindgen(js_name = tokenKeyFromSignature)]
pub fn token_key_from_signature(signature: &[u8]) -> Result<TokenKey, JsError> {
    let seed = tidex6_core::identity::elgamal_seed(signature)
        .map_err(|e| JsError::new(&format!("derive token key: {e}")))?;
    let secret = SecretKey::from_seed(&seed).map_err(|e| JsError::new(&e.to_string()))?;
    let public = secret
        .public_key()
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(TokenKey {
        secret: scalar_bytes(&secret.0),
        public: point_bytes(&public.0),
    })
}

/// Registration proof: the key is `s⁻¹·H` for a secret this tab knows.
#[wasm_bindgen(js_name = tokenProvePubkey)]
pub fn token_prove_pubkey(
    secret: &Uint8Array,
    proving_key: &Uint8Array,
) -> Result<TokenProof, JsError> {
    let secret = secret_from(secret)?;
    let public = secret
        .public_key()
        .map_err(|e| JsError::new(&e.to_string()))?;
    let pk = proving_key_from(proving_key)?;
    let (proof, inputs) = pubkey::prove(&pk, &secret, &public, &mut rand::thread_rng())
        .map_err(|e| js("pubkey proof")(e.to_string()))?;
    finish(&pk, proof, &inputs, [0u8; 32])
}

/// Transfer between balances. `auditor` may be the sender's own key when the
/// sender names nobody.
#[wasm_bindgen(js_name = tokenProveTransfer)]
#[allow(clippy::too_many_arguments)]
pub fn token_prove_transfer(
    secret: &Uint8Array,
    balance: u64,
    available_commitment: &Uint8Array,
    available_handle: &Uint8Array,
    amount: u64,
    recipient_key: &Uint8Array,
    auditor_key: &Uint8Array,
    proving_key: &Uint8Array,
) -> Result<TokenProof, JsError> {
    let mut rng = rand::thread_rng();
    let opening = elgamal::random_opening(&mut rng);
    let witness = transfer::TokenTransferWitness {
        secret: secret_from(secret)?,
        balance,
        available: cipher_from(available_commitment, available_handle)?,
        amount,
        opening,
        recipient: key_from(recipient_key, "recipient key")?,
        auditor: key_from(auditor_key, "auditor key")?,
    };
    let pk = proving_key_from(proving_key)?;
    let (proof, public) = transfer::prove(&pk, &witness, &mut rng)
        .map_err(|e| js("transfer proof")(e.to_string()))?;
    finish(&pk, proof, &public.inputs(), scalar_bytes(&opening))
}

/// Leave for the open ERC-20: the amount is public.
#[wasm_bindgen(js_name = tokenProveUnwrap)]
pub fn token_prove_unwrap(
    secret: &Uint8Array,
    balance: u64,
    available_commitment: &Uint8Array,
    available_handle: &Uint8Array,
    amount: u64,
    proving_key: &Uint8Array,
) -> Result<TokenProof, JsError> {
    let witness = unwrap::TokenUnwrapWitness {
        secret: secret_from(secret)?,
        balance,
        available: cipher_from(available_commitment, available_handle)?,
        amount,
    };
    let pk = proving_key_from(proving_key)?;
    let (proof, inputs) = unwrap::prove(&pk, &witness, &mut rand::thread_rng())
        .map_err(|e| js("unwrap proof")(e.to_string()))?;
    finish(&pk, proof, &inputs, [0u8; 32])
}

/// From the balance into the pool: payment to `core_pay`, fee to the treasury.
#[wasm_bindgen(js_name = tokenProveDeposit)]
#[allow(clippy::too_many_arguments)]
pub fn token_prove_deposit(
    secret: &Uint8Array,
    balance: u64,
    available_commitment: &Uint8Array,
    available_handle: &Uint8Array,
    amount_pay: u64,
    amount_fee: u64,
    core_pay: &Uint8Array,
    rho_fee: &Uint8Array,
    treasury_pk: &Uint8Array,
    fee_floor: u64,
    proving_key: &Uint8Array,
) -> Result<TokenProof, JsError> {
    let mut rng = rand::thread_rng();
    let opening = elgamal::random_opening(&mut rng);
    let witness = deposit::DepositFromTokenWitness {
        secret: secret_from(secret)?,
        balance,
        available: cipher_from(available_commitment, available_handle)?,
        amount_pay,
        amount_fee,
        opening,
        core_pay: field(core_pay, "core_pay")?,
        rho_fee: field(rho_fee, "rho_fee")?,
        treasury_pk: field(treasury_pk, "treasury_pk")?,
        fee_floor,
    };
    let pk = proving_key_from(proving_key)?;
    let (proof, public) =
        deposit::prove(&pk, &witness, &mut rng).map_err(|e| js("deposit proof")(e.to_string()))?;
    finish(&pk, proof, &public.inputs(), scalar_bytes(&opening))
}

/// Spend a v2 note onto `recipient_key`'s pending balance.
#[wasm_bindgen(js_name = tokenProveExit)]
#[allow(clippy::too_many_arguments)]
pub fn token_prove_exit(
    spending_key: &Uint8Array,
    rho: &Uint8Array,
    aux: &Uint8Array,
    amount: u64,
    refund: &Uint8Array,
    path_siblings_concat: &Uint8Array,
    path_indices_packed: &Uint8Array,
    merkle_root: &Uint8Array,
    recipient_key: &Uint8Array,
    proving_key: &Uint8Array,
) -> Result<TokenProof, JsError> {
    let mut rng = rand::thread_rng();
    let opening = elgamal::random_opening(&mut rng);
    let (path_siblings, path_indices) =
        hidden_merkle_path(path_siblings_concat, path_indices_packed)?;
    let witness = exit::WithdrawToTokenWitness {
        sk_spend: field(spending_key, "spending_key")?,
        rho: field(rho, "rho")?,
        aux: field(aux, "aux")?,
        amount,
        refund: field(refund, "refund")?,
        path_siblings,
        path_indices,
        merkle_root: field(merkle_root, "merkle_root")?,
        opening,
        recipient: key_from(recipient_key, "recipient key")?,
    };
    let pk = proving_key_from(proving_key)?;
    let (proof, public) =
        exit::prove(&pk, &witness, &mut rng).map_err(|e| js("exit proof")(e.to_string()))?;
    finish(&pk, proof, &public.inputs(), scalar_bytes(&opening))
}

/// Read a balance by brute force over `bits` bits — the fallback when no
/// opening is at hand. 32 bits is a fraction of a second.
#[wasm_bindgen(js_name = tokenDecodeBalance)]
pub fn token_decode_balance(
    secret: &Uint8Array,
    commitment: &Uint8Array,
    handle: &Uint8Array,
    bits: u32,
) -> Result<u64, JsError> {
    let secret = secret_from(secret)?;
    let point = secret.decrypt_point(&cipher_from(commitment, handle)?);
    elgamal::decode_amount(&point, bits).map_err(|e| JsError::new(&e.to_string()))
}

/// Does `commitment` open to `amount` with `opening`? How a reader checks the
/// amount an envelope claims.
#[wasm_bindgen(js_name = tokenOpens)]
pub fn token_opens(
    commitment: &Uint8Array,
    amount: u64,
    opening: &Uint8Array,
) -> Result<bool, JsError> {
    let raw = uint8array_to_vec(opening);
    if raw.len() != 32 {
        return Err(JsError::new("opening must be 32 bytes"));
    }
    let r = BjjFr::from_le_bytes_mod_order(&raw);
    Ok(elgamal::opens_to(
        &point_from(commitment, "commitment")?,
        amount,
        r,
    ))
}
