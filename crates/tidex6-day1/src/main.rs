//! Day-1 Validation Checklist harness for tidex6.
//!
//! This binary runs the Day-1 kill gates against a live Solana cluster.
//! Each gate sends a transaction to the deployed `tidex6-verifier`
//! program, reads the program logs, and asserts the invariant that the
//! gate is protecting.
//!
//! - Gate 1 — Poseidon offchain ↔ onchain equivalence. Sends a
//!   `hash_poseidon` transaction with the canonical two-input test
//!   vector and compares the onchain result against the offchain
//!   `tidex6_core::poseidon::hash_pair` output byte-for-byte.
//!
//! - Gate 2 — Groth16 pipeline smoke test. Sends a `verify_test_proof`
//!   transaction with a known-good Groth16 proof (copied from the
//!   `groth16-solana` upstream test suite), asserts the program
//!   reports `VALID`. Passing this gate proves that `groth16-solana`
//!   can verify proofs onchain on the target cluster.
//!
//! - Gate 3 — `alt_bn128` syscall availability. Implicitly validated
//!   by Gate 2: the Groth16 verifier internally calls
//!   `alt_bn128_addition`, `alt_bn128_multiplication`, and
//!   `alt_bn128_pairing` syscalls. A successful `verify_test_proof`
//!   proves all three are active on the cluster.
//!
//! Gate 4 — Anchor 1.0 CPI with proof data — is the job of the
//! `tidex6-caller` program and is exercised in a separate harness.
//!
//! See `docs/release/security.md` section 3 for the full kill-gate
//! specification.

use std::rc::Rc;

use anchor_client::{Client, Cluster, CommitmentConfig, Signer};
use anyhow::{Context, Result, anyhow};
use ark_bn254::g1::G1Affine as G1;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use solana_keypair::{Keypair, read_keypair_file};
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signature::Signature;
use solana_transaction_status::{UiTransactionEncoding, option_serializer::OptionSerializer};

use tidex6_caller::accounts as caller_accounts;
use tidex6_caller::instruction as caller_instruction;
use tidex6_core::poseidon;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

const POSEIDON_LOG_PREFIX: &str = "Program log: tidex6-day1-poseidon:";
const GROTH16_VALID_LINE: &str = "Program log: tidex6-day1-groth16:VALID";
const ALT_BN128_OK_LINE: &str = "Program log: tidex6-day1-alt_bn128:OK";
const CPI_OK_LINE: &str = "Program log: tidex6-day1-cpi:OK";

/// The canonical Groth16 proof from the upstream `groth16-solana`
/// 0.2.0 test suite (`proof_verification_should_succeed`). Known to
/// verify against the `VERIFYING_KEY` hardcoded in
/// `programs/tidex6-verifier/src/groth16_test_vectors.rs`.
const RAW_PROOF: [u8; 256] = [
    45, 206, 255, 166, 152, 55, 128, 138, 79, 217, 145, 164, 25, 74, 120, 234, 234, 217, 68, 149,
    162, 44, 133, 120, 184, 205, 12, 44, 175, 98, 168, 172, 20, 24, 216, 15, 209, 175, 106, 75,
    147, 236, 90, 101, 123, 219, 245, 151, 209, 202, 218, 104, 148, 8, 32, 254, 243, 191, 218, 122,
    42, 81, 193, 84, 40, 57, 233, 205, 180, 46, 35, 111, 215, 5, 23, 93, 12, 71, 118, 225, 7, 46,
    247, 147, 47, 130, 106, 189, 184, 80, 146, 103, 141, 52, 242, 25, 0, 203, 124, 176, 110, 34,
    151, 212, 66, 180, 238, 151, 236, 189, 133, 209, 17, 137, 205, 183, 168, 196, 92, 159, 75, 174,
    81, 168, 18, 86, 176, 56, 16, 26, 210, 20, 18, 81, 122, 142, 104, 62, 251, 169, 98, 141, 21,
    253, 50, 130, 182, 15, 33, 109, 228, 31, 79, 183, 88, 147, 174, 108, 4, 22, 14, 129, 168, 6,
    80, 246, 254, 100, 218, 131, 94, 49, 247, 211, 3, 245, 22, 200, 177, 91, 60, 144, 147, 174, 90,
    17, 19, 189, 62, 147, 152, 18, 41, 139, 183, 208, 246, 198, 118, 127, 89, 160, 9, 27, 61, 26,
    123, 180, 221, 108, 17, 166, 47, 115, 82, 48, 132, 139, 253, 65, 152, 92, 209, 53, 37, 25, 83,
    61, 252, 42, 181, 243, 16, 21, 2, 199, 123, 96, 218, 151, 253, 86, 69, 181, 202, 109, 64, 129,
    124, 254, 192, 25, 177, 199, 26, 50,
];

fn main() -> Result<()> {
    println!("tidex6 Day-1 Validation Checklist");
    println!("=================================");
    println!();

    let payer = load_default_keypair().context("failed to load Solana keypair")?;
    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    let program_id = tidex6_verifier::ID;

    println!("cluster       : {}", cluster.url());
    println!("payer         : {}", payer.pubkey());
    println!("program id    : {program_id}");
    println!();

    let payer_handle = Rc::new(clone_keypair(&payer));
    let client = Client::new_with_options(cluster, payer_handle, CommitmentConfig::confirmed());
    let program = client
        .program(program_id)
        .context("failed to construct Anchor program handle")?;

    run_gate_1_poseidon(&program, &payer).context("Gate 1 (Poseidon equivalence) failed")?;
    println!();
    run_gate_2_groth16(&program, &payer)
        .context("Gate 2 (Groth16 verification) / Gate 3 (alt_bn128) failed")?;
    println!();

    let caller_program = client
        .program(tidex6_caller::ID)
        .context("failed to construct Anchor program handle for tidex6-caller")?;
    run_gate_4_cpi(&caller_program, &payer)
        .context("Gate 4 (Anchor 1.0 CPI with proof data) failed")?;
    println!();

    println!("=================================");
    println!("Day-1 Validation Checklist — Gates 1, 2, 3, 4: ALL PASSED on live devnet");
    println!("=================================");

    Ok(())
}

/// Gate 1: offchain Poseidon via `tidex6_core::poseidon::hash_pair`
/// must match the onchain `sol_poseidon` syscall byte-for-byte on the
/// canonical two-input test vector.
fn run_gate_1_poseidon<C>(program: &anchor_client::Program<C>, payer: &Keypair) -> Result<()>
where
    C: std::ops::Deref<Target = Keypair> + Clone,
{
    println!("--- Gate 1: Poseidon equivalence ---");

    let left = [1u8; 32];
    let right = [2u8; 32];

    let offchain = poseidon::hash_pair(&left, &right)
        .context("offchain Poseidon hash failed — Gate 1 cannot proceed")?;
    println!("offchain hash : {}", hex::encode(offchain));

    let signature = program
        .request()
        .accounts(verifier_accounts::HashPoseidon {
            payer: payer.pubkey(),
        })
        .args(verifier_instruction::HashPoseidon {
            inputs: vec![left, right],
        })
        .signer(payer)
        .send()
        .context("hash_poseidon transaction failed to confirm")?;
    println!("signature     : {signature}");

    let logs = fetch_transaction_logs(program, &signature)?;
    let onchain = parse_poseidon_result(&logs)?;
    println!("onchain hash  : {}", hex::encode(onchain));

    if offchain != onchain {
        return Err(anyhow!(
            "Gate 1 FAIL: offchain {} != onchain {}",
            hex::encode(offchain),
            hex::encode(onchain),
        ));
    }

    println!("Gate 1 PASS");
    Ok(())
}

/// Gate 2: the onchain `groth16-solana` verifier accepts a known-good
/// Groth16 proof. Gate 3 (`alt_bn128` syscall availability) is
/// implicitly validated because a successful Groth16 verification
/// requires `alt_bn128_addition`, `alt_bn128_multiplication`, and
/// `alt_bn128_pairing` syscalls.
fn run_gate_2_groth16<C>(program: &anchor_client::Program<C>, payer: &Keypair) -> Result<()>
where
    C: std::ops::Deref<Target = Keypair> + Clone,
{
    println!("--- Gate 2 + 3: Groth16 verification (onchain alt_bn128 syscalls) ---");

    let proof_a = negate_g1_proof_component(&RAW_PROOF[0..64].try_into()?)?;
    let proof_b: [u8; 128] = RAW_PROOF[64..192]
        .try_into()
        .context("proof_b slice must be exactly 128 bytes")?;
    let proof_c: [u8; 64] = RAW_PROOF[192..256]
        .try_into()
        .context("proof_c slice must be exactly 64 bytes")?;

    println!("proof_a (neg) : {}", hex::encode(proof_a));
    println!("proof_b       : {}", hex::encode(proof_b));
    println!("proof_c       : {}", hex::encode(proof_c));

    let signature = program
        .request()
        .accounts(verifier_accounts::VerifyTestProof {
            payer: payer.pubkey(),
        })
        .args(verifier_instruction::VerifyTestProof {
            proof_a,
            proof_b,
            proof_c,
        })
        .signer(payer)
        .send()
        .context("verify_test_proof transaction failed to confirm")?;
    println!("signature     : {signature}");

    let logs = fetch_transaction_logs(program, &signature)?;

    let groth16_valid = logs.iter().any(|line| line == GROTH16_VALID_LINE);
    let alt_bn128_ok = logs.iter().any(|line| line == ALT_BN128_OK_LINE);

    if !groth16_valid {
        return Err(anyhow!(
            "Gate 2 FAIL: no `tidex6-day1-groth16:VALID` line in transaction logs:\n{}",
            logs.join("\n")
        ));
    }
    if !alt_bn128_ok {
        return Err(anyhow!(
            "Gate 3 FAIL: no `tidex6-day1-alt_bn128:OK` line despite groth16 success"
        ));
    }

    println!("Gate 2 PASS (Groth16 verifier accepted the canonical proof)");
    println!("Gate 3 PASS (alt_bn128 syscalls are live on the target cluster)");
    Ok(())
}

/// Gate 4: a second Anchor 1.0 program (`tidex6-caller`) forwards the
/// Groth16 proof to `tidex6-verifier::verify_test_proof` via CPI. A
/// successful CPI plus a downstream verification plus a
/// `tidex6-day1-cpi:OK` log line closes the gate.
fn run_gate_4_cpi<C>(program: &anchor_client::Program<C>, payer: &Keypair) -> Result<()>
where
    C: std::ops::Deref<Target = Keypair> + Clone,
{
    println!("--- Gate 4: Anchor 1.0 CPI with proof data ---");

    let proof_a = negate_g1_proof_component(&RAW_PROOF[0..64].try_into()?)?;
    let proof_b: [u8; 128] = RAW_PROOF[64..192]
        .try_into()
        .context("proof_b slice must be exactly 128 bytes")?;
    let proof_c: [u8; 64] = RAW_PROOF[192..256]
        .try_into()
        .context("proof_c slice must be exactly 64 bytes")?;

    let signature = program
        .request()
        .accounts(caller_accounts::ForwardVerify {
            payer: payer.pubkey(),
            tidex6_verifier_program: tidex6_verifier::ID,
        })
        .args(caller_instruction::ForwardVerify {
            proof_a,
            proof_b,
            proof_c,
        })
        .signer(payer)
        .send()
        .context("forward_verify CPI transaction failed to confirm")?;
    println!("signature     : {signature}");

    let logs = fetch_transaction_logs(program, &signature)?;

    let cpi_ok = logs.iter().any(|line| line == CPI_OK_LINE);
    let downstream_valid = logs.iter().any(|line| line == GROTH16_VALID_LINE);

    if !downstream_valid {
        return Err(anyhow!(
            "Gate 4 FAIL: downstream verify_test_proof did not log VALID via CPI:\n{}",
            logs.join("\n")
        ));
    }
    if !cpi_ok {
        return Err(anyhow!(
            "Gate 4 FAIL: tidex6-caller did not log `tidex6-day1-cpi:OK`"
        ));
    }

    println!("Gate 4 PASS (tidex6-caller CPI-ed into tidex6-verifier with proof data)");
    Ok(())
}

/// Negate the G1 point encoded in the first 64 bytes of a `groth16-
/// solana`-formatted proof.
///
/// The `groth16-solana` verifier expects `proof_a` to be pre-negated
/// because it checks the pairing equation in the form
/// `e(-A, B) · e(α, β) · e(L, γ) · e(C, δ) == 1`. The negation lives
/// offchain so that the onchain program does not need to link against
/// `ark-bn254`.
fn negate_g1_proof_component(bytes: &[u8; 64]) -> Result<[u8; 64]> {
    use std::ops::Neg;

    // groth16-solana stores G1 in big-endian. arkworks expects
    // little-endian for deserialization. Reverse each 32-byte half.
    let mut le = [0u8; 64];
    reverse_bytes_halves(bytes, &mut le);

    let point = G1::deserialize_with_mode(&le[..], Compress::No, Validate::Yes).map_err(|err| {
        anyhow!("failed to deserialize proof_a as a BN254 G1 affine point: {err}")
    })?;

    let negated = point.neg();

    let mut negated_le = [0u8; 64];
    negated
        .serialize_with_mode(&mut negated_le[..], Compress::No)
        .map_err(|err| anyhow!("failed to serialize negated proof_a in little-endian: {err}"))?;

    let mut negated_be = [0u8; 64];
    reverse_bytes_halves(&negated_le, &mut negated_be);
    Ok(negated_be)
}

/// Swap big-endian ↔ little-endian on a 64-byte G1 point encoded as
/// two 32-byte field elements `(x, y)`.
fn reverse_bytes_halves(source: &[u8; 64], destination: &mut [u8; 64]) {
    for half in 0..2 {
        let start = half * 32;
        for i in 0..32 {
            destination[start + i] = source[start + 31 - i];
        }
    }
}

/// Fetches the given transaction and returns its program log messages.
fn fetch_transaction_logs<C>(
    program: &anchor_client::Program<C>,
    signature: &Signature,
) -> Result<Vec<String>>
where
    C: std::ops::Deref<Target = Keypair> + Clone,
{
    let rpc = program.rpc();
    let transaction_config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };

    let transaction = rpc
        .get_transaction_with_config(signature, transaction_config)
        .context("get_transaction_with_config RPC call failed")?;

    transaction
        .transaction
        .meta
        .as_ref()
        .ok_or_else(|| anyhow!("transaction meta is missing"))
        .and_then(|meta| match &meta.log_messages {
            OptionSerializer::Some(logs) => Ok(logs.clone()),
            _ => Err(anyhow!("transaction meta has no log messages")),
        })
}

/// Extract the onchain Poseidon hash from the `hash_poseidon`
/// instruction's log output.
fn parse_poseidon_result(logs: &[String]) -> Result<[u8; 32]> {
    let hex_hash = logs
        .iter()
        .find_map(|line| line.strip_prefix(POSEIDON_LOG_PREFIX))
        .ok_or_else(|| {
            anyhow!(
                "log line starting with `{POSEIDON_LOG_PREFIX}` not found:\n{}",
                logs.join("\n")
            )
        })?;

    let decoded =
        hex::decode(hex_hash.trim()).context("failed to decode onchain hex hash into bytes")?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("onchain hash length is not 32 bytes"))
}

/// Loads the default Solana keypair from `~/.config/solana/id.json`.
fn load_default_keypair() -> Result<Keypair> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/id.json");
    read_keypair_file(&path).map_err(|err| anyhow!("failed to read keypair from {path}: {err}"))
}

/// Clones a `Keypair` by round-tripping through its byte representation.
/// `Keypair` intentionally omits `Clone` to discourage accidental key
/// duplication in production code; the Day-1 harness is a local
/// validation tool, not production.
fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::try_from(keypair.to_bytes().as_slice())
        .expect("round-tripping a Keypair through its byte form is infallible")
}

/// Reads the cluster URL from `~/.config/solana/cli/config.yml`,
/// falling back to devnet when the config is missing or unparseable.
fn detect_cluster() -> Result<Cluster> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/cli/config.yml");

    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Ok(Cluster::Devnet);
    };

    let url = contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("json_rpc_url:"))
        .map(|value| value.trim().trim_matches('"').to_string());

    match url.as_deref() {
        Some(u) if u.contains("devnet") => Ok(Cluster::Devnet),
        Some(u) if u.contains("mainnet") => Ok(Cluster::Mainnet),
        Some(u) if u.contains("testnet") => Ok(Cluster::Testnet),
        Some(u) if u.starts_with("http") => Ok(Cluster::Custom(u.to_string(), u.to_string())),
        _ => Ok(Cluster::Devnet),
    }
}
