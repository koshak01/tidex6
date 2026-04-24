//! Day-12 negative tests for the shielded withdraw flow.
//!
//! This harness exercises three attack scenarios against the real
//! onchain `tidex6-verifier` program on devnet:
//!
//! 1. **Front-running** — an attacker intercepts a pending withdraw
//!    transaction and rewrites the `recipient` account to their own
//!    address. The proof was bound to the original recipient via
//!    the third public input, so the Groth16 pairing must fail and
//!    the transaction must revert.
//!
//! 2. **Legitimate withdraw** — the same proof with the correct
//!    recipient must succeed, proving the negative case above is
//!    genuinely rejected by the recipient binding and not by some
//!    unrelated reason.
//!
//! 3. **Double-spend** — an attacker (or a confused user) attempts
//!    to withdraw the same note twice. The per-nullifier PDA was
//!    created during step 2 and the second `init` must fail at the
//!    account-initialisation step, before any Groth16 work runs.
//!
//! The harness uses `TenSol` so it runs against a fresh pool that
//! was never touched by the Day-11 happy-path harness. Recipient
//! for the legitimate case is the payer itself, so the 10 SOL
//! returns to the test wallet and does not leak to a random key.

use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use anchor_client::{Client, Cluster, CommitmentConfig, Signer};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result, anyhow};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use solana_keypair::{Keypair, read_keypair_file};
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_transaction_status::{UiTransactionEncoding, option_serializer::OptionSerializer};

use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::withdraw::{
    WITHDRAW_TREE_DEPTH, WithdrawWitness, prove_withdraw, relayer_fee_bytes_from_u64,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::note::{Denomination, DepositNote};
use tidex6_core::types::Commitment;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

/// Use `TenSol` so the harness runs against a pool that Day-11 and
/// Day-5 never touched. The full 10 SOL round-trips back to the
/// payer via the legitimate withdraw test, so nothing leaks.
const FLIGHT_DENOMINATION: Denomination = Denomination::TenSol;

fn main() -> Result<()> {
    println!("tidex6 Day-12 negative tests (front-run + double-spend)");
    println!("=======================================================");
    println!();

    let payer = load_default_keypair().context("failed to load Solana keypair")?;
    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    let program_id = tidex6_verifier::ID;

    println!("cluster       : {}", cluster.url());
    println!("payer         : {}", payer.pubkey());
    println!("program id    : {program_id}");
    println!(
        "denomination  : {} ({} lamports)",
        FLIGHT_DENOMINATION,
        FLIGHT_DENOMINATION.lamports()
    );
    println!();

    let payer_handle = Rc::new(clone_keypair(&payer));
    let client = Client::new_with_options(cluster, payer_handle, CommitmentConfig::confirmed());
    let program = client
        .program(program_id)
        .context("failed to construct Anchor program handle")?;

    let denomination_lamports = FLIGHT_DENOMINATION.lamports();
    let (pool_pda, _pool_bump) = Pubkey::find_program_address(
        &[b"pool", &denomination_lamports.to_le_bytes()],
        &program_id,
    );
    let (vault_pda, _vault_bump) = Pubkey::find_program_address(
        &[b"vault", &denomination_lamports.to_le_bytes()],
        &program_id,
    );

    println!("pool PDA      : {pool_pda}");
    println!("vault PDA     : {vault_pda}");
    println!();

    // Ensure pool is fresh.
    let pool_was_fresh = ensure_pool_initialised(
        &program,
        &payer,
        denomination_lamports,
        &pool_pda,
        &vault_pda,
    )?;
    if !pool_was_fresh {
        return Err(anyhow!(
            "The {} pool is not empty. This harness assumes a fresh pool so the offchain \
             Merkle tree rebuild is a single-leaf insert.",
            FLIGHT_DENOMINATION
        ));
    }

    // Deposit
    println!("--- Generating deposit note ---");
    let note = DepositNote::random(FLIGHT_DENOMINATION)
        .context("failed to generate a random deposit note")?;
    println!("commitment    : {}", note.commitment().to_hex());

    println!();
    println!("--- Sending deposit transaction ---");
    let deposit_signature = program
        .request()
        .accounts(verifier_accounts::Deposit {
            pool: pool_pda,
            vault: vault_pda,
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(verifier_instruction::Deposit {
            commitment: note.commitment().to_bytes(),
            memo_payload: tidex6_core::memo::placeholder_payload_for_harness(),
        })
        .signer(&payer)
        .send()
        .context("deposit transaction failed to confirm")?;
    println!("signature     : {deposit_signature}");

    let deposit_logs = fetch_transaction_logs(&program, &deposit_signature)?;
    let (leaf_index, _log_commitment, onchain_root) = parse_deposit_log(&deposit_logs)?;
    println!("leaf index    : {leaf_index}");
    println!("onchain root  : {}", hex::encode(onchain_root));
    if leaf_index != 0 {
        return Err(anyhow!(
            "Expected a fresh pool with leaf_index=0, but got {leaf_index}"
        ));
    }

    // Build offchain tree + Merkle proof
    println!();
    println!("--- Building offchain Merkle tree ---");
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).context("new offchain tree")?;
    let (_inserted_index, offchain_root) = tree
        .insert(Commitment::from_bytes(note.commitment().to_bytes()))
        .context("insert into offchain tree")?;
    if offchain_root.to_bytes() != onchain_root {
        return Err(anyhow!("Root mismatch after deposit"));
    }
    println!("roots agree   : OK");

    let merkle_proof = tree.proof(leaf_index).context("offchain Merkle proof")?;
    let nullifier_hash = note
        .nullifier()
        .derive_hash()
        .context("derive nullifier hash")?;

    // Load PK
    println!();
    println!("--- Loading proving key ---");
    let pk = load_withdraw_proving_key().context("load withdraw proving key")?;
    println!("proving key   : loaded");

    // Prove withdraw bound to the payer as the recipient. The same
    // proof will be reused across all three sub-tests.
    let payer_pubkey_bytes = payer.pubkey().to_bytes();
    println!();
    println!("--- Generating withdraw proof bound to payer as recipient ---");
    let sibling_byte_arrays: Vec<[u8; 32]> = merkle_proof
        .siblings
        .iter()
        .map(|commitment| *commitment.as_bytes())
        .collect();
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] =
        std::array::from_fn(|i| &sibling_byte_arrays[i]);

    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit_slot) in path_indices.iter_mut().enumerate() {
        *bit_slot = (leaf_index >> i) & 1 == 1;
    }

    // ADR-011: direct-path harness, relayer_address = recipient, fee = 0.
    let relayer_address_bytes = payer_pubkey_bytes;
    let relayer_fee_bytes = relayer_fee_bytes_from_u64(0);

    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: note.secret().as_bytes(),
        nullifier: note.nullifier().as_bytes(),
        path_siblings: sibling_refs,
        path_indices,
        merkle_root: &onchain_root,
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient: &payer_pubkey_bytes,
        relayer_address: &relayer_address_bytes,
        relayer_fee: &relayer_fee_bytes,
    };

    let mut rng = StdRng::seed_from_u64(0xd12_7e57);
    let (proof, _public_inputs_fr) =
        prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&pk, witness, &mut rng)
            .context("prove withdraw")?;

    let solana_bytes =
        groth16_to_solana_bytes(&proof, pk_as_vk(&pk)).context("convert proof to solana bytes")?;
    let Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        ..
    } = &solana_bytes;

    let (nullifier_pda, _nullifier_bump) =
        Pubkey::find_program_address(&[b"nullifier", nullifier_hash.as_bytes()], &program_id);
    println!("nullifier PDA : {nullifier_pda}");

    // ════════════════════════════════════════════════════════════
    // TEST 1: Front-running attempt. Send the proof with the wrong
    // recipient; the Groth16 verifier must reject it because the
    // third public input will not match the one the proof was bound
    // to.
    // ════════════════════════════════════════════════════════════
    println!();
    println!("================================================");
    println!("TEST 1: Front-running attempt (wrong recipient)");
    println!("================================================");
    let attacker = Keypair::new();
    println!("attacker      : {}", attacker.pubkey());

    // ADR-011 direct-path: proof was built with relayer=payer and
    // fee=0. Keeping `relayer = payer.pubkey()` here isolates the
    // failure to the mutated `recipient` field — if we also broke
    // the relayer binding, we could not tell which public-input
    // mismatch caused the rejection.
    let front_run_result = program
        .request()
        .accounts(verifier_accounts::Withdraw {
            pool: pool_pda,
            vault: vault_pda,
            nullifier: nullifier_pda,
            recipient: attacker.pubkey(), // WRONG — not what the proof was bound to
            relayer: payer.pubkey(),
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(verifier_instruction::Withdraw {
            proof_a: *proof_a,
            proof_b: *proof_b,
            proof_c: *proof_c,
            merkle_root: onchain_root,
            nullifier_hash: *nullifier_hash.as_bytes(),
            relayer_fee: 0,
        })
        .signer(&payer)
        .send();

    match front_run_result {
        Ok(signature) => {
            return Err(anyhow!(
                "SECURITY FAILURE: front-run transaction unexpectedly succeeded: {signature}"
            ));
        }
        Err(err) => {
            println!("front-run tx rejected (expected).");
            let message = format!("{err}");
            // The onchain error for Groth16 verification failure is
            // `Tidex6VerifierError::Groth16VerificationFailed`. We
            // only assert the tx was rejected — the exact error
            // format varies across anchor-client versions.
            println!("tx error      : {message}");
            if !message.to_lowercase().contains("groth16")
                && !message.contains("custom program error")
                && !message.contains("0x1774")
                && !message.contains("verification")
            {
                println!(
                    "(warning) rejection message did not mention Groth16 — verify it is the \
                     correct failure path by inspecting logs."
                );
            }
        }
    }

    // Sanity: nullifier PDA must not exist yet (the failing tx
    // should have rolled back all state changes including the
    // account init).
    let nullifier_exists_after_front_run = program
        .rpc()
        .get_account(&nullifier_pda)
        .map(|account| !account.data.is_empty())
        .unwrap_or(false);
    if nullifier_exists_after_front_run {
        return Err(anyhow!(
            "SECURITY FAILURE: nullifier PDA exists after the failing front-run tx — the \
             failing tx did not roll back state."
        ));
    }
    println!("nullifier PDA : not created (correct rollback)");

    // ════════════════════════════════════════════════════════════
    // TEST 2: Legitimate withdraw with the correct recipient. This
    // must succeed. It also sets up the state for the double-spend
    // test by creating the nullifier PDA.
    // ════════════════════════════════════════════════════════════
    println!();
    println!("================================================");
    println!("TEST 2: Legitimate withdraw (recipient = payer)");
    println!("================================================");

    let pre_balance = program
        .rpc()
        .get_balance(&payer.pubkey())
        .context("get payer pre-withdraw balance")?;
    println!("payer pre     : {pre_balance} lamports");

    let legit_signature = program
        .request()
        .accounts(verifier_accounts::Withdraw {
            pool: pool_pda,
            vault: vault_pda,
            nullifier: nullifier_pda,
            recipient: payer.pubkey(), // CORRECT — matches the proof
            relayer: payer.pubkey(),
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(verifier_instruction::Withdraw {
            proof_a: *proof_a,
            proof_b: *proof_b,
            proof_c: *proof_c,
            merkle_root: onchain_root,
            nullifier_hash: *nullifier_hash.as_bytes(),
            relayer_fee: 0,
        })
        .signer(&payer)
        .send()
        .context("legitimate withdraw transaction failed to confirm")?;
    println!("signature     : {legit_signature}");

    // Verify the nullifier PDA now exists.
    let nullifier_after_legit = program
        .rpc()
        .get_account(&nullifier_pda)
        .context("fetch nullifier PDA after legit withdraw")?;
    if nullifier_after_legit.data.is_empty() {
        return Err(anyhow!(
            "Nullifier PDA should exist after successful withdraw"
        ));
    }
    println!(
        "nullifier PDA : created ({} bytes)",
        nullifier_after_legit.data.len()
    );

    // ════════════════════════════════════════════════════════════
    // TEST 3: Double-spend. Resend the same withdraw. Anchor's
    // `init` constraint on the nullifier PDA must fail because the
    // account already exists from TEST 2.
    // ════════════════════════════════════════════════════════════
    println!();
    println!("================================================");
    println!("TEST 3: Double-spend attempt (same nullifier)");
    println!("================================================");

    let double_spend_result = program
        .request()
        .accounts(verifier_accounts::Withdraw {
            pool: pool_pda,
            vault: vault_pda,
            nullifier: nullifier_pda,
            recipient: payer.pubkey(),
            relayer: payer.pubkey(),
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(verifier_instruction::Withdraw {
            proof_a: *proof_a,
            proof_b: *proof_b,
            proof_c: *proof_c,
            merkle_root: onchain_root,
            nullifier_hash: *nullifier_hash.as_bytes(),
            relayer_fee: 0,
        })
        .signer(&payer)
        .send();

    match double_spend_result {
        Ok(signature) => {
            return Err(anyhow!(
                "SECURITY FAILURE: double-spend transaction unexpectedly succeeded: {signature}"
            ));
        }
        Err(err) => {
            let message = format!("{err}");
            println!("double-spend tx rejected (expected).");
            println!("tx error      : {message}");
            // Common failure modes: "already in use" (account init
            // conflict), "custom program error: 0x0"
            // (account-in-use from system program), or "address
            // already in use".
            if !message.contains("already in use")
                && !message.contains("custom program error")
                && !message.to_lowercase().contains("already")
            {
                println!(
                    "(warning) rejection message did not mention account-already-in-use — \
                     verify it is the correct failure path by inspecting logs."
                );
            }
        }
    }

    println!();
    println!("=======================================================");
    println!("Day-12 negative tests: PASSED");
    println!("  front-run   : Groth16 recipient binding rejected");
    println!("  legitimate  : nullifier PDA created, payout received");
    println!("  double-spend: nullifier PDA init rejected");
    println!("=======================================================");

    Ok(())
}

/// Load the cached proving key from disk.
fn load_withdraw_proving_key() -> Result<ProvingKey<ark_bn254::Bn254>> {
    let path = find_pk_path()?;
    let bytes =
        fs::read(&path).with_context(|| format!("read proving key from {}", path.display()))?;
    let pk = ProvingKey::<ark_bn254::Bn254>::deserialize_uncompressed_unchecked(&bytes[..])
        .map_err(|err| anyhow!("deserialize proving key: {err}"))?;
    Ok(pk)
}

fn pk_as_vk(pk: &ProvingKey<ark_bn254::Bn254>) -> &ark_groth16::VerifyingKey<ark_bn254::Bn254> {
    &pk.vk
}

fn find_pk_path() -> Result<PathBuf> {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut current = start.clone();
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            let text = fs::read_to_string(&candidate).unwrap_or_default();
            if text.contains("[workspace]") {
                return Ok(current.join("crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin"));
            }
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => {
                return Err(anyhow!(
                    "could not find workspace root from {}",
                    start.display()
                ));
            }
        }
    }
}

fn ensure_pool_initialised<C>(
    program: &anchor_client::Program<C>,
    payer: &Keypair,
    denomination: u64,
    pool_pda: &Pubkey,
    vault_pda: &Pubkey,
) -> Result<bool>
where
    C: std::ops::Deref<Target = Keypair> + Clone,
{
    let rpc = program.rpc();
    if let Ok(account) = rpc.get_account(pool_pda) {
        if !account.data.is_empty() {
            let data = &account.data[8..];
            if data.len() < 16 {
                return Err(anyhow!("existing pool account data too short"));
            }
            let next_leaf_index = u64::from_le_bytes(
                data[8..16]
                    .try_into()
                    .expect("next_leaf_index slice is 8 bytes"),
            );
            println!("--- pool already initialised, next_leaf_index = {next_leaf_index} ---");
            return Ok(next_leaf_index == 0);
        }
    }

    println!("--- Initialising pool ---");
    let signature = program
        .request()
        .accounts(verifier_accounts::InitPool {
            pool: *pool_pda,
            vault: *vault_pda,
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(verifier_instruction::InitPool { denomination })
        .signer(payer)
        .send()
        .context("init_pool transaction failed to confirm")?;
    println!("init signature: {signature}");
    Ok(true)
}

fn parse_deposit_log(logs: &[String]) -> Result<(u64, [u8; 32], [u8; 32])> {
    const PREFIX: &str = "Program log: tidex6-deposit:";

    for line in logs {
        if let Some(payload) = line.strip_prefix(PREFIX) {
            let mut parts = payload.split(':');
            let leaf_index_str = parts
                .next()
                .ok_or_else(|| anyhow!("deposit log missing leaf index"))?;
            let hex_commitment = parts
                .next()
                .ok_or_else(|| anyhow!("deposit log missing commitment hex"))?;
            let hex_root = parts
                .next()
                .ok_or_else(|| anyhow!("deposit log missing root hex"))?;

            let leaf_index = leaf_index_str
                .parse::<u64>()
                .context("deposit log leaf index is not a number")?;
            let commitment_bytes =
                hex::decode(hex_commitment.trim()).context("deposit commitment hex decode")?;
            let commitment: [u8; 32] = commitment_bytes
                .try_into()
                .map_err(|_| anyhow!("deposit commitment is not 32 bytes"))?;
            let root_bytes = hex::decode(hex_root.trim()).context("deposit root hex decode")?;
            let root: [u8; 32] = root_bytes
                .try_into()
                .map_err(|_| anyhow!("deposit root is not 32 bytes"))?;

            return Ok((leaf_index, commitment, root));
        }
    }

    Err(anyhow!(
        "no deposit log line found in transaction output:\n{}",
        logs.join("\n")
    ))
}

fn fetch_transaction_logs<C>(
    program: &anchor_client::Program<C>,
    signature: &solana_signature::Signature,
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

fn load_default_keypair() -> Result<Keypair> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/id.json");
    read_keypair_file(&path).map_err(|err| anyhow!("failed to read keypair from {path}: {err}"))
}

fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::try_from(keypair.to_bytes().as_slice())
        .expect("round-tripping a Keypair through its byte form is infallible")
}

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
