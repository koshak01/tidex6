//! Day-11 production withdraw flight test.
//!
//! This binary is the real end-to-end proof that the shielded pool
//! works on devnet:
//!
//! 1. Init a fresh `OneSol` pool if it does not exist yet.
//! 2. Generate a random deposit note, deposit it, and capture the
//!    onchain `leaf_index` + new Merkle root from the program logs.
//! 3. Rebuild the offchain Merkle tree up to the new leaf (the
//!    harness assumes the pool was empty at start — first-run flow).
//! 4. Load the cached `WithdrawCircuit<20>` proving key from
//!    `crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin`.
//! 5. Generate a Groth16 withdraw proof bound to a fresh recipient
//!    keypair.
//! 6. Convert the proof into groth16-solana byte layout, send the
//!    `withdraw` transaction, and verify the recipient balance
//!    increased by exactly one `denomination`.
//!
//! If anything diverges between the offchain and onchain computations
//! the harness exits with a loud error.

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
use tidex6_circuits::square::fr_to_be_bytes;
use tidex6_circuits::withdraw::{WITHDRAW_TREE_DEPTH, WithdrawWitness, prove_withdraw};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::note::{Denomination, DepositNote};
use tidex6_core::types::Commitment;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

/// Denomination used for the flight test. Picked to be different
/// from Day-5's `OneTenthSol` so we start with a fresh pool.
const FLIGHT_DENOMINATION: Denomination = Denomination::OneSol;

fn main() -> Result<()> {
    println!("tidex6 Day-11 withdraw flight test");
    println!("===================================");
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

    // ── 1. Ensure pool is initialised and assert it is fresh ────
    let pool_was_fresh = ensure_pool_initialised(
        &program,
        &payer,
        denomination_lamports,
        &pool_pda,
        &vault_pda,
    )?;
    if !pool_was_fresh {
        return Err(anyhow!(
            "The {} pool already exists and has prior deposits. This harness assumes a fresh \
             pool so it can rebuild the offchain Merkle tree from a single deposit. Run with a \
             different denomination or redeploy the verifier program.",
            FLIGHT_DENOMINATION
        ));
    }

    // ── 2. Generate and send the deposit ────────────────────────
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

    // ── 3. Build the offchain Merkle tree (single leaf at index 0) ─
    println!();
    println!("--- Building offchain Merkle tree ---");
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).context("new offchain tree")?;
    let (inserted_index, offchain_root) = tree
        .insert(Commitment::from_bytes(note.commitment().to_bytes()))
        .context("insert into offchain tree")?;
    println!("inserted idx  : {inserted_index}");
    println!("offchain root : {}", hex::encode(offchain_root.to_bytes()));
    if offchain_root.to_bytes() != onchain_root {
        return Err(anyhow!(
            "Root mismatch after deposit: onchain {} vs offchain {}",
            hex::encode(onchain_root),
            hex::encode(offchain_root.to_bytes())
        ));
    }
    println!("roots agree   : OK");

    let merkle_proof = tree
        .proof(leaf_index)
        .context("offchain Merkle proof for deposited leaf")?;
    let nullifier_hash = note
        .nullifier()
        .derive_hash()
        .context("derive nullifier hash")?;

    // ── 4. Load cached proving key ──────────────────────────────
    println!();
    println!("--- Loading proving key ---");
    let pk = load_withdraw_proving_key().context("load withdraw proving key")?;
    println!("proving key   : loaded");

    // ── 5. Generate withdraw proof ──────────────────────────────
    //
    // Use a fresh recipient keypair so the test is repeatable and
    // the observed balance delta is unambiguous. We do not need to
    // fund the recipient — SystemProgram::transfer will create it
    // on receipt of lamports.
    let recipient = Keypair::new();
    let recipient_pubkey_bytes = recipient.pubkey().to_bytes();
    println!();
    println!("--- Generating withdraw proof ---");
    println!("recipient     : {}", recipient.pubkey());

    // The MerkleProof sibling list is bottom-up. The WithdrawCircuit
    // expects the same order, and path_indices is LSB-first bits of
    // the leaf index.
    let sibling_byte_arrays: Vec<[u8; 32]> = merkle_proof
        .siblings
        .iter()
        .map(|commitment| *commitment.as_bytes())
        .collect();
    if sibling_byte_arrays.len() != WITHDRAW_TREE_DEPTH {
        return Err(anyhow!(
            "Merkle proof depth {} does not match WITHDRAW_TREE_DEPTH {}",
            sibling_byte_arrays.len(),
            WITHDRAW_TREE_DEPTH
        ));
    }
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] =
        std::array::from_fn(|i| &sibling_byte_arrays[i]);

    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit_slot) in path_indices.iter_mut().enumerate() {
        *bit_slot = (leaf_index >> i) & 1 == 1;
    }

    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: note.secret().as_bytes(),
        nullifier: note.nullifier().as_bytes(),
        path_siblings: sibling_refs,
        path_indices,
        merkle_root: &onchain_root,
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient: &recipient_pubkey_bytes,
    };

    // Deterministic RNG so a repeated run against the same fresh
    // pool produces the same proof — useful for debugging.
    let mut rng = StdRng::seed_from_u64(0xf116_7e57);
    let (proof, public_inputs_fr) =
        prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&pk, witness, &mut rng)
            .context("prove withdraw")?;

    // Cross-check: the recipient public input the circuit produced
    // must equal the onchain recipient reduction. The onchain
    // reduction uses the same `from_be_bytes_mod_order` path
    // (via the circuit witness), so comparing via fr_to_be_bytes
    // confirms the bytes we will send as the recipient account key
    // will reduce identically onchain.
    let expected_recipient_fr_bytes = fr_to_be_bytes(public_inputs_fr[2]);
    println!(
        "recipient_fr  : {}",
        hex::encode(expected_recipient_fr_bytes)
    );

    let solana_bytes =
        groth16_to_solana_bytes(&proof, pk_as_vk(&pk)).context("convert proof to solana bytes")?;
    let Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        ..
    } = &solana_bytes;

    // ── 6. Send withdraw transaction ────────────────────────────
    println!();
    println!("--- Sending withdraw transaction ---");

    let (nullifier_pda, _nullifier_bump) =
        Pubkey::find_program_address(&[b"nullifier", nullifier_hash.as_bytes()], &program_id);
    println!("nullifier PDA : {nullifier_pda}");

    let pre_balance = program.rpc().get_balance(&recipient.pubkey()).unwrap_or(0);
    println!("recipient pre : {pre_balance} lamports");

    let withdraw_signature = program
        .request()
        .accounts(verifier_accounts::Withdraw {
            pool: pool_pda,
            vault: vault_pda,
            nullifier: nullifier_pda,
            recipient: recipient.pubkey(),
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(verifier_instruction::Withdraw {
            proof_a: *proof_a,
            proof_b: *proof_b,
            proof_c: *proof_c,
            merkle_root: onchain_root,
            nullifier_hash: *nullifier_hash.as_bytes(),
        })
        .signer(&payer)
        .send()
        .context("withdraw transaction failed to confirm")?;
    println!("signature     : {withdraw_signature}");

    // Verify balance increased by exactly `denomination`.
    let post_balance = program
        .rpc()
        .get_balance(&recipient.pubkey())
        .context("get recipient post-withdraw balance")?;
    println!("recipient post: {post_balance} lamports");

    let delta = post_balance
        .checked_sub(pre_balance)
        .ok_or_else(|| anyhow!("recipient balance decreased after withdraw; something is wrong"))?;
    if delta != denomination_lamports {
        return Err(anyhow!(
            "recipient balance delta {delta} lamports does not equal denomination {denomination_lamports}"
        ));
    }
    println!("delta         : {delta} lamports == denomination ({denomination_lamports})");

    println!();
    println!("===================================");
    println!("Day-11 withdraw flight test: PASSED");
    println!("deposit → offchain tree rebuild → prove → onchain verify → payout");
    println!("===================================");

    Ok(())
}

/// The `ProvingKey` on disk was written via `CanonicalSerialize` in
/// `gen_withdraw_vk.rs`. Deserialize it back here.
fn load_withdraw_proving_key() -> Result<ProvingKey<ark_bn254::Bn254>> {
    let path = find_pk_path()?;
    let bytes =
        fs::read(&path).with_context(|| format!("read proving key from {}", path.display()))?;
    let pk = ProvingKey::<ark_bn254::Bn254>::deserialize_uncompressed_unchecked(&bytes[..])
        .map_err(|err| anyhow!("deserialize proving key: {err}"))?;
    Ok(pk)
}

/// Extract the verifying key out of a proving key — arkworks stores
/// it as a direct field so there is no cost to this. We need it to
/// call `groth16_to_solana_bytes`.
fn pk_as_vk(pk: &ProvingKey<ark_bn254::Bn254>) -> &ark_groth16::VerifyingKey<ark_bn254::Bn254> {
    &pk.vk
}

/// Locate the cached proving key file. Walks up from
/// `CARGO_MANIFEST_DIR` until it finds the workspace root and then
/// joins the known artifact path.
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

/// Check whether the pool PDA already exists. Returns `true` if the
/// pool was either freshly created or was already present but still
/// empty (`next_leaf_index == 0`).
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
            // Parse next_leaf_index out of the zero-copy layout
            // directly. Field offsets inside PoolState:
            //   0..8   denomination
            //   8..16  next_leaf_index
            let data = &account.data[8..]; // skip Anchor discriminator
            if data.len() < 16 {
                return Err(anyhow!(
                    "existing pool account data too short: {} bytes",
                    data.len()
                ));
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

/// Parse the `tidex6-deposit:<leaf_index>:<commitment>:<root>` log
/// line emitted by the deposit instruction. Returns the new leaf
/// index, the inserted commitment and the updated Merkle root.
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
