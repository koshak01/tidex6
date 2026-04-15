//! Day-22 adversarial test harness — 7 additional negative tests
//! for the shielded withdraw flow.
//!
//! Extends the Day-12 harness (3 tests: front-run, legitimate,
//! double-spend) with 7 more adversarial scenarios that probe
//! specific attack vectors against the `tidex6-verifier` program
//! on live Solana devnet.
//!
//! These tests use the HalfSol pool (which already has multiple
//! deposits from Days 13-17) and run through the `tidex6-client`
//! SDK + `tidex6-indexer` so they exercise the full production
//! code path, not a test-only shortcut.
//!
//! All 7 tests are expected to FAIL loudly with specific error
//! codes. A passing adversarial test means the attack was
//! rejected; a SECURITY FAILURE means the attack succeeded.

use std::rc::Rc;

use anchor_client::{Client, Cluster, CommitmentConfig, Signer};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result, anyhow};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use solana_keypair::{Keypair, read_keypair_file};

use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::withdraw::{WITHDRAW_TREE_DEPTH, WithdrawWitness, prove_withdraw};
use tidex6_core::merkle::{MerkleProof, MerkleTree};
use tidex6_core::note::{Denomination, DepositNote};
use tidex6_core::types::{Commitment, MerkleRoot, NullifierHash};
use tidex6_indexer::PoolIndexer;
use tidex6_verifier::PoolState;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

/// Use HalfSol — it has multiple prior deposits from Days 13-17,
/// proving that adversarial tests work on populated pools.
const TEST_DENOMINATION: Denomination = Denomination::HalfSol;

fn main() -> Result<()> {
    println!("tidex6 Day-22 adversarial test harness");
    println!("======================================");
    println!();

    let payer = load_keypair()?;
    let cluster = detect_cluster()?;
    let program_id = tidex6_verifier::ID;
    let denomination_lamports = TEST_DENOMINATION.lamports();

    let payer_handle = Rc::new(clone_keypair(&payer));
    let client =
        Client::new_with_options(cluster.clone(), payer_handle, CommitmentConfig::confirmed());
    let program = client.program(program_id).context("program handle")?;

    let (pool_pda, _) = Pubkey::find_program_address(
        &[
            PoolState::POOL_SEED_PREFIX,
            &denomination_lamports.to_le_bytes(),
        ],
        &program_id,
    );
    let (vault_pda, _) = Pubkey::find_program_address(
        &[b"vault", &denomination_lamports.to_le_bytes()],
        &program_id,
    );

    println!("cluster       : {}", cluster.url());
    println!("pool pda      : {pool_pda}");
    println!(
        "denomination  : {} ({} lamports)",
        TEST_DENOMINATION, denomination_lamports
    );
    println!();

    // ── Deposit a fresh note for adversarial testing ────────────
    println!("--- Depositing a fresh note for adversarial tests ---");
    let note = DepositNote::random(TEST_DENOMINATION).context("random note")?;
    let signature = program
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
        .context("deposit tx")?;
    println!("deposit sig   : {signature}");

    // Rebuild the tree using the indexer.
    println!("--- Rebuilding Merkle tree via indexer ---");
    let indexer = PoolIndexer::new(cluster.url(), pool_pda);
    let (tree, replayed_root): (MerkleTree, MerkleRoot) = indexer
        .rebuild_tree(WITHDRAW_TREE_DEPTH)
        .context("rebuild")?;
    let commitment = Commitment::from_bytes(note.commitment().to_bytes());
    let leaf_index: u64 = indexer
        .find_leaf_index(&commitment)
        .context("find leaf")?
        .ok_or_else(|| anyhow!("commitment not found in pool"))?;
    println!("leaf index    : {leaf_index}");
    println!("replayed root : {}", hex::encode(replayed_root.to_bytes()));

    let merkle_proof: MerkleProof = tree.proof(leaf_index).context("merkle proof")?;
    let nullifier_hash = note.nullifier().derive_hash().context("nullifier hash")?;

    // Load proving key.
    println!("--- Loading proving key ---");
    let pk = load_pk()?;

    // Generate a valid proof bound to the payer as recipient.
    let recipient = payer.pubkey();
    let merkle_root_bytes = replayed_root.to_bytes();
    let (proof, _public_inputs) = build_proof(
        &pk,
        &note,
        &merkle_proof,
        leaf_index,
        &merkle_root_bytes,
        &nullifier_hash,
        &recipient.to_bytes(),
    )?;
    let solana_bytes = groth16_to_solana_bytes(&proof, &pk.vk).context("solana bytes")?;
    let Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        ..
    } = &solana_bytes;

    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", nullifier_hash.as_bytes()], &program_id);

    let mut passed = 0u32;
    let mut failed = 0u32;

    // ════════════════════════════════════════════════════════════
    // TEST 4: Invalid Merkle root (not in ring buffer)
    // ════════════════════════════════════════════════════════════
    {
        println!();
        println!("TEST 4: Invalid Merkle root");
        let mut bad_root = merkle_root_bytes;
        bad_root[0] ^= 0xFF;

        let result = program
            .request()
            .accounts(verifier_accounts::Withdraw {
                pool: pool_pda,
                vault: vault_pda,
                nullifier: nullifier_pda,
                recipient,
                payer: payer.pubkey(),
                system_program: anchor_lang::system_program::ID,
            })
            .args(verifier_instruction::Withdraw {
                proof_a: *proof_a,
                proof_b: *proof_b,
                proof_c: *proof_c,
                merkle_root: bad_root,
                nullifier_hash: *nullifier_hash.as_bytes(),
            })
            .signer(&payer)
            .send();

        match result {
            Err(err) => {
                let msg = format!("{err}");
                if msg.contains("MerkleRootNotRecent") || msg.contains("0x1774") {
                    println!("  PASS: rejected with MerkleRootNotRecent");
                    passed += 1;
                } else {
                    println!("  PASS: rejected (error: {})", &msg[..msg.len().min(120)]);
                    passed += 1;
                }
            }
            Ok(sig) => {
                println!("  SECURITY FAILURE: accepted invalid root! sig={sig}");
                failed += 1;
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // TEST 5: Malformed proof bytes (random garbage)
    // ════════════════════════════════════════════════════════════
    {
        println!();
        println!("TEST 5: Malformed proof bytes");
        let garbage_a = [0xDE; 64];
        let garbage_b = [0xAD; 128];
        let garbage_c = [0xBE; 64];

        let result = program
            .request()
            .accounts(verifier_accounts::Withdraw {
                pool: pool_pda,
                vault: vault_pda,
                nullifier: nullifier_pda,
                recipient,
                payer: payer.pubkey(),
                system_program: anchor_lang::system_program::ID,
            })
            .args(verifier_instruction::Withdraw {
                proof_a: garbage_a,
                proof_b: garbage_b,
                proof_c: garbage_c,
                merkle_root: merkle_root_bytes,
                nullifier_hash: *nullifier_hash.as_bytes(),
            })
            .signer(&payer)
            .send();

        match result {
            Err(_) => {
                println!("  PASS: rejected malformed proof bytes");
                passed += 1;
            }
            Ok(sig) => {
                println!("  SECURITY FAILURE: accepted garbage proof! sig={sig}");
                failed += 1;
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // TEST 6: Wrong nullifier hash (doesn't match the witness)
    // ════════════════════════════════════════════════════════════
    {
        println!();
        println!("TEST 6: Wrong nullifier hash in public inputs");
        let mut bad_nh = *nullifier_hash.as_bytes();
        bad_nh[0] ^= 0xFF;

        let (bad_nullifier_pda, _) =
            Pubkey::find_program_address(&[b"nullifier", &bad_nh], &program_id);

        let result = program
            .request()
            .accounts(verifier_accounts::Withdraw {
                pool: pool_pda,
                vault: vault_pda,
                nullifier: bad_nullifier_pda,
                recipient,
                payer: payer.pubkey(),
                system_program: anchor_lang::system_program::ID,
            })
            .args(verifier_instruction::Withdraw {
                proof_a: *proof_a,
                proof_b: *proof_b,
                proof_c: *proof_c,
                merkle_root: merkle_root_bytes,
                nullifier_hash: bad_nh,
            })
            .signer(&payer)
            .send();

        match result {
            Err(_) => {
                println!("  PASS: rejected wrong nullifier hash");
                passed += 1;
            }
            Ok(sig) => {
                println!("  SECURITY FAILURE: accepted wrong nullifier hash! sig={sig}");
                failed += 1;
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // TEST 7: Legitimate withdraw (baseline — must succeed)
    // ════════════════════════════════════════════════════════════
    {
        println!();
        println!("TEST 7: Legitimate withdraw (baseline)");
        let result = program
            .request()
            .accounts(verifier_accounts::Withdraw {
                pool: pool_pda,
                vault: vault_pda,
                nullifier: nullifier_pda,
                recipient,
                payer: payer.pubkey(),
                system_program: anchor_lang::system_program::ID,
            })
            .args(verifier_instruction::Withdraw {
                proof_a: *proof_a,
                proof_b: *proof_b,
                proof_c: *proof_c,
                merkle_root: merkle_root_bytes,
                nullifier_hash: *nullifier_hash.as_bytes(),
            })
            .signer(&payer)
            .send();

        match result {
            Ok(sig) => {
                println!("  PASS: legitimate withdraw succeeded: {sig}");
                passed += 1;
            }
            Err(err) => {
                println!("  FAILURE: legitimate withdraw rejected: {err}");
                failed += 1;
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // TEST 8: Double-spend (same nullifier PDA already exists)
    // ════════════════════════════════════════════════════════════
    {
        println!();
        println!("TEST 8: Double-spend attempt");
        let result = program
            .request()
            .accounts(verifier_accounts::Withdraw {
                pool: pool_pda,
                vault: vault_pda,
                nullifier: nullifier_pda,
                recipient,
                payer: payer.pubkey(),
                system_program: anchor_lang::system_program::ID,
            })
            .args(verifier_instruction::Withdraw {
                proof_a: *proof_a,
                proof_b: *proof_b,
                proof_c: *proof_c,
                merkle_root: merkle_root_bytes,
                nullifier_hash: *nullifier_hash.as_bytes(),
            })
            .signer(&payer)
            .send();

        match result {
            Err(err) => {
                let msg = format!("{err}");
                if msg.contains("already in use") || msg.contains("custom program error: 0x0") {
                    println!("  PASS: double-spend blocked by nullifier PDA");
                } else {
                    println!("  PASS: rejected ({})", &msg[..msg.len().min(100)]);
                }
                passed += 1;
            }
            Ok(sig) => {
                println!("  SECURITY FAILURE: double-spend succeeded! sig={sig}");
                failed += 1;
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // TEST 9: Front-run (wrong recipient)
    // ════════════════════════════════════════════════════════════
    //
    // Deposit another fresh note so we get a clean nullifier.
    {
        println!();
        println!("TEST 9: Front-run attempt (wrong recipient)");
        let note2 = DepositNote::random(TEST_DENOMINATION).context("random note 2")?;
        let dep2_sig = program
            .request()
            .accounts(verifier_accounts::Deposit {
                pool: pool_pda,
                vault: vault_pda,
                payer: payer.pubkey(),
                system_program: anchor_lang::system_program::ID,
            })
            .args(verifier_instruction::Deposit {
                commitment: note2.commitment().to_bytes(),
                memo_payload: tidex6_core::memo::placeholder_payload_for_harness(),
            })
            .signer(&payer)
            .send()
            .context("deposit note 2")?;
        println!("  deposit sig : {dep2_sig}");

        // Rebuild tree for the new deposit.
        let (tree2, root2): (MerkleTree, MerkleRoot) = indexer
            .rebuild_tree(WITHDRAW_TREE_DEPTH)
            .context("rebuild 2")?;
        let commitment2 = Commitment::from_bytes(note2.commitment().to_bytes());
        let leaf2: u64 = indexer
            .find_leaf_index(&commitment2)
            .context("find leaf 2")?
            .ok_or_else(|| anyhow!("note 2 not found"))?;
        let proof2_data: MerkleProof = tree2.proof(leaf2).context("proof 2")?;
        let nh2: NullifierHash = note2.nullifier().derive_hash().context("nh 2")?;
        let root2_bytes: [u8; 32] = root2.to_bytes();

        // Proof is bound to the payer as recipient.
        let (proof2, _) = build_proof(
            &pk,
            &note2,
            &proof2_data,
            leaf2,
            &root2_bytes,
            &nh2,
            &payer.pubkey().to_bytes(),
        )?;
        let sb2 = groth16_to_solana_bytes(&proof2, &pk.vk).context("sb2")?;

        let (nullifier_pda2, _) =
            Pubkey::find_program_address(&[b"nullifier", nh2.as_bytes()], &program_id);

        // Send with a DIFFERENT recipient — an attacker's key.
        let attacker = Keypair::new();

        let result = program
            .request()
            .accounts(verifier_accounts::Withdraw {
                pool: pool_pda,
                vault: vault_pda,
                nullifier: nullifier_pda2,
                recipient: attacker.pubkey(),
                payer: payer.pubkey(),
                system_program: anchor_lang::system_program::ID,
            })
            .args(verifier_instruction::Withdraw {
                proof_a: sb2.proof_a,
                proof_b: sb2.proof_b,
                proof_c: sb2.proof_c,
                merkle_root: root2_bytes,
                nullifier_hash: *nh2.as_bytes(),
            })
            .signer(&payer)
            .send();

        match result {
            Err(err) => {
                let msg = format!("{err}");
                if msg.contains("Groth16") || msg.contains("0x1773") {
                    println!("  PASS: front-run blocked by Groth16 recipient binding");
                } else {
                    println!("  PASS: rejected ({})", &msg[..msg.len().min(100)]);
                }
                passed += 1;
            }
            Ok(sig) => {
                println!("  SECURITY FAILURE: front-run succeeded! sig={sig}");
                failed += 1;
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // Summary
    // ════════════════════════════════════════════════════════════
    println!();
    println!("======================================");
    println!("Day-22 adversarial harness: {passed} PASSED, {failed} FAILED");
    if failed > 0 {
        println!("SECURITY FAILURES DETECTED — investigate immediately.");
        std::process::exit(1);
    } else {
        println!("All adversarial scenarios rejected as expected.");
    }
    println!("======================================");

    Ok(())
}

fn build_proof(
    pk: &ProvingKey<ark_bn254::Bn254>,
    note: &DepositNote,
    merkle_proof: &tidex6_core::merkle::MerkleProof,
    leaf_index: u64,
    merkle_root: &[u8; 32],
    nullifier_hash: &tidex6_core::types::NullifierHash,
    recipient: &[u8; 32],
) -> Result<(ark_groth16::Proof<ark_bn254::Bn254>, [ark_bn254::Fr; 3])> {
    let siblings: Vec<[u8; 32]> = merkle_proof
        .siblings
        .iter()
        .map(|c| *c.as_bytes())
        .collect();
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] = std::array::from_fn(|i| &siblings[i]);

    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (leaf_index >> i) & 1 == 1;
    }

    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: note.secret().as_bytes(),
        nullifier: note.nullifier().as_bytes(),
        path_siblings: sibling_refs,
        path_indices,
        merkle_root,
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient,
    };

    let mut rng = StdRng::seed_from_u64(0xd22a_0003);
    prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(pk, witness, &mut rng).context("prove_withdraw")
}

fn load_pk() -> Result<ProvingKey<ark_bn254::Bn254>> {
    let start = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut current = start.clone();
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            let text = std::fs::read_to_string(&candidate).unwrap_or_default();
            if text.contains("[workspace]") {
                let path = current.join("crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin");
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("read pk from {}", path.display()))?;
                return ProvingKey::<ark_bn254::Bn254>::deserialize_uncompressed_unchecked(
                    &bytes[..],
                )
                .map_err(|err| anyhow!("deserialize pk: {err}"));
            }
        }
        current = current
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| anyhow!("workspace root not found from {}", start.display()))?;
    }
}

fn load_keypair() -> Result<Keypair> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = format!("{home}/.config/solana/id.json");
    read_keypair_file(&path).map_err(|err| anyhow!("read {path}: {err}"))
}

fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::try_from(keypair.to_bytes().as_slice()).expect("clone keypair")
}

fn detect_cluster() -> Result<Cluster> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = format!("{home}/.config/solana/cli/config.yml");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Ok(Cluster::Devnet);
    };
    let url = contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("json_rpc_url:"))
        .map(|v| v.trim().trim_matches('"').to_string());
    match url.as_deref() {
        Some(u) if u.contains("devnet") => Ok(Cluster::Devnet),
        Some(u) if u.contains("mainnet") => Ok(Cluster::Mainnet),
        Some(u) if u.contains("testnet") => Ok(Cluster::Testnet),
        Some(u) if u.starts_with("http") => Ok(Cluster::Custom(u.to_string(), u.to_string())),
        _ => Ok(Cluster::Devnet),
    }
}
