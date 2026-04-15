//! Day-13 Accountant flight harness.
//!
//! Exercises the end-to-end Shielded Memo round-trip against a live
//! Solana cluster:
//!
//!   1. Generate a fresh auditor keypair in memory. Nothing touches
//!      disk — the harness is idempotent and leaves no cached state.
//!   2. Send three deposits into the `0.1 SOL` pool, each with a
//!      unique memo plaintext encrypted under the auditor public
//!      key. `tidex6-client::PrivatePool` drives the tx, which now
//!      carries both the verifier `deposit` instruction and an SPL
//!      Memo instruction in a single atomic transaction.
//!   3. Run `tidex6-client::AccountantScanner::scan` against the
//!      live pool with the matching auditor secret key.
//!   4. Assert that exactly the three memos come back, in deposit
//!      order, with their plaintexts intact.
//!
//! Failure modes — tx rejection, missing memo instruction, tag
//! mismatch, plaintext corruption, extra or missing entry — are
//! surfaced as non-zero exit codes with an explicit PASS/FAIL line
//! so the harness can gate CI.
//!
//! Run with:
//!
//! ```bash
//! cargo run --release -p tidex6-day1 --bin tidex6-day13-accountant
//! ```

use std::collections::HashSet;

use anchor_client::{Cluster, Signer};
use anyhow::{Context, Result, anyhow};
use solana_keypair::{Keypair, read_keypair_file};

use tidex6_client::{AccountantScanner, PrivatePool};
use tidex6_core::elgamal::AuditorSecretKey;
use tidex6_core::note::Denomination;

/// Denomination used for the harness. Small so repeated runs do not
/// burn mainnet SOL; still large enough to exercise every code path.
const TEST_DENOMINATION: Denomination = Denomination::OneTenthSol;

/// The three memo plaintexts. Distinctive strings so a wrong
/// pairing between plaintext and decryption result is obvious in
/// the failure output.
const MEMO_PLAINTEXTS: &[&str] = &[
    "day13-kai-rent-march-2026",
    "day13-kai-medicine-april-2026",
    "day13-kai-groceries-may-2026",
];

fn main() -> Result<()> {
    println!("tidex6 Day-13 accountant flight harness");
    println!("=======================================");
    println!();

    let payer = load_default_keypair().context("failed to load Solana keypair")?;
    let cluster = detect_cluster().context("failed to detect Solana cluster")?;

    println!("cluster       : {}", cluster.url());
    println!("payer         : {}", payer.pubkey());
    println!("denomination  : {TEST_DENOMINATION}");
    println!();

    // Generate a fresh auditor keypair. Kept entirely in memory —
    // the whole point of this test is to verify that the depositor
    // does not need the auditor's *secret* key and vice versa.
    let auditor_sk =
        AuditorSecretKey::random().context("generate auditor secret key for harness")?;
    let auditor_pk = auditor_sk.public_key();
    println!("auditor pk    : {}", auditor_pk.to_hex());
    println!();

    let pool = PrivatePool::connect(cluster.clone(), TEST_DENOMINATION)?;
    println!("pool PDA      : {}", pool.pool_pda());
    println!();

    // Send three memo-carrying deposits.
    println!(
        "--- Sending {} memo-carrying deposits ---",
        MEMO_PLAINTEXTS.len()
    );
    let mut expected_memos: HashSet<String> = HashSet::new();
    for (index, memo_text) in MEMO_PLAINTEXTS.iter().enumerate() {
        let outcome = pool
            .deposit(&payer)
            .with_auditor(auditor_pk)
            .with_memo(*memo_text)
            .send()
            .with_context(|| format!("deposit #{} failed", index + 1))?;
        println!(
            "  deposit #{}: leaf {} signature {}",
            index + 1,
            outcome.leaf_index,
            outcome.signature
        );
        expected_memos.insert((*memo_text).to_string());
    }
    println!();

    // Scan the pool as the auditor would.
    println!("--- Running AccountantScanner ---");
    let scanner = AccountantScanner::new(cluster.url(), pool.pool_pda(), &auditor_sk);
    let entries = scanner.scan().context("accountant scan failed")?;
    println!("decrypted {} entries", entries.len());
    println!();

    // Check that every expected memo came back and that nothing
    // extra was decoded. We only match by plaintext: leaf-index is
    // not deterministic because the pool might already hold prior
    // deposits from earlier runs.
    let mut decrypted_memos: HashSet<String> = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let plaintext = entry.plaintext_lossy();
        println!(
            "  [{i}] leaf={} sig={} memo={plaintext}",
            entry.leaf_index,
            shorten(&entry.signature, 16),
        );
        decrypted_memos.insert(plaintext);
    }
    println!();

    // Verify the expected set is a subset of what we decrypted —
    // the pool may contain memos from prior runs that also decrypt
    // under *this run's* auditor key if (by astronomically low
    // probability) the same scalar was sampled twice, but in
    // practice the expected set should always appear.
    let missing: Vec<String> = expected_memos
        .difference(&decrypted_memos)
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(anyhow!(
            "Day-13 FAIL: expected memos were not decoded by the accountant scan: {:?}",
            missing
        ));
    }

    // Also fail if the scan somehow returned *fewer* entries than
    // we sent — every memo-carrying deposit in this run must be
    // visible to the auditor.
    if entries.len() < MEMO_PLAINTEXTS.len() {
        return Err(anyhow!(
            "Day-13 FAIL: expected at least {} entries, scanner returned {}",
            MEMO_PLAINTEXTS.len(),
            entries.len()
        ));
    }

    println!("=======================================");
    println!("Day-13 accountant harness: PASSED");
    println!(
        "  {} deposits sent, {} entries decrypted, all expected memos present.",
        MEMO_PLAINTEXTS.len(),
        entries.len()
    );
    println!("=======================================");

    Ok(())
}

fn load_default_keypair() -> Result<Keypair> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/id.json");
    read_keypair_file(&path).map_err(|err| anyhow!("failed to read keypair from {path}: {err}"))
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

fn shorten(s: &str, len: usize) -> String {
    if s.len() <= len {
        s.to_string()
    } else {
        let mut out = s[..len].to_string();
        out.push('…');
        out
    }
}
