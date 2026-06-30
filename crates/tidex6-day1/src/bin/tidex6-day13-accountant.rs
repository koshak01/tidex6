//! Day-13 Accountant flight harness (v2, ML-KEM).
//!
//! Exercises the end-to-end ML-KEM memo round-trip against a live
//! cluster on the v2 verifier:
//!
//!   1. Generate a fresh ML-KEM-768 keypair in memory (auditor =
//!      recipient = self for the test).
//!   2. Send three deposits into the `0.1 SOL` pool, each sealing a
//!      unique memo for that key (recipient slot + auditor slot).
//!   3. Run `tidex6-client::AccountantScanner::scan` against the v2
//!      program with the matching ML-KEM secret.
//!   4. Assert that the three memos come back with plaintexts intact.
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
use tidex6_core::note::Denomination;
use tidex6_core::pqc;

/// Denomination used for the harness.
const TEST_DENOMINATION: Denomination = Denomination::OneTenthSol;

/// The three memo plaintexts.
const MEMO_PLAINTEXTS: &[&str] = &[
    "day13-kai-rent-march-2026",
    "day13-kai-medicine-april-2026",
    "day13-kai-groceries-may-2026",
];

fn main() -> Result<()> {
    println!("tidex6 Day-13 accountant flight harness (v2, ML-KEM)");
    println!("====================================================");
    println!();

    let payer = load_default_keypair().context("failed to load Solana keypair")?;
    let cluster = detect_cluster().context("failed to detect Solana cluster")?;

    println!("cluster       : {}", cluster.url());
    println!("payer         : {}", payer.pubkey());
    println!("denomination  : {TEST_DENOMINATION}");
    println!();

    // Fresh ML-KEM keypair, in memory only. The recipient slot and the
    // auditor slot are both sealed to this key for the test.
    let (mlkem_public, mlkem_secret) = pqc::keygen();
    println!("ML-KEM pk     : {}…", &hex::encode(mlkem_public.as_bytes())[..32]);
    println!();

    let pool = PrivatePool::connect(cluster.clone(), TEST_DENOMINATION)?;
    println!("pool PDA      : {}", pool.pool_pda());
    println!();

    println!(
        "--- Sending {} memo-carrying deposits ---",
        MEMO_PLAINTEXTS.len()
    );
    let mut expected_memos: HashSet<String> = HashSet::new();
    for (index, memo_text) in MEMO_PLAINTEXTS.iter().enumerate() {
        let outcome = pool
            .deposit(&payer)
            .to_recipient(mlkem_public.clone())
            .with_auditor(mlkem_public.clone())
            .with_memo(*memo_text)
            .revoke_after(0)
            .send()
            .with_context(|| format!("deposit #{} failed", index + 1))?;
        println!(
            "  deposit #{}: leaf {} memo-account {}",
            index + 1,
            outcome.leaf_index,
            outcome.memo_account
        );
        expected_memos.insert((*memo_text).to_string());
    }
    println!();

    println!("--- Running AccountantScanner (v2, getProgramAccounts) ---");
    let scanner = AccountantScanner::new(cluster.url(), pool.program_id(), &mlkem_secret);
    let entries = scanner.scan().context("accountant scan failed")?;
    println!("decrypted {} entries", entries.len());
    println!();

    let mut decrypted_memos: HashSet<String> = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let plaintext = entry.plaintext_lossy();
        println!(
            "  [{i}] commitment={} amount={} memo={plaintext}",
            shorten(&entry.commitment_hex, 16),
            entry.denomination,
        );
        decrypted_memos.insert(plaintext);
    }
    println!();

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

    if entries.len() < MEMO_PLAINTEXTS.len() {
        return Err(anyhow!(
            "Day-13 FAIL: expected at least {} entries, scanner returned {}",
            MEMO_PLAINTEXTS.len(),
            entries.len()
        ));
    }

    println!("====================================================");
    println!("Day-13 accountant harness (v2): PASSED");
    println!(
        "  {} deposits sent, {} entries decrypted, all expected memos present.",
        MEMO_PLAINTEXTS.len(),
        entries.len()
    );
    println!("====================================================");

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
