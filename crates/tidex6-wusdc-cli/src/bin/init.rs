//! Инициализирует verify-only wUSDC-пул на mainnet (`init_pool`).
//!
//! Singleton-пул `[b"wusdc-pool"]` под наш wUSDC-mint. Запускается один раз
//! после деплоя программы.
//!
//! Запуск: cargo run -p tidex6-wusdc-cli --bin init --release

use std::rc::Rc;

use anchor_client::{Client, Cluster, CommitmentConfig, Signer};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};
use solana_keypair::read_keypair_file;
use tidex6_wusdc_pool::accounts as wp_accounts;
use tidex6_wusdc_pool::instruction as wp_instruction;

const WUSDC_MINT: &str = "CckZq2kKW5yZwNjNmLwrGDDpHB7NsU2u3Zdhk3K6ZLbv";

fn main() -> Result<()> {
    let (rpc, ws, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path).map_err(|e| anyhow::anyhow!("keypair: {e}"))?;
    let payer = Rc::new(payer);
    let program_id: Pubkey = tidex6_wusdc_pool::ID;
    let wusdc_mint: Pubkey = WUSDC_MINT.parse().context("mint")?;

    println!("payer:      {}", payer.pubkey());
    println!("program:    {program_id}");
    println!("wUSDC mint: {wusdc_mint}");

    let client = Client::new_with_options(
        Cluster::Custom(rpc, ws),
        payer.clone(),
        CommitmentConfig::confirmed(),
    );
    let program = client.program(program_id)?;

    let (pool_pda, _) = Pubkey::find_program_address(&[b"wusdc-pool"], &program_id);
    println!("pool PDA:   {pool_pda}");

    // Уже инициализирован?
    if let Ok(acc) = program.rpc().get_account(&pool_pda) {
        if !acc.data.is_empty() {
            println!("\nпул уже инициализирован — пропускаю.");
            return Ok(());
        }
    }

    println!("\nинициализирую пул…");
    let sig = program
        .request()
        .accounts(wp_accounts::InitPool {
            pool: pool_pda,
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(wp_instruction::InitPool { mint: wusdc_mint })
        .send()
        .context("init_pool не подтвердился")?;

    println!("\n═══ ПУЛ ИНИЦИАЛИЗИРОВАН ═══");
    println!("tx:      {sig}");
    println!("Solscan: https://solscan.io/tx/{sig}");
    Ok(())
}

/// Читает rpc/ws/keypair из ~/.config/solana/cli/config.yml.
fn load_cli_config() -> Result<(String, String, String)> {
    let home = std::env::var("HOME").context("нет $HOME")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/solana/cli/config.yml"))
        .context("не прочитан ~/.config/solana/cli/config.yml")?;
    let field = |name: &str| -> Result<String> {
        raw.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(|v| v.trim().to_owned())
            .with_context(|| format!("нет поля {name}"))
    };
    let rpc = field("json_rpc_url")?;
    let ws = field("websocket_url")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| rpc.replacen("https", "wss", 1));
    Ok((rpc, ws, field("keypair_path")?))
}
