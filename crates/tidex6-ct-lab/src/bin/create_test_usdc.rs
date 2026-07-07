//! create_test_usdc — создаёт ТЕСТОВЫЙ USDC-минт на активной сети (RPC из
//! `solana config`) и чеканит запас на кошелёк payer'а. Нужен как underlying
//! для `wrap` на devnet (реального Circle-USDC на devnet нет).
//!
//! USDC = стандартный SPL-минт (legacy `spl_token`, НЕ Token-2022), 6 decimals
//! — один в один как настоящий USDC. Token-2022 CT-обёртку делает `create_wusdc`.
//!
//! Запуск (из crates/tidex6-ct-lab): cargo run --bin create_test_usdc

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_keypair::{write_keypair_file, Keypair};
use solana_signer::Signer;
use spl_token_client::client::{ProgramRpcClient, ProgramRpcClientSendTransaction};
use spl_token_client::token::Token;
use tidex6_ct_lab::config::Config;
use tidex6_ct_lab::flow;
use tidex6_core::network::Network;

/// decimals как у настоящего USDC.
const DECIMALS: u8 = 6;
/// Начеканить payer'у 100 000 test-USDC (в минимальных единицах).
const MINT_AMOUNT: u64 = 100_000 * 1_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    // RPC+keypair из wusdc-config (rpc_devnet + keypair-devnet.json), НЕ из
    // solana CLI — на проде тот настроен на mainnet и занят боевым сервисом.
    // test-USDC — только devnet (реального Circle-USDC на devnet нет).
    let config = Config::load().context("config.toml")?;
    let net = Network::Devnet;
    let (rpc, payer) =
        flow::rpc_for_network(net, config.rpc_override(net)).context("devnet rpc/keypair")?;
    println!("payer:   {}", payer.pubkey());
    println!("rpc:     {}", rpc.url().split('?').next().unwrap_or(""));
    println!("network: {net:?}");

    // Mint keypair — сохраняем по сети, не затираем существующий.
    let home = std::env::var("HOME").context("нет $HOME")?;
    let dir = format!("{home}/.tidex6-wusdc");
    std::fs::create_dir_all(&dir).context("создать ~/.tidex6-wusdc")?;
    // Опц. первый аргумент = символ (usdc дефолт, usdt для wUSDT-underlying).
    let sym = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "usdc".to_string())
        .to_lowercase();
    let mint_path = format!("{dir}/test-{sym}-mint-{}.json", net.info().moniker);
    if std::path::Path::new(&mint_path).exists() {
        anyhow::bail!("test-{} mint keypair already exists: {mint_path} — remove it to recreate", sym.to_uppercase());
    }
    let mint_keypair = Keypair::new();
    write_keypair_file(&mint_keypair, &mint_path)
        .map_err(|e| anyhow::anyhow!("mint keypair не сохранён: {e}"))?;

    let program_client = Arc::new(ProgramRpcClient::new(
        rpc.clone(),
        ProgramRpcClientSendTransaction,
    ));
    let token = Token::new(
        program_client,
        &spl_token::id(),
        &mint_keypair.pubkey(),
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );

    // 1. Создать стандартный SPL-минт (authority = payer, без расширений).
    println!("\nсоздаю test-USDC mint (SPL, decimals {DECIMALS})…");
    token
        .create_mint(&payer.pubkey(), None, vec![], &[&mint_keypair])
        .await
        .context("create_mint")?;

    // 2. ATA payer'а + чеканка запаса.
    token
        .create_associated_token_account(&payer.pubkey())
        .await
        .ok();
    let ata = token.get_associated_token_address(&payer.pubkey());
    token
        .mint_to(&ata, &payer.pubkey(), MINT_AMOUNT, &[&payer])
        .await
        .context("mint_to")?;

    println!("\n═══ test-{} создан ═══", sym.to_uppercase());
    println!("mint keypair: {mint_path}");
    println!(">>> TEST-{} MINT: {} <<<", sym.to_uppercase(), mint_keypair.pubkey());
    println!("minted {} {} → {}", MINT_AMOUNT / 1_000_000, sym.to_uppercase(), ata);
    Ok(())
}
