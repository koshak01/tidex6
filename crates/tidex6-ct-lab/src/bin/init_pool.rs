//! init_pool — инициализирует PoolState PDA wUSDC-пула на активной сети
//! (RPC берётся из `solana config`, сеть — из ~/.tidex6-wusdc/config.toml →
//! реестра). Нужен при devnet-развёртывании: после деплоя пула и создания
//! wUSDC-минта.
//!
//! Запуск (из crates/tidex6-ct-lab):
//!   cargo run --bin init_pool -- <wusdc-mint-pubkey>

use std::str::FromStr;

use anyhow::{Context, Result};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use tidex6_ct_lab::{config, flow, pool};

#[tokio::main]
async fn main() -> Result<()> {
    let (rpc, payer) = flow::rpc_from_config().context("solana config")?;
    config::set_active_network(tidex6_core::network::Network::from_rpc_url(&rpc.url()));

    let mint_arg = std::env::args()
        .nth(1)
        .context("usage: init_pool <mint-pubkey> [asset: wusdc|wusdt]")?;
    let mint = Pubkey::from_str(&mint_arg).context("bad mint pubkey")?;

    // Актив: 2-й аргумент (override) или из конфига. Определяет какой пул init'ить.
    let asset = match std::env::args().nth(2) {
        Some(a) => tidex6_core::network::Asset::from_symbol(&a)
            .context("bad asset arg (use wusdc|wusdt)")?,
        None => config::Config::load().context("config.toml")?.asset(),
    };
    config::set_active_asset(asset);
    println!("asset:    {asset:?}");

    println!("network:  {:?}", config::active_network());
    println!("payer:    {}", payer.pubkey());
    println!("pool PDA: {}", pool::pool_pda());
    println!("mint:     {mint}");

    let ix = pool::build_init_pool_ix(&payer.pubkey(), &mint);
    let sig = pool::send_ix(&rpc, &payer, ix)
        .await
        .context("init_pool send")?;
    println!("init_pool ok\ntx: {sig}");
    Ok(())
}
