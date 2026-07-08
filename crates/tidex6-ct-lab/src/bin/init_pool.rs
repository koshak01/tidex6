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
    // Сеть — из env TIDEX6_NET (mainnet|devnet), дефолт devnet. RPC+keypair из
    // wusdc-config (rpc_<net> + keypair-<moniker>.json), НЕ solana CLI — payer
    // = оператор сети. Мин-оверрайды из config, чтобы pool_pda взял верный пул.
    let cfg = config::Config::load().context("config.toml")?;
    let net = match std::env::var("TIDEX6_NET").ok().as_deref() {
        Some("mainnet") | Some("mainnet-beta") => tidex6_core::network::Network::Mainnet,
        _ => tidex6_core::network::Network::Devnet,
    };
    let (rpc, payer) = flow::rpc_for_network(net, cfg.rpc_override(net)).context("rpc/keypair")?;
    config::set_active_network(net);
    config::set_mint_overrides(cfg.mints.clone());

    let mint_arg = std::env::args()
        .nth(1)
        .context("usage: init_pool <mint-pubkey> [asset: wusdc|wusdt]")?;
    let mint = Pubkey::from_str(&mint_arg).context("bad mint pubkey")?;

    // Актив: 2-й аргумент (override) или из конфига. Определяет какой пул init'ить.
    let asset = match std::env::args().nth(2) {
        Some(a) => tidex6_core::network::Asset::from_symbol(&a)
            .context("bad asset arg (use wusdc|wusdt)")?,
        None => cfg.asset(),
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
