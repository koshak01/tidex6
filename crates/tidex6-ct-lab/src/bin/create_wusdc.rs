//! Создаёт постоянный wUSDC-mint на mainnet — фундамент MVP.
//!
//! Token-2022 mint с `ConfidentialTransferMint` + `ConfidentialMintBurn`,
//! decimals 6 (как USDC). Обёрточный токен: обеспечивается 1:1 реальным USDC
//! в vault, суммы скрыты (CT). Mint/burn-authority и supply-ElGamal держит
//! оператор (наш кошелёк) — MVP-версия; децентрализация authority — следом.
//!
//! Supply-ElGamal и AE-ключи выводятся ДЕТЕРМИНИРОВАННО из подписи кошелька
//! (`new_from_signature`), поэтому их не нужно хранить — регенерируются при
//! каждом wrap. Сохраняется только mint keypair (для идентификации).
//!
//! Запуск: cargo run -p tidex6-ct-lab --bin create_wusdc --release

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, write_keypair_file, Keypair};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::{ExtensionInitializationParams, Token},
};

/// decimals wUSDC = decimals USDC.
const DECIMALS: u8 = 6;
/// Домены подписи для детерминированных ключей supply (см. модульный docstring).
const SUPPLY_ELGAMAL_MSG: &[u8] = b"tidex6-wusdc-supply-elgamal-v1";
const SUPPLY_AE_MSG: &[u8] = b"tidex6-wusdc-supply-ae-v1";

#[tokio::main]
async fn main() -> Result<()> {
    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow::anyhow!("keypair не прочитан: {e}"))?;
    println!("payer:  {}", payer.pubkey());
    println!("rpc:    {}", json_rpc_url.split('?').next().unwrap_or(""));
    // Сеть определяем по RPC (что реально указано в `solana config`),
    // а не по config.toml — убирает рассинхрон.
    let net = tidex6_core::network::Network::from_rpc_url(&json_rpc_url);
    println!("network: {net:?}");

    let rpc_client = Arc::new(RpcClient::new_with_commitment(
        json_rpc_url,
        CommitmentConfig::confirmed(),
    ));
    let program_client = Arc::new(ProgramRpcClient::new(
        rpc_client.clone(),
        ProgramRpcClientSendTransaction,
    ));

    // Mint keypair — сохраняем в ~/.tidex6-wusdc/. Devnet НЕ затирает
    // mainnet-keypair (mint-authority для CckZq2kK…): отдельный файл по сети.
    let home = std::env::var("HOME").context("нет $HOME")?;
    let dir = format!("{home}/.tidex6-wusdc");
    std::fs::create_dir_all(&dir).context("создать ~/.tidex6-wusdc")?;
    let suffix = if net == tidex6_core::network::Network::Mainnet {
        String::new()
    } else {
        format!("-{}", net.info().moniker)
    };
    // Опц. первый аргумент = метка актива для имени файла: "" = wUSDC (дефолт),
    // "wusdt" = wUSDT (тот же CT-минт, другой файл keypair).
    let asset_label = std::env::args().nth(1).unwrap_or_default();
    let label = if asset_label.trim().is_empty() {
        "wusdc".to_string()
    } else {
        asset_label.trim().to_lowercase()
    };
    let prefix = if label == "wusdc" {
        String::new()
    } else {
        format!("{label}-")
    };
    let mint_keypair = Keypair::new();
    let mint_path = format!("{dir}/{prefix}mint-keypair{suffix}.json");
    // Страховка: не затираем существующий mint-authority keypair (фонд-материал).
    if std::path::Path::new(&mint_path).exists() {
        anyhow::bail!(
            "mint keypair already exists: {mint_path}\n\
             refusing to overwrite (it's the mint-authority). Remove it deliberately \
             or set the correct `network` in ~/.tidex6-wusdc/config.toml."
        );
    }
    write_keypair_file(&mint_keypair, &mint_path)
        .map_err(|e| anyhow::anyhow!("mint keypair не сохранён: {e}"))?;
    println!("network:  {:?} ({})", net, net.info().moniker);
    println!("asset:    {label}");
    println!("mint keypair saved: {mint_path}");
    println!(">>> {} MINT: {} <<<", label.to_uppercase(), mint_keypair.pubkey());

    // Детерминированные supply-ключи из подписи кошелька.
    let supply_sig = payer.sign_message(SUPPLY_ELGAMAL_MSG);
    let supply_elgamal = ElGamalKeypair::new_from_signature_legacy(&supply_sig)
        .map_err(|e| anyhow::anyhow!("supply ElGamal: {e}"))?;
    let ae_sig = payer.sign_message(SUPPLY_AE_MSG);
    let mint_ae = AeKey::new_from_signature_legacy(&ae_sig)
        .map_err(|e| anyhow::anyhow!("supply AE: {e}"))?;

    let token = Token::new(
        program_client,
        &spl_token_2022::id(),
        &mint_keypair.pubkey(),
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );

    println!("\nсоздаю {}-mint (CT + ConfidentialMintBurn, decimals {DECIMALS})…", label.to_uppercase());
    let out = token
        .create_mint(
            &payer.pubkey(),
            None,
            vec![
                ExtensionInitializationParams::ConfidentialTransferMint {
                    authority: Some(payer.pubkey()),
                    auto_approve_new_accounts: true,
                    auditor_elgamal_pubkey: None,
                },
                ExtensionInitializationParams::ConfidentialMintBurn {
                    supply_elgamal_pubkey: (*supply_elgamal.pubkey()).into(),
                    decryptable_supply: mint_ae.encrypt(0).into(),
                },
            ],
            &[&mint_keypair],
        )
        .await
        .context("create_mint")?;

    println!("\n═══ {}-mint создан ═══", label.to_uppercase());
    println!("mint:    {}", mint_keypair.pubkey());
    println!("keypair: {mint_path}");
    println!("tx:      {out:?}");
    println!("Solscan: https://solscan.io/token/{}", mint_keypair.pubkey());
    Ok(())
}

/// Читает json_rpc_url и keypair_path из ~/.config/solana/cli/config.yml.
fn load_cli_config() -> Result<(String, String)> {
    let home = std::env::var("HOME").context("нет $HOME")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/solana/cli/config.yml"))
        .context("не прочитан ~/.config/solana/cli/config.yml")?;
    let field = |name: &str| -> Result<String> {
        raw.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(|v| v.trim().to_owned())
            .with_context(|| format!("в конфиге CLI нет поля {name}"))
    };
    Ok((field("json_rpc_url")?, field("keypair_path")?))
}
