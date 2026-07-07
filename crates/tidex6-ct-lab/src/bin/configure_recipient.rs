//! Настраивает конфиденциальный wUSDC-аккаунт для СВЕЖЕГО получателя.
//!
//! Получатель — ключ, который сохранил `withdraw` (recipient-<nh8>.json).
//! Чтобы релеер-мувер смог выплатить wUSDC конфиденциально, у получателя
//! должен быть reallocate+configure CT-аккаунт с его ElGamal-ключом. Его
//! публичный ElGamal-ключ ложится в on-chain расширение — оттуда мувер его
//! и читает (секрет получателя муверу не нужен).
//!
//! Домены ключей — те же, что у владельца в wrap/unwrap
//! (`tidex6-wusdc-alice-elgamal-v1` / `-ae-v1`), но подписаны ключом
//! получателя. Значит потом `unwrap` этим же ключом сойдётся.
//!
//! Fee платит основной кошелёк (payer); получатель со-подписывает configure.
//!
//! Запуск: cargo run -p tidex6-ct-lab --bin configure_recipient -- <recipient-key.json>

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};
use spl_token_2022::extension::{
    confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions, ExtensionType,
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::Token,
};

const WUSDC_MINT: &str = "CckZq2kKW5yZwNjNmLwrGDDpHB7NsU2u3Zdhk3K6ZLbv";
const DECIMALS: u8 = 6;

#[tokio::main]
async fn main() -> Result<()> {
    let recipient_path = std::env::args()
        .nth(1)
        .context("укажи ключ получателя: configure_recipient -- <recipient-key.json>")?;
    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer =
        read_keypair_file(&keypair_path).map_err(|e| anyhow::anyhow!("payer keypair: {e}"))?;
    let recipient = read_keypair_file(&recipient_path)
        .map_err(|e| anyhow::anyhow!("recipient keypair: {e}"))?;
    let mint_pubkey: Pubkey = WUSDC_MINT.parse().context("mint pubkey")?;

    println!("payer:     {}", payer.pubkey());
    println!("получатель:{}", recipient.pubkey());
    println!("wUSDC mint:{mint_pubkey}");

    let rpc = Arc::new(RpcClient::new_with_commitment(
        json_rpc_url,
        CommitmentConfig::confirmed(),
    ));
    let program_client = Arc::new(ProgramRpcClient::new(
        rpc.clone(),
        ProgramRpcClientSendTransaction,
    ));
    let token = Token::new(
        program_client,
        &spl_token_2022::id(),
        &mint_pubkey,
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );

    let recipient_elgamal = elgamal_from(&recipient, b"tidex6-wusdc-alice-elgamal-v1")?;
    let recipient_ae = ae_from(&recipient, b"tidex6-wusdc-alice-ae-v1")?;

    let ata = token.get_associated_token_address(&recipient.pubkey());
    println!("получатель ATA: {ata}");

    // Уже сконфигурирован?
    if let Ok(info) = token.get_account_info(&ata).await {
        if info.get_extension::<ConfidentialTransferAccount>().is_ok() {
            println!("\nCT-аккаунт получателя уже настроен — готов принимать wUSDC.");
            return Ok(());
        }
    }

    println!("\n[1/3] создаю ATA получателя…");
    token
        .create_associated_token_account(&recipient.pubkey())
        .await
        .ok();

    println!("[2/3] reallocate под ConfidentialTransferAccount…");
    token
        .reallocate(
            &ata,
            &recipient.pubkey(),
            &[ExtensionType::ConfidentialTransferAccount],
            &[&payer, &recipient],
        )
        .await
        .context("reallocate получателя")?;

    println!("[3/3] configure (ElGamal-ключ получателя → on-chain)…");
    token
        .confidential_transfer_configure_token_account(
            &ata,
            &recipient.pubkey(),
            None,
            None,
            &recipient_elgamal,
            &recipient_ae,
            &[&payer, &recipient],
        )
        .await
        .context("configure получателя")?;

    println!("\n═══ ПОЛУЧАТЕЛЬ ГОТОВ ═══");
    println!("ATA: {ata}");
    println!("Теперь релеер-мувер сможет выплатить wUSDC на этот адрес конфиденциально.");
    Ok(())
}

fn elgamal_from(signer: &Keypair, msg: &[u8]) -> Result<ElGamalKeypair> {
    ElGamalKeypair::new_from_signature_legacy(&signer.sign_message(msg))
        .map_err(|e| anyhow::anyhow!("elgamal: {e}"))
}

fn ae_from(signer: &Keypair, msg: &[u8]) -> Result<AeKey> {
    AeKey::new_from_signature_legacy(&signer.sign_message(msg))
        .map_err(|e| anyhow::anyhow!("ae: {e}"))
}

fn load_cli_config() -> Result<(String, String)> {
    let home = std::env::var("HOME").context("нет $HOME")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/solana/cli/config.yml"))
        .context("не прочитан ~/.config/solana/cli/config.yml")?;
    let field = |name: &str| -> Result<String> {
        raw.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(|v| v.trim().to_owned())
            .with_context(|| format!("нет поля {name}"))
    };
    Ok((field("json_rpc_url")?, field("keypair_path")?))
}
