//! Реальный wrap USDC → wUSDC на mainnet (MVP-версия с обеспечением в vault).
//!
//! Переводит `amount` реального USDC из кошелька в vault-аккаунт (обеспечение
//! 1:1) и конфиденциально минтит столько же wUSDC обратно на кошелёк. После
//! этого сумма живёт в зашифрованном wUSDC-балансе; USDC заперт в vault под
//! оператором (MVP: оператор = наш кошелёк; децентрализация через
//! wrap-программу с PDA-authority — следующий шаг).
//!
//! Vault keypair сохраняется в ~/.tidex6-wusdc/vault-keypair.json — из него
//! потом идёт unwrap (burn wUSDC → возврат USDC).
//!
//! Запуск: cargo run -p tidex6-ct-lab --bin wrap --release -- <amount_usdc>
//! Пример: ... -- 5   (обернуть 5 USDC)

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, write_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};
use spl_token_2022::extension::{
    confidential_mint_burn::ConfidentialMintBurn,
    confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions, ExtensionType,
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::{ProofAccountWithCiphertext, Token},
    zk_proofs::confidential_mint_burn::SupplyAccountInfo,
};
use spl_token_confidential_transfer_proof_generation::mint::MintProofData;

/// Реальный USDC на mainnet (Circle).
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// Наш wUSDC-mint (create_wusdc).
const WUSDC_MINT: &str = "CckZq2kKW5yZwNjNmLwrGDDpHB7NsU2u3Zdhk3K6ZLbv";
const DECIMALS: u8 = 6;

type Client = Token<ProgramRpcClientSendTransaction>;

#[tokio::main]
async fn main() -> Result<()> {
    let amount_usdc: f64 = std::env::args()
        .nth(1)
        .context("укажи сумму USDC: cargo run --bin wrap -- <amount>")?
        .parse()
        .context("сумма — число")?;
    let amount: u64 = (amount_usdc * 1_000_000.0).round() as u64;
    require(amount > 0, "сумма должна быть > 0")?;

    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path).map_err(|e| anyhow::anyhow!("keypair: {e}"))?;
    let usdc_mint: Pubkey = USDC_MINT.parse()?;
    let wusdc_mint: Pubkey = WUSDC_MINT.parse()?;
    println!("кошелёк:    {}", payer.pubkey());
    println!("оборачиваю: {amount_usdc} USDC → wUSDC");

    let rpc = Arc::new(RpcClient::new_with_commitment(
        json_rpc_url,
        CommitmentConfig::confirmed(),
    ));
    let program_client = Arc::new(ProgramRpcClient::new(
        rpc.clone(),
        ProgramRpcClientSendTransaction,
    ));

    // ── Vault: отдельный аккаунт под USDC-обеспечение ────────────────
    let home = std::env::var("HOME").context("нет $HOME")?;
    let vault_path = format!("{home}/.tidex6-wusdc/vault-keypair.json");
    let vault = if std::path::Path::new(&vault_path).exists() {
        read_keypair_file(&vault_path).map_err(|e| anyhow::anyhow!("vault keypair: {e}"))?
    } else {
        let v = Keypair::new();
        write_keypair_file(&v, &vault_path).map_err(|e| anyhow::anyhow!("vault save: {e}"))?;
        v
    };
    println!("vault:      {} (обеспечение USDC)", vault.pubkey());

    // ── USDC: перевод amount в vault ─────────────────────────────────
    let usdc = Token::new(
        program_client.clone(),
        &spl_token::id(),
        &usdc_mint,
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );
    let payer_usdc = usdc.get_associated_token_address(&payer.pubkey());
    usdc.create_associated_token_account(&vault.pubkey())
        .await
        .ok();
    let vault_usdc = usdc.get_associated_token_address(&vault.pubkey());
    println!("\n[1/3] перевожу {amount_usdc} USDC → vault…");
    usdc.transfer(&payer_usdc, &vault_usdc, &payer.pubkey(), amount, &[&payer])
        .await
        .context("USDC → vault")?;

    // ── wUSDC: конфид-минт amount на кошелёк ─────────────────────────
    let wusdc = Token::new(
        program_client,
        &spl_token_2022::id(),
        &wusdc_mint,
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );
    let supply_elgamal = elgamal_from(&payer, b"tidex6-wusdc-supply-elgamal-v1")?;
    let mint_ae = ae_from(&payer, b"tidex6-wusdc-supply-ae-v1")?;
    let owner_elgamal = elgamal_from(&payer, b"tidex6-wusdc-alice-elgamal-v1")?;
    let owner_ae = ae_from(&payer, b"tidex6-wusdc-alice-ae-v1")?;

    println!("\n[2/3] настраиваю конфид wUSDC-аккаунт (если нужно)…");
    wusdc
        .create_associated_token_account(&payer.pubkey())
        .await
        .ok();
    let owner_ata = wusdc.get_associated_token_address(&payer.pubkey());
    // reallocate + configure только если ещё не конфиденциальный.
    if wusdc
        .get_account_info(&owner_ata)
        .await
        .ok()
        .and_then(|a| {
            a.get_extension::<ConfidentialTransferAccount>()
                .ok()
                .map(|_| ())
        })
        .is_none()
    {
        wusdc
            .reallocate(
                &owner_ata,
                &payer.pubkey(),
                &[ExtensionType::ConfidentialTransferAccount],
                &[&payer],
            )
            .await
            .context("reallocate")?;
        wusdc
            .confidential_transfer_configure_token_account(
                &owner_ata,
                &payer.pubkey(),
                None,
                None,
                &owner_elgamal,
                &owner_ae,
                &[&payer],
            )
            .await
            .context("configure")?;
    }

    println!("\n[3/3] конфид-минт {amount_usdc} wUSDC → кошелёк…");
    {
        let mint_info = wusdc.get_mint_info().await.context("mint info")?;
        let supply_ext = mint_info
            .get_extension::<ConfidentialMintBurn>()
            .context("нет ConfidentialMintBurn")?;
        let MintProofData {
            equality_proof_data,
            ciphertext_validity_proof_data_with_ciphertext,
            range_proof_data,
        } = SupplyAccountInfo::new(supply_ext)
            .generate_split_mint_proof_data(
                amount,
                &supply_elgamal,
                &mint_ae,
                owner_elgamal.pubkey(),
                None,
            )
            .map_err(|e| anyhow::anyhow!("mint proof: {e}"))?;
        let (eq, val, range) = (Keypair::new(), Keypair::new(), Keypair::new());
        create_ctx(&wusdc, &payer, &eq, &equality_proof_data, false).await?;
        create_ctx(
            &wusdc,
            &payer,
            &val,
            &ciphertext_validity_proof_data_with_ciphertext.proof_data,
            false,
        )
        .await?;
        create_ctx(&wusdc, &payer, &range, &range_proof_data, true).await?;
        let val_ct = ProofAccountWithCiphertext {
            context_state_account: val.pubkey(),
            ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
            ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        };
        wusdc
            .confidential_transfer_mint(
                &payer.pubkey(),
                &owner_ata,
                Some(&eq.pubkey()),
                Some(&val_ct),
                Some(&range.pubkey()),
                amount,
                &supply_elgamal,
                owner_elgamal.pubkey(),
                None,
                &mint_ae,
                None,
                &[&payer],
            )
            .await
            .context("confidential mint")?;
        close_ctxs(&wusdc, &payer, &[&eq, &val, &range]).await?;
    }
    wusdc
        .confidential_transfer_apply_pending_balance(
            &owner_ata,
            &payer.pubkey(),
            None,
            owner_elgamal.secret(),
            &owner_ae,
            &[&payer],
        )
        .await
        .context("apply")?;

    // ── Итог ─────────────────────────────────────────────────────────
    let vault_bal = usdc.get_account_info(&vault_usdc).await?.base.amount;
    let info = wusdc.get_account_info(&owner_ata).await?;
    let ct = info.get_extension::<ConfidentialTransferAccount>()?;
    let plain: Option<u64> = owner_ae.decrypt(&ct.decryptable_available_balance.try_into()?);
    println!("\n══════ WRAP ГОТОВ ══════");
    println!("vault USDC (обеспечение): {} USDC", vault_bal as f64 / 1e6);
    println!(
        "твой wUSDC (конфид):      {} wUSDC (публичный={}, на цепи=шифр)",
        plain.map(|v| v as f64 / 1e6).unwrap_or(-1.0),
        info.base.amount
    );
    println!("vault keypair: {vault_path}");
    Ok(())
}

async fn create_ctx<ZK, U>(
    token: &Client,
    payer: &Keypair,
    ctx: &Keypair,
    proof: &ZK,
    split: bool,
) -> Result<()>
where
    ZK: bytemuck::Pod + solana_zk_elgamal_proof_interface::proof_data::ZkProofData<U>,
    U: bytemuck::Pod,
{
    token
        .confidential_transfer_create_context_state_account(
            &ctx.pubkey(),
            &payer.pubkey(),
            proof,
            split,
            &[ctx],
        )
        .await
        .context("create context")?;
    Ok(())
}

async fn close_ctxs(token: &Client, payer: &Keypair, ctxs: &[&Keypair]) -> Result<()> {
    for c in ctxs {
        token
            .confidential_transfer_close_context_state_account(
                &c.pubkey(),
                &payer.pubkey(),
                &payer.pubkey(),
                &[payer],
            )
            .await
            .context("close context")?;
    }
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

fn require(cond: bool, msg: &str) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{msg}"))
    }
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
