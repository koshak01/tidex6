//! unwrap wUSDC → USDC на mainnet — обратка wrap, замыкает цикл.
//!
//! Конфиденциально сжигает `amount` wUSDC с кошелька и возвращает столько же
//! реального USDC из vault (обеспечение). После этого сумма снова публична
//! (USDC на кошельке), но всё, что было между wrap и unwrap, — скрыто.
//!
//! Запуск: cargo run -p tidex6-ct-lab --bin unwrap --release -- <amount_usdc>

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};
use spl_token_2022::extension::{
    confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::{ProofAccountWithCiphertext, Token},
    zk_proofs::confidential_mint_burn::BurnAccountInfo,
};
use spl_token_confidential_transfer_proof_generation::burn::BurnProofData;

const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WUSDC_MINT: &str = "CckZq2kKW5yZwNjNmLwrGDDpHB7NsU2u3Zdhk3K6ZLbv";
const DECIMALS: u8 = 6;

type Client = Token<ProgramRpcClientSendTransaction>;

#[tokio::main]
async fn main() -> Result<()> {
    let amount_usdc: f64 = std::env::args()
        .nth(1)
        .context("укажи сумму: cargo run --bin unwrap -- <amount>")?
        .parse()
        .context("сумма — число")?;
    let amount: u64 = (amount_usdc * 1_000_000.0).round() as u64;

    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path).map_err(|e| anyhow::anyhow!("keypair: {e}"))?;
    let usdc_mint: Pubkey = USDC_MINT.parse()?;
    let wusdc_mint: Pubkey = WUSDC_MINT.parse()?;
    println!("кошелёк:  {}", payer.pubkey());
    println!("разворачиваю: {amount_usdc} wUSDC → USDC");

    let rpc = Arc::new(RpcClient::new_with_commitment(
        json_rpc_url,
        CommitmentConfig::confirmed(),
    ));
    let program_client = Arc::new(ProgramRpcClient::new(
        rpc.clone(),
        ProgramRpcClientSendTransaction,
    ));

    let home = std::env::var("HOME").context("нет $HOME")?;
    let vault = read_keypair_file(format!("{home}/.tidex6-wusdc/vault-keypair.json"))
        .map_err(|e| anyhow::anyhow!("vault keypair: {e}"))?;

    // ── 1. Конфид-burn amount wUSDC ──────────────────────────────────
    let wusdc = Token::new(
        program_client.clone(),
        &spl_token_2022::id(),
        &wusdc_mint,
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );
    let supply_elgamal = elgamal_from(&payer, b"tidex6-wusdc-supply-elgamal-v1")?;
    let owner_elgamal = elgamal_from(&payer, b"tidex6-wusdc-alice-elgamal-v1")?;
    let owner_ae = ae_from(&payer, b"tidex6-wusdc-alice-ae-v1")?;
    let owner_ata = wusdc.get_associated_token_address(&payer.pubkey());

    println!("\n[1/2] конфид-burn {amount_usdc} wUSDC…");
    {
        let account_info = wusdc.get_account_info(&owner_ata).await.context("wUSDC info")?;
        let ct = account_info
            .get_extension::<ConfidentialTransferAccount>()
            .context("нет CT")?;
        let BurnProofData {
            equality_proof_data,
            ciphertext_validity_proof_data_with_ciphertext,
            range_proof_data,
        } = BurnAccountInfo::new(ct)
            .generate_split_burn_proof_data(
                amount,
                &owner_elgamal,
                &owner_ae,
                supply_elgamal.pubkey(),
                None,
            )
            .map_err(|e| anyhow::anyhow!("burn proof: {e}"))?;
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
            .confidential_transfer_burn(
                &payer.pubkey(),
                &owner_ata,
                Some(&eq.pubkey()),
                Some(&val_ct),
                Some(&range.pubkey()),
                amount,
                &owner_elgamal,
                supply_elgamal.pubkey(),
                None,
                &owner_ae,
                None,
                &[&payer],
            )
            .await
            .context("confidential burn")?;
        close_ctxs(&wusdc, &payer, &[&eq, &val, &range]).await?;
    }

    // ── 2. Возврат amount USDC из vault → кошелёк ────────────────────
    println!("\n[2/2] возвращаю {amount_usdc} USDC из vault…");
    let usdc = Token::new(
        program_client,
        &spl_token::id(),
        &usdc_mint,
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );
    let vault_usdc = usdc.get_associated_token_address(&vault.pubkey());
    let payer_usdc = usdc.get_associated_token_address(&payer.pubkey());
    usdc.transfer(&vault_usdc, &payer_usdc, &vault.pubkey(), amount, &[&vault])
        .await
        .context("vault USDC → кошелёк")?;

    // ── Итог ─────────────────────────────────────────────────────────
    let usdc_bal = usdc.get_account_info(&payer_usdc).await?.base.amount;
    println!("\n══════ UNWRAP ГОТОВ ══════");
    println!("USDC на кошельке: {} USDC", usdc_bal as f64 / 1e6);
    println!("Цикл замкнут: USDC → wUSDC (скрыто) → USDC.");
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
    AeKey::new_from_signature_legacy(&signer.sign_message(msg)).map_err(|e| anyhow::anyhow!("ae: {e}"))
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
