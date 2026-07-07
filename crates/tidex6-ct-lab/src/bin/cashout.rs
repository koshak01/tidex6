//! cashout — получатель обналичивает принятый wUSDC на ОСНОВНОЙ кошелёк как USDC.
//!
//! Замыкает круг для свежего получателя (из withdraw): его конфиденциальный
//! wUSDC (пришёл от мувера в pending) → apply → конфид-burn → vault возвращает
//! столько же USDC на основной кошелёк. Владелец CT — ключ получателя (fresh,
//! без SOL), комиссию платит основной кошелёк (fee-payer), поэтому получателю
//! SOL не нужен. Сумма берётся из sibling payout-файла (та, что депонировали).
//!
//! Запуск: cargo run -p tidex6-ct-lab --bin cashout -- <recipient-keypair.json>

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
    let recipient_path = std::env::args()
        .nth(1)
        .context("укажи ключ получателя: cashout -- <recipient-keypair.json>")?;
    let recipient = read_keypair_file(&recipient_path)
        .map_err(|e| anyhow::anyhow!("recipient keypair: {e}"))?;
    let amount = amount_from_sibling_payout(&recipient_path)
        .context("сумма из payout-файла (сначала пройди withdraw)")?;
    let amount_usdc = amount as f64 / 1e6;

    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path).map_err(|e| anyhow::anyhow!("keypair: {e}"))?;
    let usdc_mint: Pubkey = USDC_MINT.parse()?;
    let wusdc_mint: Pubkey = WUSDC_MINT.parse()?;

    println!("получатель:  {}", recipient.pubkey());
    println!("на кошелёк:  {}", payer.pubkey());
    println!("обналичиваю: {amount_usdc} wUSDC → USDC");

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

    // USDC Token (для проверки vault ДО burn и для возврата на шаге 3).
    let usdc = Token::new(
        program_client.clone(),
        &spl_token::id(),
        &usdc_mint,
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );
    let vault_usdc = usdc.get_associated_token_address(&vault.pubkey());
    let payer_usdc = usdc.get_associated_token_address(&payer.pubkey());

    // Платёжеспособность vault: НЕ жжём wUSDC, если vault не покроет возврат.
    // Иначе burn пройдёт, а возврат упадёт — застрянет полусостояние.
    let vault_bal = usdc
        .get_account_info(&vault_usdc)
        .await
        .context("vault USDC info")?
        .base
        .amount;
    if vault_bal < amount {
        anyhow::bail!(
            "vault недоколлатерализован: {} USDC в vault < {amount_usdc} к возврату. \
             wUSDC не сжигаю. Обеспечь: только wrap минтит wUSDC (+vault), не демо-минт.",
            vault_bal as f64 / 1e6
        );
    }

    // Fee-payer = основной кошелёк; владелец CT = получатель.
    let wusdc = Token::new(
        program_client.clone(),
        &spl_token_2022::id(),
        &wusdc_mint,
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );
    // Supply-ключ mint'а создан основным кошельком (create_wusdc).
    let supply_elgamal = elgamal_from(&payer, b"tidex6-wusdc-supply-elgamal-v1")?;
    // Ключи получателя — те же домены, что задал configure_recipient.
    let recipient_elgamal = elgamal_from(&recipient, b"tidex6-wusdc-alice-elgamal-v1")?;
    let recipient_ae = ae_from(&recipient, b"tidex6-wusdc-alice-ae-v1")?;
    let recipient_ata = wusdc.get_associated_token_address(&recipient.pubkey());

    // ── 1. apply pending (перевод мувера лежит в pending) ────────────
    println!("\n[1/3] apply pending balance получателя…");
    wusdc
        .confidential_transfer_apply_pending_balance(
            &recipient_ata,
            &recipient.pubkey(),
            None,
            recipient_elgamal.secret(),
            &recipient_ae,
            &[&recipient],
        )
        .await
        .context("apply pending")?;

    // ── 2. Конфид-burn amount wUSDC получателя ───────────────────────
    println!("[2/3] конфид-burn {amount_usdc} wUSDC…");
    {
        let account_info = wusdc
            .get_account_info(&recipient_ata)
            .await
            .context("wUSDC info")?;
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
                &recipient_elgamal,
                &recipient_ae,
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
                &recipient.pubkey(),
                &recipient_ata,
                Some(&eq.pubkey()),
                Some(&val_ct),
                Some(&range.pubkey()),
                amount,
                &recipient_elgamal,
                supply_elgamal.pubkey(),
                None,
                &recipient_ae,
                None,
                &[&recipient],
            )
            .await
            .context("confidential burn")?;
        close_ctxs(&wusdc, &payer, &[&eq, &val, &range]).await?;
    }

    // ── 3. Возврат amount USDC из vault → основной кошелёк ───────────
    // usdc/vault_usdc/payer_usdc созданы выше (для pre-check платёжеспособности).
    println!("[3/3] возвращаю {amount_usdc} USDC из vault на кошелёк…");
    usdc.transfer(&vault_usdc, &payer_usdc, &vault.pubkey(), amount, &[&vault])
        .await
        .context("vault USDC → кошелёк")?;

    let usdc_bal = usdc.get_account_info(&payer_usdc).await?.base.amount;
    println!("\n══════ CASHOUT ГОТОВ ══════");
    println!("USDC на основном кошельке: {} USDC", usdc_bal as f64 / 1e6);
    println!("Круг замкнут: депозит → скрытый вывод на свежий адрес → обнал на твой кошелёк.");
    Ok(())
}

/// Сумма (micro) из sibling payout-<nh8>.json[.done] рядом с ключом получателя.
fn amount_from_sibling_payout(recipient_path: &str) -> Result<u64> {
    let nh8 = std::path::Path::new(recipient_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("recipient-"))
        .context("имя ключа не recipient-<nh8>.json")?
        .to_owned();
    let home = std::env::var("HOME").context("нет $HOME")?;
    let dir = format!("{home}/.tidex6-wusdc");
    for name in [format!("payout-{nh8}.json"), format!("payout-{nh8}.json.done")] {
        let path = format!("{dir}/{name}");
        if let Ok(raw) = std::fs::read_to_string(&path) {
            let needle = "\"amount\": ";
            if let Some(start) = raw.find(needle) {
                let rest = &raw[start + needle.len()..];
                let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                if let Ok(v) = rest[..end].parse::<u64>() {
                    return Ok(v);
                }
            }
        }
    }
    anyhow::bail!("не найден payout-{nh8}.json[.done] с суммой")
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
