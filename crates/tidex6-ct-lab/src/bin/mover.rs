//! Релеер-мувер: конфиденциально выплачивает wUSDC получателям по payout-запросам.
//!
//! Это «сшивка» двух слоёв. Groth16-пул уже проверил доказательство, сжёг
//! nullifier и (в полном виде) эмитил событие; `withdraw` положил payout-запрос
//! ~/.tidex6-wusdc/payout-<nh8>.json = {recipient, amount}. Мувер:
//!   1. читает каждый незакрытый payout-запрос;
//!   2. берёт ElGamal-pubkey получателя из его on-chain CT-аккаунта;
//!   3. делает CONFIDENTIAL transfer wUSDC (сумма скрыта) из аккаунта релеера;
//!   4. помечает запрос .done.
//!
//! Мувер видит (recipient, amount), но НЕ видит депозитора: связь deposit↔
//! withdraw скрыта Groth16-слоем. Он custodian wUSDC-флоата (как в MVP-плане:
//! «релеер видит суммы, он и так платит»). Ключи релеера — те же домены, что
//! у владельца в wrap (`tidex6-wusdc-alice-elgamal-v1` / `-ae-v1`).
//!
//! Получатель ДОЛЖЕН быть настроен заранее (configure_recipient) — иначе
//! запрос пропускается и повторится на следующем прогоне.
//!
//! Запуск: cargo run -p tidex6-ct-lab --bin mover [--release]

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalKeypair, ElGamalPubkey},
};
use spl_token_2022::extension::{
    confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::{ProofAccountWithCiphertext, Token},
};
use spl_token_client::zk_proofs::confidential_transfer::TransferAccountInfo;
use spl_token_confidential_transfer_proof_generation::transfer::TransferProofData;

const WUSDC_MINT: &str = "CckZq2kKW5yZwNjNmLwrGDDpHB7NsU2u3Zdhk3K6ZLbv";
const DECIMALS: u8 = 6;

type Client = Token<ProgramRpcClientSendTransaction>;

struct Payout {
    path: std::path::PathBuf,
    recipient: Pubkey,
    amount: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let relayer =
        read_keypair_file(&keypair_path).map_err(|e| anyhow::anyhow!("relayer keypair: {e}"))?;
    let mint_pubkey: Pubkey = WUSDC_MINT.parse().context("mint pubkey")?;

    println!("релеер (custodian): {}", relayer.pubkey());
    println!("wUSDC mint:         {mint_pubkey}");

    let payouts = scan_payouts()?;
    if payouts.is_empty() {
        println!("\nнет незакрытых payout-запросов — нечего платить.");
        return Ok(());
    }
    println!("\nнайдено payout-запросов: {}", payouts.len());

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
        Arc::new(relayer.insecure_clone()),
    );

    let relayer_elgamal = elgamal_from(&relayer, b"tidex6-wusdc-alice-elgamal-v1")?;
    let relayer_ae = ae_from(&relayer, b"tidex6-wusdc-alice-ae-v1")?;
    let relayer_ata = token.get_associated_token_address(&relayer.pubkey());

    let mut paid = 0usize;
    let mut skipped = 0usize;
    for p in &payouts {
        let nh8 = p
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_owned();
        println!(
            "\n── {} → {} ({} wUSDC)",
            nh8,
            p.recipient,
            p.amount as f64 / 1e6
        );
        match pay_one(
            &token,
            &relayer,
            &relayer_elgamal,
            &relayer_ae,
            &relayer_ata,
            p,
        )
        .await
        {
            Ok(sig) => {
                println!("   выплачено. tx: {sig}");
                mark_done(&p.path)?;
                paid += 1;
            }
            Err(e) => {
                println!("   пропуск: {e:#}");
                skipped += 1;
            }
        }
    }

    println!("\n═══ МУВЕР ЗАВЕРШИЛ ═══");
    println!("выплачено: {paid}, пропущено: {skipped}");
    if skipped > 0 {
        println!("Пропущенные — получатель ещё не настроен (configure_recipient) или иная ошибка; повторятся на следующем прогоне.");
    }
    Ok(())
}

/// Выплачивает один payout: CT-transfer amount от релеера получателю.
async fn pay_one(
    token: &Client,
    relayer: &Keypair,
    relayer_elgamal: &ElGamalKeypair,
    relayer_ae: &AeKey,
    relayer_ata: &Pubkey,
    p: &Payout,
) -> Result<String> {
    // ElGamal-pubkey получателя — из его on-chain CT-аккаунта.
    let recipient_ata = token.get_associated_token_address(&p.recipient);
    let recipient_info = token
        .get_account_info(&recipient_ata)
        .await
        .context("CT-аккаунт получателя не найден (нужен configure_recipient)")?;
    let recipient_ct = recipient_info
        .get_extension::<ConfidentialTransferAccount>()
        .context("у получателя нет ConfidentialTransferAccount (нужен configure_recipient)")?;
    let dest_pk: ElGamalPubkey = recipient_ct
        .elgamal_pubkey
        .try_into()
        .map_err(|e| anyhow::anyhow!("ElGamal-pubkey получателя: {e}"))?;

    // Proof-данные из CT-аккаунта релеера.
    let relayer_info = token
        .get_account_info(relayer_ata)
        .await
        .context("CT-аккаунт релеера не найден (нужен wrap)")?;
    let relayer_ct = relayer_info
        .get_extension::<ConfidentialTransferAccount>()
        .context("у релеера нет ConfidentialTransferAccount")?;
    let TransferProofData {
        equality_proof_data,
        ciphertext_validity_proof_data_with_ciphertext,
        range_proof_data,
    } = TransferAccountInfo::new(relayer_ct)
        .generate_split_transfer_proof_data(
            p.amount,
            relayer_elgamal,
            relayer_ae,
            &dest_pk,
            None,
        )
        .map_err(|e| anyhow::anyhow!("transfer proof: {e}"))?;

    let (eq, val, range) = (Keypair::new(), Keypair::new(), Keypair::new());
    create_ctx(token, relayer, &eq, &equality_proof_data, false).await?;
    create_ctx(
        token,
        relayer,
        &val,
        &ciphertext_validity_proof_data_with_ciphertext.proof_data,
        false,
    )
    .await?;
    create_ctx(token, relayer, &range, &range_proof_data, true).await?;
    let val_ct = ProofAccountWithCiphertext {
        context_state_account: val.pubkey(),
        ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
    };
    let sig = token
        .confidential_transfer_transfer(
            relayer_ata,
            &recipient_ata,
            &relayer.pubkey(),
            Some(&eq.pubkey()),
            Some(&val_ct),
            Some(&range.pubkey()),
            p.amount,
            None,
            relayer_elgamal,
            relayer_ae,
            &dest_pk,
            None,
            &[relayer],
        )
        .await
        .context("confidential transfer")?;
    close_ctxs(token, relayer, &[&eq, &val, &range]).await?;

    Ok(match sig {
        spl_token_client::client::RpcClientResponse::Signature(s) => s.to_string(),
        other => format!("{other:?}"),
    })
}

/// Читает все незакрытые ~/.tidex6-wusdc/payout-*.json.
fn scan_payouts() -> Result<Vec<Payout>> {
    let home = std::env::var("HOME").context("нет $HOME")?;
    let dir = std::path::PathBuf::from(format!("{home}/.tidex6-wusdc"));
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(out),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with("payout-") || !name.ends_with(".json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).context("читать payout")?;
        let recipient_str = json_str(&raw, "recipient")
            .with_context(|| format!("нет recipient в {name}"))?;
        let amount = json_num(&raw, "amount").with_context(|| format!("нет amount в {name}"))?;
        let recipient: Pubkey = recipient_str
            .parse()
            .with_context(|| format!("recipient не pubkey в {name}"))?;
        out.push(Payout {
            path,
            recipient,
            amount,
        });
    }
    Ok(out)
}

fn mark_done(path: &std::path::Path) -> Result<()> {
    let done = path.with_extension("json.done");
    std::fs::rename(path, done).context("пометить payout .done")?;
    Ok(())
}

fn json_str(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\": \"");
    let start = json.find(&needle)? + needle.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_owned())
}

fn json_num(json: &str, field: &str) -> Option<u64> {
    let needle = format!("\"{field}\": ");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
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
        .context("create context state")?;
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
