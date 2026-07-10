//! CT-операции (Token-2022 Confidential Transfer) как lib-функции для
//! unified-сервиса: wrap / configure_recipient / mover / cashout. Логика
//! перенесена из одноимённых бинов; вместо println вывод копится в String
//! и возвращается (сервис отдаёт его по IPC). Без спавна подпроцессов.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use solana_keypair::{read_keypair_file, write_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalKeypair, ElGamalPubkey},
};
use spl_token_2022::extension::{
    confidential_mint_burn::ConfidentialMintBurn,
    confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions, ExtensionType,
};
use spl_token_client::client::{ProgramRpcClient, ProgramRpcClientSendTransaction};
use spl_token_client::token::{ProofAccountWithCiphertext, Token};
use spl_token_client::zk_proofs::confidential_mint_burn::{BurnAccountInfo, SupplyAccountInfo};
use spl_token_client::zk_proofs::confidential_transfer::TransferAccountInfo;
use spl_token_confidential_transfer_proof_generation::burn::BurnProofData;
use spl_token_confidential_transfer_proof_generation::mint::MintProofData;
use spl_token_confidential_transfer_proof_generation::transfer::TransferProofData;

// Минты берём из единого реестра `tidex6_core::network` по АКТИВНЫМ сети+активу
// (config.network/asset → active_network()/active_asset()).
/// Символы (underlying, wrapped) активного актива — для сообщений, чтобы не
/// хардкодить «USDC» независимо от того, что реально в работе.
fn symbols() -> (&'static str, &'static str) {
    match crate::config::active_asset() {
        tidex6_core::network::Asset::Wusdt => ("USDT", "wUSDT"),
        _ => ("USDC", "wUSDC"),
    }
}

// Минты: сперва config-оверрайд (per-окружение, под оператора машины), иначе
// дефолт из реестра tidex6-core::network.
pub fn usdc_mint() -> String {
    let net = crate::config::active_network();
    let asset = crate::config::active_asset();
    crate::config::mint_underlying(net, asset)
        .or_else(|| {
            net.asset(asset)
                .and_then(|a| a.underlying_mint)
                .map(str::to_string)
        })
        .expect("underlying mint (config override or registry)")
}
fn wusdc_mint() -> String {
    let net = crate::config::active_network();
    let asset = crate::config::active_asset();
    crate::config::mint_wrapped(net, asset)
        .or_else(|| {
            net.asset(asset)
                .and_then(|a| a.wrapped_mint)
                .map(str::to_string)
        })
        .expect("wrapped mint (config override or registry)")
}
const DECIMALS: u8 = 6;

type TokenClient = Token<ProgramRpcClientSendTransaction>;

fn program_client(rpc: Arc<RpcClient>) -> Arc<ProgramRpcClient<ProgramRpcClientSendTransaction>> {
    Arc::new(ProgramRpcClient::new(rpc, ProgramRpcClientSendTransaction))
}

fn token(
    pc: Arc<ProgramRpcClient<ProgramRpcClientSendTransaction>>,
    program: &Pubkey,
    mint: &Pubkey,
    payer: &Keypair,
) -> TokenClient {
    Token::new(
        pc,
        program,
        mint,
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    )
}

fn dir() -> Result<String> {
    let home = std::env::var("HOME").context("нет $HOME")?;
    Ok(format!("{home}/.tidex6-wusdc"))
}

// ── wrap: USDC → wUSDC (перевод в vault + конфид-минт) ─────────────────
pub async fn wrap(rpc: Arc<RpcClient>, payer: &Keypair, amount: u64) -> Result<String> {
    let mut out = String::new();
    let (u, w) = symbols();
    let usdc_mint: Pubkey = usdc_mint().parse()?;
    let wusdc_mint: Pubkey = wusdc_mint().parse()?;
    let pc = program_client(rpc);
    writeln!(out, "wrapping: {} {u} → {w}", amount as f64 / 1e6)?;

    let vault_path = format!("{}/vault-keypair.json", dir()?);
    let vault = if std::path::Path::new(&vault_path).exists() {
        read_keypair_file(&vault_path).map_err(|e| anyhow!("vault keypair: {e}"))?
    } else {
        std::fs::DirBuilder::new()
            .recursive(true)
            .create(dir()?)
            .ok();
        let v = Keypair::new();
        write_keypair_file(&v, &vault_path).map_err(|e| anyhow!("vault save: {e}"))?;
        v
    };

    let usdc = token(pc.clone(), &spl_token::id(), &usdc_mint, payer);
    let payer_usdc = usdc.get_associated_token_address(&payer.pubkey());
    let vault_usdc = usdc.get_associated_token_address(&vault.pubkey());
    // Создать vault-ATA если её нет + ДОЖДАТЬСЯ видимости на RPC. Helius
    // балансирует ноды — свежесозданный аккаунт может не сразу отразиться, и
    // немедленный transfer падает InvalidAccountData (на проде vault свежий).
    // Ошибку создания пробрасываем (не глотаем `.ok()` — иначе теряем причину).
    if usdc.get_account_info(&vault_usdc).await.is_err() {
        usdc.create_associated_token_account(&vault.pubkey())
            .await
            .map_err(|e| anyhow!("create vault ATA: {e}"))?;
        for _ in 0..20 {
            if usdc.get_account_info(&vault_usdc).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    // Precheck: у оператора должен быть реальный underlying на ATA. Без этого
    // transfer ниже падает непонятным InvalidAccountData — даём прямую причину
    // (какой кошелёк, какой токен, сколько нужно), а не сырую RPC-ошибку.
    match usdc.get_account_info(&payer_usdc).await {
        Ok(acc) if acc.base.amount >= amount => {}
        Ok(acc) => bail!(
            "оператору {} не хватает {u}: на кошельке {:.6}, нужно {:.6}. \
             Пополни оператор-кошелёк реальным {u} (mint {usdc_mint}).",
            payer.pubkey(),
            acc.base.amount as f64 / 1e6,
            amount as f64 / 1e6,
        ),
        Err(_) => bail!(
            "у оператора {} нет {u} — token-аккаунт не создан. \
             Пополни оператор-кошелёк реальным {u} (mint {usdc_mint}), хотя бы {:.6}.",
            payer.pubkey(),
            amount as f64 / 1e6,
        ),
    }
    writeln!(out, "[1/3] transfer {u} → vault…")?;
    usdc.transfer(&payer_usdc, &vault_usdc, &payer.pubkey(), amount, &[payer])
        .await
        .context("USDC → vault")?;

    let wusdc = token(pc, &spl_token_2022::id(), &wusdc_mint, payer);
    let supply_elgamal = elgamal_from(payer, b"tidex6-wusdc-supply-elgamal-v1")?;
    let mint_ae = ae_from(payer, b"tidex6-wusdc-supply-ae-v1")?;
    let owner_elgamal = elgamal_from(payer, b"tidex6-wusdc-alice-elgamal-v1")?;
    let owner_ae = ae_from(payer, b"tidex6-wusdc-alice-ae-v1")?;

    writeln!(
        out,
        "[2/3] configuring confidential {w} account (if needed)…"
    )?;
    wusdc
        .create_associated_token_account(&payer.pubkey())
        .await
        .ok();
    let owner_ata = wusdc.get_associated_token_address(&payer.pubkey());
    // Дождаться видимости свежесозданной ATA на RPC (Helius node-lag) — иначе
    // reallocate ниже падает InvalidAccountData (на проде owner_ata свежий).
    for _ in 0..20 {
        if wusdc.get_account_info(&owner_ata).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
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
                &[payer],
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
                &[payer],
            )
            .await
            .context("configure")?;
    }

    writeln!(out, "[3/3] confidential mint {w} → wallet…")?;
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
            .map_err(|e| anyhow!("mint proof: {e}"))?;
        let (eq, val, range) = (Keypair::new(), Keypair::new(), Keypair::new());
        // 3 proof-context аккаунта — ПАРАЛЛЕЛЬНО (независимы) вместо последовательно.
        // Ускоряет CT-операцию: 3 подтверждения идут разом, не по очереди.
        let (r_eq, r_val, r_range) = tokio::join!(
            create_ctx(&wusdc, payer, &eq, &equality_proof_data, false),
            create_ctx(
                &wusdc,
                payer,
                &val,
                &ciphertext_validity_proof_data_with_ciphertext.proof_data,
                false
            ),
            create_ctx(&wusdc, payer, &range, &range_proof_data, true),
        );
        r_eq?;
        r_val?;
        r_range?;
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
                &[payer],
            )
            .await
            .context("confidential mint")?;
        close_ctxs(&wusdc, payer, &[&eq, &val, &range]).await?;
    }
    wusdc
        .confidential_transfer_apply_pending_balance(
            &owner_ata,
            &payer.pubkey(),
            None,
            owner_elgamal.secret(),
            &owner_ae,
            &[payer],
        )
        .await
        .context("apply")?;

    let vault_bal = usdc.get_account_info(&vault_usdc).await?.base.amount;
    writeln!(out, "\n══════ WRAP DONE ══════")?;
    writeln!(out, "vault {u} (backing): {} {u}", vault_bal as f64 / 1e6)?;
    Ok(out)
}

// ── configure_recipient: настроить CT-аккаунт свежего получателя ──────
pub async fn configure_recipient(
    rpc: Arc<RpcClient>,
    payer: &Keypair,
    recipient_path: &str,
) -> Result<String> {
    let mut out = String::new();
    let recipient_path = crate::flow::safe_tidex6_file(recipient_path, "recipient-")?;
    let recipient = read_keypair_file(&recipient_path).map_err(|e| anyhow!("recipient: {e}"))?;
    let wusdc_mint: Pubkey = wusdc_mint().parse()?;
    let wusdc = token(
        program_client(rpc),
        &spl_token_2022::id(),
        &wusdc_mint,
        payer,
    );

    let recipient_elgamal = elgamal_from(&recipient, b"tidex6-wusdc-alice-elgamal-v1")?;
    let recipient_ae = ae_from(&recipient, b"tidex6-wusdc-alice-ae-v1")?;
    let ata = wusdc.get_associated_token_address(&recipient.pubkey());
    writeln!(out, "recipient: {}\nATA: {ata}", recipient.pubkey())?;

    if let Ok(info) = wusdc.get_account_info(&ata).await {
        if info.get_extension::<ConfidentialTransferAccount>().is_ok() {
            writeln!(out, "CT account already configured.")?;
            return Ok(out);
        }
    }
    writeln!(out, "[1/3] creating ATA…")?;
    wusdc
        .create_associated_token_account(&recipient.pubkey())
        .await
        .ok();
    writeln!(out, "[2/3] reallocate…")?;
    wusdc
        .reallocate(
            &ata,
            &recipient.pubkey(),
            &[ExtensionType::ConfidentialTransferAccount],
            &[payer, &recipient],
        )
        .await
        .context("reallocate получателя")?;
    writeln!(out, "[3/3] configure…")?;
    wusdc
        .confidential_transfer_configure_token_account(
            &ata,
            &recipient.pubkey(),
            None,
            None,
            &recipient_elgamal,
            &recipient_ae,
            &[payer, &recipient],
        )
        .await
        .context("configure recipient")?;
    writeln!(out, "RECIPIENT READY.")?;
    Ok(out)
}

// ── mover: выплата wUSDC по payout-запросам ───────────────────────────
pub async fn mover(rpc: Arc<RpcClient>, payer: &Keypair) -> Result<String> {
    let mut out = String::new();
    let (_, w) = symbols();
    let wusdc_mint: Pubkey = wusdc_mint().parse()?;
    let wusdc = token(
        program_client(rpc),
        &spl_token_2022::id(),
        &wusdc_mint,
        payer,
    );
    let relayer_elgamal = elgamal_from(payer, b"tidex6-wusdc-alice-elgamal-v1")?;
    let relayer_ae = ae_from(payer, b"tidex6-wusdc-alice-ae-v1")?;
    let relayer_ata = wusdc.get_associated_token_address(&payer.pubkey());

    let payouts = scan_payouts()?;
    if payouts.is_empty() {
        writeln!(out, "no open payout requests.")?;
        return Ok(out);
    }
    writeln!(out, "payout requests: {}", payouts.len())?;
    let mut paid = 0usize;
    for (path, recipient, amount) in &payouts {
        writeln!(out, "\n── {recipient} ({} {w})", *amount as f64 / 1e6)?;
        match pay_one(
            &wusdc,
            payer,
            &relayer_elgamal,
            &relayer_ae,
            &relayer_ata,
            recipient,
            *amount,
        )
        .await
        {
            Ok(sig) => {
                writeln!(out, "   paid. tx: {sig}")?;
                let done = format!("{}.done", path.to_string_lossy());
                std::fs::rename(path, done).ok();
                paid += 1;
            }
            Err(e) => writeln!(out, "   skipped: {e:#}")?,
        }
    }
    writeln!(out, "\npaid: {paid}")?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn pay_one(
    wusdc: &TokenClient,
    payer: &Keypair,
    relayer_elgamal: &ElGamalKeypair,
    relayer_ae: &AeKey,
    relayer_ata: &Pubkey,
    recipient: &Pubkey,
    amount: u64,
) -> Result<String> {
    let recipient_ata = wusdc.get_associated_token_address(recipient);
    let recipient_info = wusdc
        .get_account_info(&recipient_ata)
        .await
        .context("CT-аккаунт получателя не найден (configure_recipient)")?;
    let recipient_ct = recipient_info
        .get_extension::<ConfidentialTransferAccount>()
        .context("нет ConfidentialTransferAccount у получателя")?;
    let dest_pk: ElGamalPubkey = recipient_ct
        .elgamal_pubkey
        .try_into()
        .map_err(|e| anyhow!("ElGamal-pubkey получателя: {e}"))?;

    let relayer_info = wusdc
        .get_account_info(relayer_ata)
        .await
        .context("relayer info")?;
    let relayer_ct = relayer_info
        .get_extension::<ConfidentialTransferAccount>()
        .context("нет CT у релеера")?;
    let TransferProofData {
        equality_proof_data,
        ciphertext_validity_proof_data_with_ciphertext,
        range_proof_data,
    } = TransferAccountInfo::new(relayer_ct)
        .generate_split_transfer_proof_data(amount, relayer_elgamal, relayer_ae, &dest_pk, None)
        .map_err(|e| anyhow!("transfer proof: {e}"))?;
    let (eq, val, range) = (Keypair::new(), Keypair::new(), Keypair::new());
    // 3 proof-context аккаунта — ПАРАЛЛЕЛЬНО (независимы).
    let (r_eq, r_val, r_range) = tokio::join!(
        create_ctx(wusdc, payer, &eq, &equality_proof_data, false),
        create_ctx(
            wusdc,
            payer,
            &val,
            &ciphertext_validity_proof_data_with_ciphertext.proof_data,
            false
        ),
        create_ctx(wusdc, payer, &range, &range_proof_data, true),
    );
    r_eq?;
    r_val?;
    r_range?;
    let val_ct = ProofAccountWithCiphertext {
        context_state_account: val.pubkey(),
        ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
    };
    let sig = wusdc
        .confidential_transfer_transfer(
            relayer_ata,
            &recipient_ata,
            &payer.pubkey(),
            Some(&eq.pubkey()),
            Some(&val_ct),
            Some(&range.pubkey()),
            amount,
            None,
            relayer_elgamal,
            relayer_ae,
            &dest_pk,
            None,
            &[payer],
        )
        .await
        .context("confidential transfer")?;
    close_ctxs(wusdc, payer, &[&eq, &val, &range]).await?;
    Ok(match sig {
        spl_token_client::client::RpcClientResponse::Signature(s) => s.to_string(),
        other => format!("{other:?}"),
    })
}

fn scan_payouts() -> Result<Vec<(std::path::PathBuf, Pubkey, u64)>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir()?) {
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
        let raw = std::fs::read_to_string(&path).context("payout")?;
        let recipient: Pubkey = json_str(&raw, "recipient")
            .and_then(|s| s.parse().ok())
            .with_context(|| format!("recipient в {name}"))?;
        let amount = json_num(&raw, "amount").with_context(|| format!("amount в {name}"))?;
        out.push((path, recipient, amount));
    }
    Ok(out)
}

// ── cashout: получатель → USDC на основной кошелёк ────────────────────
pub async fn cashout(rpc: Arc<RpcClient>, payer: &Keypair, recipient_path: &str) -> Result<String> {
    let mut out = String::new();
    let recipient_path = crate::flow::safe_tidex6_file(recipient_path, "recipient-")?;
    let recipient = read_keypair_file(&recipient_path).map_err(|e| anyhow!("recipient: {e}"))?;
    let amount = amount_from_sibling_payout(&recipient_path)?;
    let (u, w) = symbols();
    let usdc_mint: Pubkey = usdc_mint().parse()?;
    let wusdc_mint: Pubkey = wusdc_mint().parse()?;
    let pc = program_client(rpc);
    writeln!(out, "cashing out: {} {w} → {u}", amount as f64 / 1e6)?;

    let vault = read_keypair_file(format!("{}/vault-keypair.json", dir()?))
        .map_err(|e| anyhow!("vault keypair: {e}"))?;
    let usdc = token(pc.clone(), &spl_token::id(), &usdc_mint, payer);
    let vault_usdc = usdc.get_associated_token_address(&vault.pubkey());
    let payer_usdc = usdc.get_associated_token_address(&payer.pubkey());
    let vault_bal = usdc
        .get_account_info(&vault_usdc)
        .await
        .context("vault USDC info")?
        .base
        .amount;
    if vault_bal < amount {
        bail!(
            "vault undercollateralized: {} USDC < {} — not burning.",
            vault_bal as f64 / 1e6,
            amount as f64 / 1e6
        );
    }

    let wusdc = token(pc, &spl_token_2022::id(), &wusdc_mint, payer);
    let supply_elgamal = elgamal_from(payer, b"tidex6-wusdc-supply-elgamal-v1")?;
    let recipient_elgamal = elgamal_from(&recipient, b"tidex6-wusdc-alice-elgamal-v1")?;
    let recipient_ae = ae_from(&recipient, b"tidex6-wusdc-alice-ae-v1")?;
    let recipient_ata = wusdc.get_associated_token_address(&recipient.pubkey());

    writeln!(out, "[1/3] apply pending balance…")?;
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

    writeln!(out, "[2/3] confidential burn…")?;
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
            .map_err(|e| anyhow!("burn proof: {e}"))?;
        let (eq, val, range) = (Keypair::new(), Keypair::new(), Keypair::new());
        // 3 proof-context аккаунта — ПАРАЛЛЕЛЬНО (независимы) вместо последовательно.
        // Ускоряет CT-операцию: 3 подтверждения идут разом, не по очереди.
        let (r_eq, r_val, r_range) = tokio::join!(
            create_ctx(&wusdc, payer, &eq, &equality_proof_data, false),
            create_ctx(
                &wusdc,
                payer,
                &val,
                &ciphertext_validity_proof_data_with_ciphertext.proof_data,
                false
            ),
            create_ctx(&wusdc, payer, &range, &range_proof_data, true),
        );
        r_eq?;
        r_val?;
        r_range?;
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
        close_ctxs(&wusdc, payer, &[&eq, &val, &range]).await?;
    }

    writeln!(out, "[3/3] vault → wallet…")?;
    usdc.transfer(&vault_usdc, &payer_usdc, &vault.pubkey(), amount, &[&vault])
        .await
        .context("vault USDC → wallet")?;
    let usdc_bal = usdc.get_account_info(&payer_usdc).await?.base.amount;
    writeln!(
        out,
        "\n══════ CASHOUT DONE ══════\n{u} on wallet: {} {u}",
        usdc_bal as f64 / 1e6
    )?;
    Ok(out)
}

// ── cashout_to_address: оператор → USDC на ВНЕШНИЙ адрес (браузерный вывод) ──
/// Выплата после браузерного withdraw: жжём `amount` wUSDC с CT-аккаунта
/// ОПЕРАТОРА (его баланс = backing депозитов) и отпускаем `amount` USDC из
/// vault на внешний адрес получателя (обычный SPL-перевод — на свежий адрес
/// сумма становится видимой, но связь с депозитом скрыта пулом).
pub async fn cashout_to_address(
    rpc: Arc<RpcClient>,
    payer: &Keypair,
    recipient: &Pubkey,
    amount: u64,
) -> Result<String> {
    let mut out = String::new();
    let (u, w) = symbols();
    let usdc_mint: Pubkey = usdc_mint().parse()?;
    let wusdc_mint: Pubkey = wusdc_mint().parse()?;
    let pc = program_client(rpc);
    writeln!(
        out,
        "cashing out: {} {w} → {u} to {recipient}",
        amount as f64 / 1e6
    )?;

    let vault = read_keypair_file(format!("{}/vault-keypair.json", dir()?))
        .map_err(|e| anyhow!("vault keypair: {e}"))?;
    let usdc = token(pc.clone(), &spl_token::id(), &usdc_mint, payer);
    let vault_usdc = usdc.get_associated_token_address(&vault.pubkey());
    let vault_bal = usdc
        .get_account_info(&vault_usdc)
        .await
        .context("vault USDC info")?
        .base
        .amount;
    if vault_bal < amount {
        bail!(
            "vault undercollateralized: {} {u} < {} — not paying out.",
            vault_bal as f64 / 1e6,
            amount as f64 / 1e6
        );
    }

    // Источник wUSDC — CT-аккаунт оператора (те же ключи, что при wrap-минте).
    let wusdc = token(pc.clone(), &spl_token_2022::id(), &wusdc_mint, payer);
    let supply_elgamal = elgamal_from(payer, b"tidex6-wusdc-supply-elgamal-v1")?;
    let owner_elgamal = elgamal_from(payer, b"tidex6-wusdc-alice-elgamal-v1")?;
    let owner_ae = ae_from(payer, b"tidex6-wusdc-alice-ae-v1")?;
    let owner_ata = wusdc.get_associated_token_address(&payer.pubkey());

    writeln!(out, "[1/3] apply pending (operator)…")?;
    wusdc
        .confidential_transfer_apply_pending_balance(
            &owner_ata,
            &payer.pubkey(),
            None,
            owner_elgamal.secret(),
            &owner_ae,
            &[payer],
        )
        .await
        .context("apply pending")?;

    writeln!(out, "[2/3] confidential burn {w}…")?;
    {
        let account_info = wusdc
            .get_account_info(&owner_ata)
            .await
            .context("wUSDC info")?;
        let ct = account_info
            .get_extension::<ConfidentialTransferAccount>()
            .context("нет CT у оператора")?;
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
            .map_err(|e| anyhow!("burn proof: {e}"))?;
        let (eq, val, range) = (Keypair::new(), Keypair::new(), Keypair::new());
        let (r_eq, r_val, r_range) = tokio::join!(
            create_ctx(&wusdc, payer, &eq, &equality_proof_data, false),
            create_ctx(
                &wusdc,
                payer,
                &val,
                &ciphertext_validity_proof_data_with_ciphertext.proof_data,
                false
            ),
            create_ctx(&wusdc, payer, &range, &range_proof_data, true),
        );
        r_eq?;
        r_val?;
        r_range?;
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
                &[payer],
            )
            .await
            .context("confidential burn")?;
        close_ctxs(&wusdc, payer, &[&eq, &val, &range]).await?;
    }

    writeln!(out, "[3/3] vault → recipient {u}…")?;
    usdc.create_associated_token_account(recipient).await.ok();
    let recipient_usdc = usdc.get_associated_token_address(recipient);
    usdc.transfer(
        &vault_usdc,
        &recipient_usdc,
        &vault.pubkey(),
        amount,
        &[&vault],
    )
    .await
    .context("vault USDC → recipient")?;
    let recip_bal = usdc.get_account_info(&recipient_usdc).await?.base.amount;
    writeln!(
        out,
        "\n══════ PAYOUT DONE ══════\n{recipient}: {} {u}",
        recip_bal as f64 / 1e6
    )?;
    Ok(out)
}

fn amount_from_sibling_payout(recipient_path: &str) -> Result<u64> {
    let nh8 = std::path::Path::new(recipient_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("recipient-"))
        .context("имя ключа не recipient-<nh8>.json")?
        .to_owned();
    let d = dir()?;
    for name in [
        format!("payout-{nh8}.json"),
        format!("payout-{nh8}.json.done"),
    ] {
        if let Ok(raw) = std::fs::read_to_string(format!("{d}/{name}")) {
            if let Some(v) = json_num(&raw, "amount") {
                return Ok(v);
            }
        }
    }
    bail!("не найден payout-{nh8}.json[.done]")
}

// ── общие CT-хелперы ──────────────────────────────────────────────────
async fn create_ctx<ZK, U>(
    token: &TokenClient,
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

async fn close_ctxs(token: &TokenClient, payer: &Keypair, ctxs: &[&Keypair]) -> Result<()> {
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

// legacy-KDF намеренно: им созданы ключи существующего wUSDC-mint и все
// on-chain балансы; новый KDF вывел бы ДРУГИЕ ключи и всё сломал.
#[allow(deprecated)]
fn elgamal_from(signer: &Keypair, msg: &[u8]) -> Result<ElGamalKeypair> {
    ElGamalKeypair::new_from_signature_legacy(&signer.sign_message(msg))
        .map_err(|e| anyhow!("elgamal: {e}"))
}

#[allow(deprecated)]
fn ae_from(signer: &Keypair, msg: &[u8]) -> Result<AeKey> {
    AeKey::new_from_signature_legacy(&signer.sign_message(msg)).map_err(|e| anyhow!("ae: {e}"))
}

fn json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\": \"");
    let start = json.find(&needle)? + needle.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_owned())
}

fn json_num(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\": ");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}
