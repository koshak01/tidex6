//! MVP-демо на mainnet: конфиденциальный перевод wUSDC A→B со СКРЫТОЙ суммой.
//!
//! Использует постоянный wUSDC-mint (создан create_wusdc). Флоу:
//!   1. Alice (наш кошелёк) — настроить конфид-аккаунт wUSDC;
//!   2. конфид-минт 10 wUSDC → Alice (эмиссия скрыта);
//!   3. Bob (новый кошелёк) — настроить конфид-аккаунт;
//!   4. КОНФИД-ПЕРЕВОД 4 wUSDC Alice→Bob — сумма СКРЫТА на цепи;
//!   5. показать: on-chain шифры + расшифрованные суммы (Alice 6, Bob 4).
//!
//! Это пункт «закинуть с одного кошелька на другой, увидеть сумму скрытой».
//! Реальный wrap USDC↔wUSDC (обеспечение) — следующий шаг (wrap-программа);
//! здесь wUSDC минтится напрямую, чтобы показать скрытие суммы перевода.
//!
//! Ключи ElGamal/AE детерминированы из подписи кошелька-владельца
//! (`new_from_signature`) — восстановимы, не хранятся. Bob keypair
//! сохраняется в ~/.tidex6-wusdc/bob-keypair.json.
//!
//! Запуск: cargo run -p tidex6-ct-lab --bin wusdc_demo --release

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
use spl_token_confidential_transfer_proof_generation::{
    mint::MintProofData, transfer::TransferProofData,
};

const WUSDC_MINT: &str = "CckZq2kKW5yZwNjNmLwrGDDpHB7NsU2u3Zdhk3K6ZLbv";
const DECIMALS: u8 = 6;
const MINT_AMOUNT: u64 = 10_000_000; // 10 wUSDC
const TRANSFER_AMOUNT: u64 = 4_000_000; // 4 wUSDC → скрыто

type Client = Token<ProgramRpcClientSendTransaction>;

#[tokio::main]
async fn main() -> Result<()> {
    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow::anyhow!("keypair не прочитан: {e}"))?;
    let mint_pubkey: Pubkey = WUSDC_MINT.parse().context("mint pubkey")?;
    println!("payer/Alice: {}", payer.pubkey());
    println!("wUSDC mint:  {mint_pubkey}");

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

    // ── Ключи ────────────────────────────────────────────────────────
    let supply_elgamal = elgamal_from(&payer, b"tidex6-wusdc-supply-elgamal-v1")?;
    let mint_ae = ae_from(&payer, b"tidex6-wusdc-supply-ae-v1")?;
    let alice_elgamal = elgamal_from(&payer, b"tidex6-wusdc-alice-elgamal-v1")?;
    let alice_ae = ae_from(&payer, b"tidex6-wusdc-alice-ae-v1")?;

    // Bob — новый кошелёк, сохраняем.
    let home = std::env::var("HOME").context("нет $HOME")?;
    let bob_path = format!("{home}/.tidex6-wusdc/bob-keypair.json");
    let bob = Keypair::new();
    write_keypair_file(&bob, &bob_path).map_err(|e| anyhow::anyhow!("bob keypair: {e}"))?;
    let bob_elgamal = elgamal_from(&bob, b"tidex6-wusdc-owner-elgamal-v1")?;
    let bob_ae = ae_from(&bob, b"tidex6-wusdc-owner-ae-v1")?;
    println!("Bob:         {} (keypair: {bob_path})", bob.pubkey());

    // ── 1. Alice: конфид-аккаунт ─────────────────────────────────────
    println!("\n[1/5] настраиваю конфид-аккаунт Alice…");
    token
        .create_associated_token_account(&payer.pubkey())
        .await
        .ok();
    let alice_ata = token.get_associated_token_address(&payer.pubkey());
    token
        .reallocate(
            &alice_ata,
            &payer.pubkey(),
            &[ExtensionType::ConfidentialTransferAccount],
            &[&payer],
        )
        .await
        .context("reallocate Alice")?;
    token
        .confidential_transfer_configure_token_account(
            &alice_ata,
            &payer.pubkey(),
            None,
            None,
            &alice_elgamal,
            &alice_ae,
            &[&payer],
        )
        .await
        .context("configure Alice")?;
    println!("  Alice ATA: {alice_ata}");

    // ── 2. Конфид-минт 10 wUSDC → Alice ──────────────────────────────
    println!(
        "\n[2/5] конфид-минт {} wUSDC → Alice…",
        MINT_AMOUNT / 1_000_000
    );
    {
        let mint_info = token.get_mint_info().await.context("mint info")?;
        let supply_ext = mint_info
            .get_extension::<ConfidentialMintBurn>()
            .context("нет ConfidentialMintBurn")?;
        let MintProofData {
            equality_proof_data,
            ciphertext_validity_proof_data_with_ciphertext,
            range_proof_data,
        } = SupplyAccountInfo::new(supply_ext)
            .generate_split_mint_proof_data(
                MINT_AMOUNT,
                &supply_elgamal,
                &mint_ae,
                alice_elgamal.pubkey(),
                None,
            )
            .map_err(|e| anyhow::anyhow!("mint proof: {e}"))?;
        let (eq, val, range) = (Keypair::new(), Keypair::new(), Keypair::new());
        create_ctx(&token, &payer, &eq, &equality_proof_data, false).await?;
        create_ctx(
            &token,
            &payer,
            &val,
            &ciphertext_validity_proof_data_with_ciphertext.proof_data,
            false,
        )
        .await?;
        create_ctx(&token, &payer, &range, &range_proof_data, true).await?;
        let val_ct = ProofAccountWithCiphertext {
            context_state_account: val.pubkey(),
            ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
            ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        };
        token
            .confidential_transfer_mint(
                &payer.pubkey(),
                &alice_ata,
                Some(&eq.pubkey()),
                Some(&val_ct),
                Some(&range.pubkey()),
                MINT_AMOUNT,
                &supply_elgamal,
                alice_elgamal.pubkey(),
                None,
                &mint_ae,
                None,
                &[&payer],
            )
            .await
            .context("confidential mint")?;
        close_ctxs(&token, &payer, &[&eq, &val, &range]).await?;
    }
    token
        .confidential_transfer_apply_pending_balance(
            &alice_ata,
            &payer.pubkey(),
            None,
            alice_elgamal.secret(),
            &alice_ae,
            &[&payer],
        )
        .await
        .context("apply Alice")?;

    // ── 3. Bob: конфид-аккаунт (payer платит fee) ────────────────────
    println!("\n[3/5] настраиваю конфид-аккаунт Bob…");
    token
        .create_associated_token_account(&bob.pubkey())
        .await
        .ok();
    let bob_ata = token.get_associated_token_address(&bob.pubkey());
    token
        .reallocate(
            &bob_ata,
            &bob.pubkey(),
            &[ExtensionType::ConfidentialTransferAccount],
            &[&payer, &bob],
        )
        .await
        .context("reallocate Bob")?;
    token
        .confidential_transfer_configure_token_account(
            &bob_ata,
            &bob.pubkey(),
            None,
            None,
            &bob_elgamal,
            &bob_ae,
            &[&payer, &bob],
        )
        .await
        .context("configure Bob")?;
    println!("  Bob ATA:   {bob_ata}");

    // ── 4. КОНФИД-ПЕРЕВОД 4 wUSDC Alice→Bob (сумма скрыта) ───────────
    println!(
        "\n[4/5] КОНФИД-ПЕРЕВОД {} wUSDC Alice→Bob (сумма СКРЫТА)…",
        TRANSFER_AMOUNT / 1_000_000
    );
    let transfer_sig;
    {
        let account_info = token
            .get_account_info(&alice_ata)
            .await
            .context("Alice info")?;
        let ct_ext = account_info
            .get_extension::<ConfidentialTransferAccount>()
            .context("нет CT")?;
        let TransferProofData {
            equality_proof_data,
            ciphertext_validity_proof_data_with_ciphertext,
            range_proof_data,
        } = spl_token_client::zk_proofs::confidential_transfer::TransferAccountInfo::new(ct_ext)
            .generate_split_transfer_proof_data(
                TRANSFER_AMOUNT,
                &alice_elgamal,
                &alice_ae,
                bob_elgamal.pubkey(),
                None,
            )
            .map_err(|e| anyhow::anyhow!("transfer proof: {e}"))?;
        let (eq, val, range) = (Keypair::new(), Keypair::new(), Keypair::new());
        create_ctx(&token, &payer, &eq, &equality_proof_data, false).await?;
        create_ctx(
            &token,
            &payer,
            &val,
            &ciphertext_validity_proof_data_with_ciphertext.proof_data,
            false,
        )
        .await?;
        create_ctx(&token, &payer, &range, &range_proof_data, true).await?;
        let val_ct = ProofAccountWithCiphertext {
            context_state_account: val.pubkey(),
            ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
            ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        };
        transfer_sig = token
            .confidential_transfer_transfer(
                &alice_ata,
                &bob_ata,
                &payer.pubkey(),
                Some(&eq.pubkey()),
                Some(&val_ct),
                Some(&range.pubkey()),
                TRANSFER_AMOUNT,
                None,
                &alice_elgamal,
                &alice_ae,
                bob_elgamal.pubkey(),
                None,
                &[&payer],
            )
            .await
            .context("confidential transfer")?;
        close_ctxs(&token, &payer, &[&eq, &val, &range]).await?;
    }
    token
        .confidential_transfer_apply_pending_balance(
            &bob_ata,
            &bob.pubkey(),
            None,
            bob_elgamal.secret(),
            &bob_ae,
            &[&payer, &bob],
        )
        .await
        .context("apply Bob")?;

    // ── 5. Итог ──────────────────────────────────────────────────────
    println!("\n══════ РЕЗУЛЬТАТ ══════");
    println!("Перевод tx: {transfer_sig:?}");
    if let spl_token_client::client::RpcClientResponse::Signature(sig) = &transfer_sig {
        println!("Solscan:    https://solscan.io/tx/{sig}");
    }
    show(&token, "Alice", &alice_ata, &alice_ae).await?;
    show(&token, "Bob", &bob_ata, &bob_ae).await?;
    println!("\nНа цепи сумма перевода = шифр; расшифровать может только владелец ключа.");
    Ok(())
}

/// Создаёт proof-context-аккаунт (range требует split=true).
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

/// Закрывает proof-context-аккаунты, rent → payer.
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

/// Печатает публичный + конфиденциальный (расшифрованный) баланс.
async fn show(token: &Client, who: &str, ata: &Pubkey, ae: &AeKey) -> Result<()> {
    let info = token.get_account_info(ata).await.context("account info")?;
    let ct = info
        .get_extension::<ConfidentialTransferAccount>()
        .context("нет CT")?;
    let plain: Option<u64> = ae.decrypt(&ct.decryptable_available_balance.try_into()?);
    println!(
        "{who}: публичный={}  конфид(расшифровано владельцем)={} wUSDC",
        info.base.amount,
        plain.map(|v| v as f64 / 1e6).unwrap_or(-1.0)
    );
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
