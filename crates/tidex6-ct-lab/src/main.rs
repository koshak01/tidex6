//! tidex6-ct-lab — mainnet-спайк confidential_mint_burn (wrap-механика wUSDC).
//!
//! Проверяет цепочку, на которой строится wrap-USDC:
//! 1. минт с ConfidentialTransferMint (+ auditor) и ConfidentialMintBurn —
//!    supply токена ШИФРУЕТСЯ, публичного supply нет вообще;
//! 2. конфиденциальный mint (сумма эмиссии скрыта) прямо в pending-баланс;
//! 3. apply_pending_balance — приём в available;
//! 4. конфиденциальный burn (сумма сжигания скрыта).
//!
//! В wrap-USDC этот mint/burn делает PDA-authority программы-обёртки:
//! завёл USDC в vault → конфид-минт wUSDC 1:1; вывод — конфид-burn + отдача
//! USDC из vault. Спайк выполняет те же инструкции от обычного кошелька.
//!
//! Проофы mint/burn (equality + ciphertext-validity + range U128) не влезают
//! в одну транзакцию (3136 байт > 1232), поэтому используется штатный
//! context-state паттерн: каждый proof заранее верифицируется программой
//! ZkE1Gama1Proof в отдельный context-аккаунт, инструкция ссылается на них,
//! после — аккаунты закрываются (rent возвращается payer'у). Референс —
//! официальный тест spl-token-client tests/confidential_mint_burn.rs.
//!
//! Ключи ElGamal/AES здесь эфемерные (new_rand) — токен одноразовый,
//! состояние после завершения процесса не восстанавливается. Это осознанно:
//! спайк проверяет инструкции, а не управление ключами.

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
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
    token::{ExtensionInitializationParams, ProofAccountWithCiphertext, Token},
    zk_proofs::confidential_mint_burn::{BurnAccountInfo, SupplyAccountInfo},
};
use spl_token_confidential_transfer_proof_generation::{
    burn::BurnProofData, mint::MintProofData,
};

/// 1000 wUSDC при decimals = 6.
const MINT_AMOUNT: u64 = 1_000_000_000;
/// 400 wUSDC сжигаем.
const BURN_AMOUNT: u64 = 400_000_000;
const DECIMALS: u8 = 6;

type MainnetToken = Token<ProgramRpcClientSendTransaction>;

#[tokio::main]
async fn main() -> Result<()> {
    // Конфиг берём тот же, что использует solana CLI (Helius RPC + наш keypair).
    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow::anyhow!("keypair не прочитан: {e}"))?;
    println!("payer:  {}", payer.pubkey());
    println!("rpc:    {}", json_rpc_url.split('?').next().unwrap_or(""));

    let rpc_client = Arc::new(RpcClient::new_with_commitment(
        json_rpc_url,
        CommitmentConfig::confirmed(),
    ));
    let program_client = Arc::new(ProgramRpcClient::new(
        rpc_client.clone(),
        ProgramRpcClientSendTransaction,
    ));

    // ── Ключи участников ────────────────────────────────────────────────
    let mint_keypair = Keypair::new();
    // Эмитент (в wrap-USDC это будет PDA программы-обёртки).
    let supply_elgamal = ElGamalKeypair::new_rand();
    let mint_ae_key = AeKey::new_rand();
    // Владелец конфид-баланса (пользователь).
    let alice_elgamal = ElGamalKeypair::new_rand();
    let alice_ae_key = AeKey::new_rand();
    // Аудитор — third-party наблюдатель сумм (наш H10/regulated-кейс).
    let auditor_elgamal = ElGamalKeypair::new_rand();

    let token = Token::new(
        program_client,
        &spl_token_2022::id(),
        &mint_keypair.pubkey(),
        Some(DECIMALS),
        Arc::new(payer.insecure_clone()),
    );

    // ── 1. Минт с CT + MintBurn ─────────────────────────────────────────
    println!("\n[1/5] создаю минт (CT + ConfidentialMintBurn + auditor)…");
    let out = token
        .create_mint(
            &payer.pubkey(),
            None,
            vec![
                ExtensionInitializationParams::ConfidentialTransferMint {
                    authority: Some(payer.pubkey()),
                    auto_approve_new_accounts: true,
                    auditor_elgamal_pubkey: Some((*auditor_elgamal.pubkey()).into()),
                },
                ExtensionInitializationParams::ConfidentialMintBurn {
                    supply_elgamal_pubkey: (*supply_elgamal.pubkey()).into(),
                    decryptable_supply: mint_ae_key.encrypt(0).into(),
                },
            ],
            &[&mint_keypair],
        )
        .await
        .context("create_mint")?;
    println!("  минт: {}", mint_keypair.pubkey());
    println!("  tx:   {out:?}");

    // ── 2. ATA + configure CT ───────────────────────────────────────────
    println!("\n[2/5] создаю ATA и включаю конфид-режим…");
    token
        .create_associated_token_account(&payer.pubkey())
        .await
        .context("create ATA")?;
    let alice_ata = token.get_associated_token_address(&payer.pubkey());
    // ATA создаётся базового размера; под CT-extension аккаунт надо
    // расширить ДО ConfigureAccount, иначе InvalidAccountData.
    token
        .reallocate(
            &alice_ata,
            &payer.pubkey(),
            &[ExtensionType::ConfidentialTransferAccount],
            &[&payer],
        )
        .await
        .context("reallocate под CT")?;
    let out = token
        .confidential_transfer_configure_token_account(
            &alice_ata,
            &payer.pubkey(),
            None,
            None,
            &alice_elgamal,
            &alice_ae_key,
            &[&payer],
        )
        .await
        .context("configure CT account")?;
    println!("  ata:  {alice_ata}");
    println!("  tx:   {out:?}");

    // ── 3. Конфиденциальный mint: сумма эмиссии скрыта ──────────────────
    println!("\n[3/5] конфиденциальный mint {MINT_AMOUNT} базовых единиц…");
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
                &mint_ae_key,
                alice_elgamal.pubkey(),
                Some(auditor_elgamal.pubkey()),
            )
            .map_err(|e| anyhow::anyhow!("mint proof generation: {e}"))?;

        let eq_ctx = Keypair::new();
        let validity_ctx = Keypair::new();
        let range_ctx = Keypair::new();

        println!("  верифицирую 3 proofs в context-аккаунты…");
        token
            .confidential_transfer_create_context_state_account(
                &eq_ctx.pubkey(),
                &payer.pubkey(),
                &equality_proof_data,
                false,
                &[&eq_ctx],
            )
            .await
            .context("equality proof context")?;
        token
            .confidential_transfer_create_context_state_account(
                &validity_ctx.pubkey(),
                &payer.pubkey(),
                &ciphertext_validity_proof_data_with_ciphertext.proof_data,
                false,
                &[&validity_ctx],
            )
            .await
            .context("validity proof context")?;
        token
            .confidential_transfer_create_context_state_account(
                &range_ctx.pubkey(),
                &payer.pubkey(),
                &range_proof_data,
                // Range proof U128 (~1.8 KB) не влезает в одну транзакцию —
                // создание аккаунта и верификация разносятся на две.
                true,
                &[&range_ctx],
            )
            .await
            .context("range proof context")?;

        let validity_with_ciphertext = ProofAccountWithCiphertext {
            context_state_account: validity_ctx.pubkey(),
            ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
            ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        };
        let out = token
            .confidential_transfer_mint(
                &payer.pubkey(),
                &alice_ata,
                Some(&eq_ctx.pubkey()),
                Some(&validity_with_ciphertext),
                Some(&range_ctx.pubkey()),
                MINT_AMOUNT,
                &supply_elgamal,
                alice_elgamal.pubkey(),
                Some(auditor_elgamal.pubkey()),
                &mint_ae_key,
                None,
                &[&payer],
            )
            .await
            .context("confidential mint")?;
        println!("  tx:   {out:?}");

        close_contexts(&token, &payer, &[&eq_ctx, &validity_ctx, &range_ctx]).await?;
    }

    // ── 4. Приём pending → available ────────────────────────────────────
    println!("\n[4/5] apply_pending_balance…");
    let out = token
        .confidential_transfer_apply_pending_balance(
            &alice_ata,
            &payer.pubkey(),
            None,
            alice_elgamal.secret(),
            &alice_ae_key,
            &[&payer],
        )
        .await
        .context("apply pending")?;
    println!("  tx:   {out:?}");

    // ── 5. Конфиденциальный burn ────────────────────────────────────────
    println!("\n[5/5] конфиденциальный burn {BURN_AMOUNT} базовых единиц…");
    {
        let account_info = token.get_account_info(&alice_ata).await.context("account info")?;
        let ct_ext = account_info
            .get_extension::<ConfidentialTransferAccount>()
            .context("нет CT extension")?;
        let BurnProofData {
            equality_proof_data,
            ciphertext_validity_proof_data_with_ciphertext,
            range_proof_data,
        } = BurnAccountInfo::new(ct_ext)
            .generate_split_burn_proof_data(
                BURN_AMOUNT,
                &alice_elgamal,
                &alice_ae_key,
                supply_elgamal.pubkey(),
                Some(auditor_elgamal.pubkey()),
            )
            .map_err(|e| anyhow::anyhow!("burn proof generation: {e}"))?;

        let eq_ctx = Keypair::new();
        let validity_ctx = Keypair::new();
        let range_ctx = Keypair::new();

        println!("  верифицирую 3 proofs в context-аккаунты…");
        token
            .confidential_transfer_create_context_state_account(
                &eq_ctx.pubkey(),
                &payer.pubkey(),
                &equality_proof_data,
                false,
                &[&eq_ctx],
            )
            .await
            .context("equality proof context")?;
        token
            .confidential_transfer_create_context_state_account(
                &validity_ctx.pubkey(),
                &payer.pubkey(),
                &ciphertext_validity_proof_data_with_ciphertext.proof_data,
                false,
                &[&validity_ctx],
            )
            .await
            .context("validity proof context")?;
        token
            .confidential_transfer_create_context_state_account(
                &range_ctx.pubkey(),
                &payer.pubkey(),
                &range_proof_data,
                // Range proof U128 (~1.8 KB) не влезает в одну транзакцию —
                // создание аккаунта и верификация разносятся на две.
                true,
                &[&range_ctx],
            )
            .await
            .context("range proof context")?;

        let validity_with_ciphertext = ProofAccountWithCiphertext {
            context_state_account: validity_ctx.pubkey(),
            ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
            ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        };
        let out = token
            .confidential_transfer_burn(
                &payer.pubkey(),
                &alice_ata,
                Some(&eq_ctx.pubkey()),
                Some(&validity_with_ciphertext),
                Some(&range_ctx.pubkey()),
                BURN_AMOUNT,
                &alice_elgamal,
                supply_elgamal.pubkey(),
                Some(auditor_elgamal.pubkey()),
                &alice_ae_key,
                None,
                &[&payer],
            )
            .await
            .context("confidential burn")?;
        println!("  tx:   {out:?}");

        close_contexts(&token, &payer, &[&eq_ctx, &validity_ctx, &range_ctx]).await?;
    }

    // ── Итог: что видно на цепи и что видит владелец ────────────────────
    print_state(&token, &alice_ata, &alice_ae_key, &mint_ae_key).await?;
    Ok(())
}

/// Закрывает proof-context-аккаунты, возвращая rent payer'у.
async fn close_contexts(
    token: &MainnetToken,
    payer: &Keypair,
    contexts: &[&Keypair],
) -> Result<()> {
    for ctx in contexts {
        token
            .confidential_transfer_close_context_state_account(
                &ctx.pubkey(),
                &payer.pubkey(),
                &payer.pubkey(),
                &[payer],
            )
            .await
            .context("close proof context")?;
    }
    Ok(())
}

/// Читает json_rpc_url и keypair_path из ~/.config/solana/cli/config.yml.
///
/// Ручной разбор двух строк YAML вместо зависимости solana-cli-config:
/// та конфликтует по версиям с rc-пинами spl-token-client (см. Cargo.toml).
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

/// Печатает состояние минта и счёта: шифры как их видит цепь и
/// расшифрованные значения, доступные только держателям ключей.
async fn print_state(
    token: &MainnetToken,
    ata: &Pubkey,
    owner_ae: &AeKey,
    mint_ae: &AeKey,
) -> Result<()> {
    println!("\n══ Итоговое состояние ══");

    let mint_info = token.get_mint_info().await.context("mint info")?;
    let mint_burn = mint_info
        .get_extension::<ConfidentialMintBurn>()
        .context("нет ConfidentialMintBurn")?;
    println!("supply (шифр на цепи):      {:?}", mint_burn.confidential_supply);
    let supply_plain: Option<u64> = mint_ae.decrypt(&mint_burn.decryptable_supply.try_into()?);
    println!("supply (видит эмитент):     {supply_plain:?} базовых единиц");

    let account_info = token.get_account_info(ata).await.context("account info")?;
    println!("публичный balance:          {}", account_info.base.amount);
    let ct = account_info
        .get_extension::<ConfidentialTransferAccount>()
        .context("нет CT extension")?;
    println!("available (шифр на цепи):   {:?}", ct.available_balance);
    let avail_plain: Option<u64> = owner_ae.decrypt(&ct.decryptable_available_balance.try_into()?);
    println!("available (видит владелец): {avail_plain:?} базовых единиц");
    Ok(())
}
