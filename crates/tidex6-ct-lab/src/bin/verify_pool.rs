//! Проверка hand-rolled пул-инструкций через simulateTransaction (без коммита,
//! без комиссий). Строит deposit со свежим commitment, симулирует. Если формат
//! (дискриминатор + borsh + аккаунты) верный — симуляция успешна; иначе
//! InstructionError/десериализация. Так убеждаемся, что байты приняла бы
//! задеплоенная программа, ДО реальной отправки средств.
//!
//! Запуск: cargo run --manifest-path crates/tidex6-ct-lab/Cargo.toml --bin verify_pool

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::read_keypair_file;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_transaction::Transaction;
use tidex6_core::types::{Commitment, Nullifier, Secret};

use tidex6_ct_lab::pool;

#[tokio::main]
async fn main() -> Result<()> {
    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path).map_err(|e| anyhow::anyhow!("keypair: {e}"))?;
    let rpc = Arc::new(RpcClient::new_with_commitment(
        json_rpc_url,
        CommitmentConfig::confirmed(),
    ));

    // Свежий commitment (не депонируем — только симулируем).
    let secret = Secret::random().context("secret")?;
    let nullifier = Nullifier::random().context("nullifier")?;
    let commitment = Commitment::derive(&secret, &nullifier).context("commitment")?;
    let commitment_bytes = commitment.to_bytes();

    println!("payer:      {}", payer.pubkey());
    println!("pool PDA:   {}", pool::pool_pda());
    println!("commitment: {}", hex(&commitment_bytes));

    let ix = pool::build_deposit_ix(&payer.pubkey(), commitment_bytes, 32, 600, &[0u8; 32]);
    println!(
        "\ndeposit ix: program={}, accounts={}, data_len={}",
        ix.program_id,
        ix.accounts.len(),
        ix.data.len()
    );
    println!("дискриминатор: {}", hex(&ix.data[..8]));

    let blockhash = rpc.get_latest_blockhash().await.context("blockhash")?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    println!("\nсимулирую (без коммита)…");
    let sim = rpc
        .simulate_transaction(&tx)
        .await
        .context("simulate")?;

    if let Some(err) = &sim.value.err {
        println!("\n❌ СИМУЛЯЦИЯ ОТКЛОНЕНА: {err:?}");
        println!("Значит формат hand-rolled инструкции неверный — смотри логи:");
    } else {
        println!("\n✅ СИМУЛЯЦИЯ УСПЕШНА — формат hand-rolled deposit принят программой.");
    }
    if let Some(logs) = &sim.value.logs {
        println!("--- program logs ---");
        for l in logs {
            println!("  {l}");
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0x0f) as usize] as char);
    }
    out
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
