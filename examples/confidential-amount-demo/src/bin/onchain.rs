//! cd-onchain — прогон сценария на реальной программе
//! `tidex6-confidential-amounts` (program ID
//! `6r8JfoXYtNKw36ZiFjWLdSJHGMpgTQUwDnqyWskKbqdP`, mainnet).
//!
//! ```text
//! cd-onchain init-vault    --payer <keypair.json>
//! cd-onchain init-account  --keypair <kp.json>
//! cd-onchain deposit       --keypair <kp.json> --amount-sol 0.01
//! cd-onchain transfer      --from <kp.json> --to-pubkey <pk> --amount-sol 0.003
//! cd-onchain withdraw      --keypair <kp.json> --amount-sol 0.005
//! cd-onchain close         --keypair <kp.json>
//! cd-onchain show          --pubkey <pk>
//! ```
//!
//! Для приватности клиент ведёт **локальный state-файл** на каждого
//! owner'а: `~/.tidex6-conf-amounts/<pubkey>.json`. Там хранятся
//! (balance, sum_blinding) — с ними мы собираем корректные
//! Pedersen-commitment'ы перед каждой tx. Файл **не надо** никому
//! отдавать — без него withdraw и transfer математически не сойдутся.

use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;

use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::anchor_lang::system_program;
use anchor_client::{Client, Cluster, Signer};
use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use solana_keypair::{Keypair, read_keypair_file};

use tidex6_confidential_amount_demo::altbn128::{ALT_BN128_G1_LEN, g1_to_alt_bn128};
use tidex6_confidential_amount_demo::pedersen::{self, Commitment};
use tidex6_confidential_amounts::{
    ID as PROGRAM_ID, accounts as conf_accounts, instruction as conf_ix,
};

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

#[derive(Parser, Debug)]
#[command(
    name = "cd-onchain",
    about = "Confidential amount demo — onchain driver"
)]
struct Cli {
    /// Solana RPC URL. По умолчанию — Helius mainnet из Solana CLI
    /// config; переопределяется переменной окружения SOLANA_RPC или
    /// флагом ниже.
    #[arg(long, global = true)]
    rpc_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Одноразово инициализирует общий vault PDA (если не сделан).
    InitVault {
        #[arg(long)]
        payer: PathBuf,
    },
    /// Создать confidential-аккаунт для `keypair` (он же owner).
    InitAccount {
        #[arg(long)]
        keypair: PathBuf,
    },
    /// Deposit `amount-sol` с owner → vault + гомоморфное обновление
    /// commitment'а аккаунта.
    Deposit {
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        amount_sol: f64,
    },
    /// Приватный перевод `amount-sol` от `from` к `to-pubkey`.
    /// Обе стороны должны иметь уже созданные аккаунты. SOL в vault
    /// не двигается — только commitment'ы.
    Transfer {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to_pubkey: String,
        #[arg(long)]
        amount_sol: f64,
    },
    /// Withdraw `amount-sol` из vault → owner + обновление commitment.
    Withdraw {
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        amount_sol: f64,
    },
    /// Закрыть confidential-account, вернуть rent.
    Close {
        #[arg(long)]
        keypair: PathBuf,
    },
    /// Показать текущий commitment аккаунта по pubkey (то что
    /// видит наблюдатель — 64 байта). Балансы не видны без local
    /// state-файла.
    Show {
        #[arg(long)]
        pubkey: String,
    },

    /// Применить входящий confidential transfer к local-state.
    /// Получатель запускает это на своей машине, передавая
    /// `transfer-blinding` который ему прислал sender out of band.
    ApplyIncoming {
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        amount_sol: f64,
        #[arg(long)]
        transfer_blinding: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc_url = resolve_rpc_url(cli.rpc_url);

    match cli.command {
        Command::InitVault { payer } => run_init_vault(&rpc_url, &payer),
        Command::InitAccount { keypair } => run_init_account(&rpc_url, &keypair),
        Command::Deposit {
            keypair,
            amount_sol,
        } => run_deposit(&rpc_url, &keypair, amount_sol),
        Command::Transfer {
            from,
            to_pubkey,
            amount_sol,
        } => run_transfer(&rpc_url, &from, &to_pubkey, amount_sol),
        Command::Withdraw {
            keypair,
            amount_sol,
        } => run_withdraw(&rpc_url, &keypair, amount_sol),
        Command::Close { keypair } => run_close(&rpc_url, &keypair),
        Command::Show { pubkey } => run_show(&rpc_url, &pubkey),
        Command::ApplyIncoming {
            keypair,
            amount_sol,
            transfer_blinding,
        } => run_apply_incoming(&keypair, amount_sol, &transfer_blinding),
    }
}

fn run_apply_incoming(
    keypair_path: &std::path::Path,
    amount_sol: f64,
    transfer_blinding_hex: &str,
) -> Result<()> {
    let owner = load_keypair(keypair_path)?;
    let amount_lamports = sol_to_lamports(amount_sol)?;
    let transfer_blinding = state_fr_from_hex(transfer_blinding_hex)?;

    let mut local = LocalState::load(&owner.pubkey())?;
    if local.sum_blinding_hex.is_empty() {
        return Err(anyhow!(
            "no local state for {} — run init-account on this machine first",
            owner.pubkey()
        ));
    }
    let old_blinding = state_fr_from_hex(&local.sum_blinding_hex)?;
    let new_blinding = old_blinding + transfer_blinding;
    local.balance_lamports += amount_lamports;
    local.sum_blinding_hex = state_fr_to_hex(&new_blinding);
    local.save(&owner.pubkey())?;

    println!(
        "Applied incoming confidential transfer of {amount_sol} SOL to {}",
        owner.pubkey()
    );
    println!(
        "  new local balance: {} SOL",
        lamports_to_sol_str(local.balance_lamports)
    );
    Ok(())
}

// ─── Subcommand handlers ──────────────────────────────────────

fn run_init_vault(rpc_url: &str, payer_path: &std::path::Path) -> Result<()> {
    let payer = load_keypair(payer_path)?;
    let (program, vault_pda) = (program_handle(rpc_url, &payer)?, vault_pda());

    println!("Initializing vault PDA: {vault_pda}");

    let signature = program
        .request()
        .accounts(conf_accounts::InitVault {
            vault: vault_pda,
            payer: payer.pubkey(),
            system_program: system_program::ID,
        })
        .args(conf_ix::InitVault {})
        .signer(&payer)
        .send()
        .context("init_vault tx failed")?;

    println!("  signature: {signature}");
    Ok(())
}

fn run_init_account(rpc_url: &str, keypair_path: &std::path::Path) -> Result<()> {
    let owner = load_keypair(keypair_path)?;
    let program = program_handle(rpc_url, &owner)?;
    let account_pda = account_pda(&owner.pubkey());

    // Начальный commitment: Com(0, r). Храним blinding локально,
    // чтобы потом корректно собирать следующие commitment'ы.
    let blinding = pedersen::fresh_blinding()?;
    let initial_commitment = Commitment::zero_with_blinding(blinding);
    let initial_bytes = g1_to_alt_bn128(&initial_commitment.0);

    println!("Initializing confidential account for {}", owner.pubkey());
    println!("  account PDA    : {account_pda}");
    println!("  initial commit : {}", hex_short(&initial_bytes));

    let signature = program
        .request()
        .accounts(conf_accounts::InitAccount {
            account: account_pda,
            owner: owner.pubkey(),
            system_program: system_program::ID,
        })
        .args(conf_ix::InitAccount {
            initial_commitment: initial_bytes,
        })
        .signer(&owner)
        .send()
        .context("init_account tx failed")?;

    let mut local = LocalState::load(&owner.pubkey())?;
    local.balance_lamports = 0;
    local.sum_blinding_hex = state_fr_to_hex(&blinding);
    local.save(&owner.pubkey())?;

    println!("  signature      : {signature}");
    println!(
        "  local state    : ~/.tidex6-conf-amounts/{}.json",
        owner.pubkey()
    );
    Ok(())
}

fn run_deposit(rpc_url: &str, keypair_path: &std::path::Path, amount_sol: f64) -> Result<()> {
    let owner = load_keypair(keypair_path)?;
    let program = program_handle(rpc_url, &owner)?;
    let amount_lamports = sol_to_lamports(amount_sol)?;

    // Свежий blinding для этой delta; в локальный state прибавляем
    // и amount, и blinding.
    let extra_blinding = pedersen::fresh_blinding()?;
    let delta = Commitment::create(amount_lamports, extra_blinding);
    let delta_bytes = g1_to_alt_bn128(&delta.0);

    println!(
        "Deposit {amount_sol} SOL ({amount_lamports} lamports) from {}",
        owner.pubkey()
    );
    println!("  delta commit : {}", hex_short(&delta_bytes));

    let signature = program
        .request()
        .accounts(conf_accounts::Deposit {
            account: account_pda(&owner.pubkey()),
            vault: vault_pda(),
            owner: owner.pubkey(),
            system_program: system_program::ID,
        })
        .args(conf_ix::Deposit {
            amount_lamports,
            delta_commitment: delta_bytes,
        })
        .signer(&owner)
        .send()
        .context("deposit tx failed")?;

    let mut local = LocalState::load(&owner.pubkey())?;
    let old_blinding = state_fr_from_hex(&local.sum_blinding_hex)?;
    let new_blinding = old_blinding + extra_blinding;
    local.balance_lamports += amount_lamports;
    local.sum_blinding_hex = state_fr_to_hex(&new_blinding);
    local.save(&owner.pubkey())?;

    println!("  signature    : {signature}");
    println!(
        "  new local balance: {} SOL (hidden onchain)",
        lamports_to_sol_str(local.balance_lamports)
    );
    Ok(())
}

fn run_transfer(
    rpc_url: &str,
    from_path: &std::path::Path,
    to_pubkey: &str,
    amount_sol: f64,
) -> Result<()> {
    let sender = load_keypair(from_path)?;
    let program = program_handle(rpc_url, &sender)?;
    let to_pubkey = Pubkey::from_str(to_pubkey)?;
    let amount_lamports = sol_to_lamports(amount_sol)?;

    // transfer_blinding свежий. У sender'а убывает и balance, и
    // blinding — ровно на эти значения. У receiver'а прибавляется
    // то же самое; мы НЕ можем обновить его local state здесь,
    // так что просто напоминаем в выводе — пусть receiver сделает
    // себе то же через `cd-onchain receive` (упрощаем: у нас
    // test-песочница, обновление state-файлов receiver'а — ручное
    // либо мы владельцы обоих кошельков).
    let transfer_blinding = pedersen::fresh_blinding()?;
    let transfer_commitment = Commitment::create(amount_lamports, transfer_blinding);
    let transfer_bytes = g1_to_alt_bn128(&transfer_commitment.0);

    println!(
        "Confidential transfer: {} → {to_pubkey} ({amount_sol} SOL)",
        sender.pubkey()
    );
    println!("  transfer commit : {}", hex_short(&transfer_bytes));

    let signature = program
        .request()
        .accounts(conf_accounts::Transfer {
            from: account_pda(&sender.pubkey()),
            to: account_pda(&to_pubkey),
            sender: sender.pubkey(),
            to_owner: to_pubkey,
        })
        .args(conf_ix::Transfer {
            transfer_commitment: transfer_bytes,
        })
        .signer(&sender)
        .send()
        .context("transfer tx failed")?;

    // Local state sender'а: вычитаем.
    let mut local_from = LocalState::load(&sender.pubkey())?;
    if local_from.balance_lamports < amount_lamports {
        eprintln!(
            "WARNING: local state says you only have {} lamports — onchain commitment is now underflowed",
            local_from.balance_lamports
        );
    }
    let old_blinding = state_fr_from_hex(&local_from.sum_blinding_hex)?;
    let new_blinding = old_blinding - transfer_blinding;
    local_from.balance_lamports = local_from.balance_lamports.saturating_sub(amount_lamports);
    local_from.sum_blinding_hex = state_fr_to_hex(&new_blinding);
    local_from.save(&sender.pubkey())?;

    // Receiver local state — если мы владельцы и его тоже.
    // Пустой sum_blinding_hex значит файла нет локально (мы на
    // другой машине от получателя). Это нормальный кейс: получатель
    // сам применит transfer_blinding у себя командой ниже.
    match LocalState::load(&to_pubkey) {
        Ok(mut local_to) if !local_to.sum_blinding_hex.is_empty() => {
            let old_to_blinding = state_fr_from_hex(&local_to.sum_blinding_hex)?;
            let new_to_blinding = old_to_blinding + transfer_blinding;
            local_to.balance_lamports += amount_lamports;
            local_to.sum_blinding_hex = state_fr_to_hex(&new_to_blinding);
            local_to.save(&to_pubkey)?;
            println!(
                "  updated receiver local state: balance now {}",
                lamports_to_sol_str(local_to.balance_lamports)
            );
        }
        _ => {
            println!();
            println!("  Receiver's local state not on this machine.");
            println!("  On the recipient machine run:");
            println!(
                "    cd-onchain apply-incoming --keypair <recipient.json> \\\n      --amount-sol {amount_sol} --transfer-blinding {}",
                state_fr_to_hex(&transfer_blinding)
            );
        }
    }

    println!("  signature       : {signature}");
    Ok(())
}

fn run_withdraw(rpc_url: &str, keypair_path: &std::path::Path, amount_sol: f64) -> Result<()> {
    let owner = load_keypair(keypair_path)?;
    let program = program_handle(rpc_url, &owner)?;
    let amount_lamports = sol_to_lamports(amount_sol)?;

    let mut local = LocalState::load(&owner.pubkey())?;
    if local.balance_lamports < amount_lamports {
        return Err(anyhow!(
            "local state says balance is {} lamports, cannot withdraw {amount_lamports}",
            local.balance_lamports
        ));
    }

    // Новый commitment: Com(balance - amount, old_blinding - r_withdraw)
    // с свежим r_withdraw.
    let withdraw_blinding = pedersen::fresh_blinding()?;
    let old_blinding = state_fr_from_hex(&local.sum_blinding_hex)?;
    let new_blinding = old_blinding - withdraw_blinding;
    let new_balance = local.balance_lamports - amount_lamports;
    let new_commitment = Commitment::create(new_balance, new_blinding);
    let new_bytes = g1_to_alt_bn128(&new_commitment.0);

    println!(
        "Withdraw {amount_sol} SOL to {} (public — SOL leaves vault)",
        owner.pubkey()
    );
    println!("  new commit   : {}", hex_short(&new_bytes));

    let signature = program
        .request()
        .accounts(conf_accounts::Withdraw {
            account: account_pda(&owner.pubkey()),
            vault: vault_pda(),
            owner: owner.pubkey(),
        })
        .args(conf_ix::Withdraw {
            amount_lamports,
            new_commitment: new_bytes,
        })
        .signer(&owner)
        .send()
        .context("withdraw tx failed")?;

    local.balance_lamports = new_balance;
    local.sum_blinding_hex = state_fr_to_hex(&new_blinding);
    local.save(&owner.pubkey())?;

    println!("  signature    : {signature}");
    println!(
        "  new local balance: {} SOL",
        lamports_to_sol_str(local.balance_lamports)
    );
    Ok(())
}

fn run_close(rpc_url: &str, keypair_path: &std::path::Path) -> Result<()> {
    let owner = load_keypair(keypair_path)?;
    let program = program_handle(rpc_url, &owner)?;

    println!("Closing confidential account for {}", owner.pubkey());

    let signature = program
        .request()
        .accounts(conf_accounts::CloseAccount {
            account: account_pda(&owner.pubkey()),
            owner: owner.pubkey(),
        })
        .args(conf_ix::CloseAccount {})
        .signer(&owner)
        .send()
        .context("close_account tx failed")?;

    let _ = LocalState::delete(&owner.pubkey());

    println!("  signature: {signature}");
    println!("  rent returned to owner");
    Ok(())
}

fn run_show(rpc_url: &str, pubkey_str: &str) -> Result<()> {
    let pubkey = Pubkey::from_str(pubkey_str)?;
    let pda = account_pda(&pubkey);

    // Нам достаточно просто RPC-клиента; anchor Program handle тут
    // избыточен, но дешёвый — dummy-payer не трогается на запросы.
    let dummy = Keypair::new();
    let program = program_handle(rpc_url, &dummy)?;
    let rpc = program.rpc();

    println!("Confidential account for {pubkey}");
    println!("  PDA : {pda}");

    let account = rpc
        .get_account(&pda)
        .map_err(|e| anyhow!("getAccountInfo failed: {e}"))?;

    // Anchor account layout: 8 bytes discriminator + owner (32) +
    // commitment (64) + bump (1). Читаем commitment напрямую.
    if account.data.len() < 8 + 32 + ALT_BN128_G1_LEN + 1 {
        return Err(anyhow!("account data too short ({})", account.data.len()));
    }
    let commit_slice = &account.data[8 + 32..8 + 32 + ALT_BN128_G1_LEN];
    let mut commit_bytes = [0u8; ALT_BN128_G1_LEN];
    commit_bytes.copy_from_slice(commit_slice);

    println!("  commitment on chain (64 bytes):");
    println!("    {}", hex_full(&commit_bytes));
    println!("  (outsider cannot derive balance from this alone)");
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────

fn program_handle(rpc_url: &str, payer: &Keypair) -> Result<anchor_client::Program<Rc<Keypair>>> {
    let cluster = Cluster::Custom(rpc_url.to_string(), rpc_url.to_string());
    let payer_rc = Rc::new(clone_keypair(payer));
    let client = Client::new_with_options(
        cluster,
        payer_rc,
        anchor_client::CommitmentConfig::confirmed(),
    );
    client.program(PROGRAM_ID).map_err(|e| anyhow!(e))
}

fn account_pda(owner: &Pubkey) -> Pubkey {
    let (pda, _bump) =
        Pubkey::find_program_address(&[b"conf-account", owner.as_ref()], &PROGRAM_ID);
    pda
}

fn vault_pda() -> Pubkey {
    let (pda, _bump) = Pubkey::find_program_address(&[b"conf-vault"], &PROGRAM_ID);
    pda
}

fn load_keypair(path: &std::path::Path) -> Result<Keypair> {
    read_keypair_file(path).map_err(|e| anyhow!("read keypair {}: {e}", path.display()))
}

fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::try_from(keypair.to_bytes().as_slice())
        .expect("round-tripping a Keypair through its byte form is infallible")
}

fn sol_to_lamports(sol: f64) -> Result<u64> {
    if !sol.is_finite() || sol <= 0.0 {
        return Err(anyhow!("amount must be positive"));
    }
    let lamports = (sol * LAMPORTS_PER_SOL as f64).round() as u64;
    if lamports == 0 {
        return Err(anyhow!("amount rounded to zero lamports"));
    }
    Ok(lamports)
}

fn lamports_to_sol_str(lamports: u64) -> String {
    format!("{:.9}", lamports as f64 / LAMPORTS_PER_SOL as f64)
}

fn resolve_rpc_url(flag: Option<String>) -> String {
    if let Some(u) = flag {
        return u;
    }
    if let Ok(u) = std::env::var("SOLANA_RPC") {
        return u;
    }
    // Default: Helius из solana CLI config; если не удалось прочесть
    // → публичный mainnet.
    let home = std::env::var("HOME").unwrap_or_default();
    let path = format!("{home}/.config/solana/cli/config.yml");
    if let Ok(contents) = std::fs::read_to_string(&path) {
        for line in contents.lines() {
            if let Some(value) = line.trim().strip_prefix("json_rpc_url:") {
                return value.trim().trim_matches('"').to_string();
            }
        }
    }
    "https://api.mainnet-beta.solana.com".to_string()
}

fn hex_short(bytes: &[u8; ALT_BN128_G1_LEN]) -> String {
    let hex: String = bytes.iter().take(12).map(|b| format!("{b:02x}")).collect();
    format!("{hex}…")
}

fn hex_full(bytes: &[u8; ALT_BN128_G1_LEN]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── Local state (balance + blinding per owner) ──────────────

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LocalState {
    balance_lamports: u64,
    sum_blinding_hex: String,
}

impl LocalState {
    fn path_for(pubkey: &Pubkey) -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME not set")?;
        let dir = PathBuf::from(format!("{home}/.tidex6-conf-amounts"));
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join(format!("{pubkey}.json")))
    }

    fn load(pubkey: &Pubkey) -> Result<Self> {
        let path = Self::path_for(pubkey)?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    fn save(&self, pubkey: &Pubkey) -> Result<()> {
        let path = Self::path_for(pubkey)?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn delete(pubkey: &Pubkey) -> Result<()> {
        let path = Self::path_for(pubkey)?;
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

fn state_fr_to_hex(scalar: &Fr) -> String {
    let mut bytes = [0u8; 32];
    scalar
        .serialize_compressed(&mut bytes[..])
        .expect("Fr serialises to 32 bytes");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn state_fr_from_hex(hex: &str) -> Result<Fr> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    if stripped.len() != 64 {
        return Err(anyhow!("expected 64 hex chars, got {}", stripped.len()));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in stripped.as_bytes().chunks(2).enumerate() {
        let hi = nibble(chunk[0])?;
        let lo = nibble(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(Fr::from_le_bytes_mod_order(&bytes))
}

fn nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(anyhow!("invalid hex char")),
    }
}
