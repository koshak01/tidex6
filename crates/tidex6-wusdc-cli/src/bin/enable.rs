//! Включить приватные платежи для кошелька из локального конфига.
//!
//! То же, что делает страница `/register/`, но ключом с диска: выводит личность
//! из подписи, создаёт запись в реестре и публикует адрес читателя.
//!
//! Понадобилось 19.08.2026 посреди записи демо: у машины есть ключ, но нет
//! браузера, а без записи в реестре кошелёк не может ни платить, ни получать.
//!
//! ```text
//! enable <mainnet|devnet>
//! enable <mainnet|devnet> --keypair <wallet.json> --rpc <url> --identity <keygen.json>
//! ```
//!
//! The second form registers a wallet under a reader key that was NOT derived
//! from it — the treasury's, made by `tidex6 keygen`. The treasury has a
//! reader key and a Solana wallet to collect with, and the pool service only
//! pays out to a registered wallet.

use anchor_client::Signer;
use anchor_lang::prelude::Pubkey;
use anchor_lang::{InstructionData, ToAccountMetas};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use solana_instruction::Instruction;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::Transaction;
use tidex6_client::confidential::{LocalIdentity, load_keypair};

/// За один раз в транзакцию влезает столько байт адреса читателя.
/// Адрес — 1216 байт, транзакция — 1232, поэтому он идёт кусками.
const MAX_CHUNK: usize = 900;

/// Версия личности, та же, что публикует браузер.
const IDENTITY_VERSION: u8 = 2;

#[derive(Deserialize)]
struct Config {
    keypair_path: String,
    rpc_mainnet: String,
    rpc_devnet: String,
}

/// Value of `--name <value>` among the arguments.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// The public reader address from a `tidex6 keygen` identity file.
fn reader_from_identity(path: &str) -> Result<tidex6_core::envelope::ReaderAddress> {
    #[derive(Deserialize)]
    struct IdentityFile {
        mlkem_public: String,
    }
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let file: IdentityFile = serde_json::from_str(&raw).with_context(|| format!("parse {path}"))?;
    let bytes = hex::decode(file.mlkem_public.trim()).context("mlkem_public is not hex")?;
    tidex6_core::envelope::ReaderAddress::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("mlkem_public: {e}"))
}

/// Where the entry's `written_len` sits: discriminator 8 + owner 32 + version 1.
const WRITTEN_LEN_OFFSET: usize = 41;
/// Where the key bytes start: `written_len` 4 + bump 1 + is_finalized 1 +
/// Vec length prefix 4 after it.
const DATA_OFFSET: usize = WRITTEN_LEN_OFFSET + 4 + 1 + 1 + 4;

/// How many key bytes the entry already holds, and those bytes. No entry or an
/// entry the node does not show yet reads as nothing written.
fn written_so_far(rpc: &RpcClient, entry: &Pubkey) -> Result<(usize, Vec<u8>)> {
    let Ok(account) = rpc.get_account(entry) else {
        return Ok((0, Vec::new()));
    };
    let data = account.data;
    if data.len() < DATA_OFFSET {
        return Ok((0, Vec::new()));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&data[WRITTEN_LEN_OFFSET..WRITTEN_LEN_OFFSET + 4]);
    let written = u32::from_le_bytes(len_bytes) as usize;
    let end = (DATA_OFFSET + written).min(data.len());
    Ok((written, data[DATA_OFFSET..end].to_vec()))
}

/// Write one chunk, riding out the node's transient failures: a fresh entry
/// the node does not see yet (`AccountNotInitialized`), an expired blockhash.
/// Before each retry the entry is read again — a chunk whose confirmation was
/// lost may have landed, and sending it twice would be refused.
fn write_chunk(
    rpc: &RpcClient,
    keypair: &solana_keypair::Keypair,
    program_id: Pubkey,
    entry: Pubkey,
    offset: usize,
    chunk: &[u8],
) -> Result<()> {
    let wallet = keypair.pubkey();
    let end = offset + chunk.len();
    let mut last_error = None;
    for attempt in 1..=6 {
        if attempt > 1 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if written_so_far(rpc, &entry)?.0 >= end {
                println!("chunk {offset}..{end}: already landed");
                return Ok(());
            }
        }
        let ix = Instruction {
            program_id,
            accounts: tidex6_registry::accounts::WriteReaderChunk { wallet, entry }
                .to_account_metas(None),
            data: tidex6_registry::instruction::WriteReaderChunk {
                offset: offset as u32,
                chunk: chunk.to_vec(),
            }
            .data(),
        };
        let hash = rpc.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&wallet), &[keypair], hash);
        match rpc.send_and_confirm_transaction(&tx) {
            Ok(sig) => {
                println!("chunk {offset}..{end}: {sig}");
                return Ok(());
            }
            Err(e) => {
                println!("chunk {offset}..{end}: attempt {attempt} failed: {e}");
                last_error = Some(e);
            }
        }
    }
    Err(anyhow::anyhow!(
        "chunk {offset}..{end} failed 6 times: {:?} — run this again; it resumes where it stopped",
        last_error
    ))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("enable — turn on private payments for the local wallet");
        eprintln!("Usage:\n  enable <mainnet|devnet>");
        eprintln!(
            "  enable <mainnet|devnet> --keypair <wallet.json> --rpc <url> --identity <keygen.json>"
        );
        std::process::exit(2);
    }

    // With --keypair and --rpc the local config is not needed at all: the
    // treasury runs as the service user, which has no ~/.tidex6-local.
    let (keypair_path, url) = match (flag(&args, "--keypair"), flag(&args, "--rpc")) {
        (Some(k), Some(u)) => (k, u),
        _ => {
            let home = std::env::var("HOME").context("HOME")?;
            let raw = std::fs::read_to_string(format!("{home}/.tidex6-local/config.toml"))
                .context("~/.tidex6-local/config.toml")?;
            let cfg: Config = toml::from_str(&raw).context("parse config")?;
            let url = match args[0].as_str() {
                "mainnet" => cfg.rpc_mainnet.clone(),
                "devnet" => cfg.rpc_devnet.clone(),
                other => bail!("unknown network: {other}"),
            };
            (flag(&args, "--keypair").unwrap_or(cfg.keypair_path), url)
        }
    };
    if !matches!(args[0].as_str(), "mainnet" | "devnet") {
        bail!("unknown network: {}", args[0]);
    }

    let keypair = load_keypair(&keypair_path)?;
    let wallet = keypair.pubkey();
    // The reader: from --identity when given (a key not derived from this
    // wallet), otherwise derived from the wallet's signature as the browser does.
    let reader = match flag(&args, "--identity") {
        Some(path) => reader_from_identity(&path)?,
        None => LocalIdentity::from_keypair(&keypair)?.reader,
    };

    println!("wallet:  {wallet}");
    println!("network: {}", args[0]);

    let rpc = RpcClient::new(url);
    let program_id = tidex6_registry::ID;
    let (entry, _) = Pubkey::find_program_address(&[b"reader", wallet.as_ref()], &program_id);
    println!("entry:   {entry}");

    // Включён ли кошелёк — вопрос о ЧИТАТЕЛЕ, а не о существовании записи.
    //
    // Регистрация — две разные вещи в разных транзакциях: сначала заводится
    // запись, потом в неё кусками пишется ключ читателя. Раньше здесь стояло
    // «есть запись → уже включён», и это оказалось ловушкой: 25.08.2026 первая
    // попытка создала запись, а первый же кусок ключа упал на гонке
    // подтверждения — узел ещё не видел свежесозданный аккаунт. Повторный
    // запуск сказал «already enabled — nothing to do», пул продолжал считать
    // кошелёк невключённым, и выйти из этого состояния тем же инструментом
    // стало нечем.
    //
    // Спрашиваем то же, что спрашивает служба: читается ли ключ читателя
    // целиком. Тогда «уже включён» значит «работает», а не «что-то начато».
    let reader_ready = tidex6_client::registry::lookup(&rpc, &wallet)
        .ok()
        .flatten()
        .is_some();
    if reader_ready {
        println!("already enabled — nothing to do");
        return Ok(());
    }

    let public = reader.to_bytes();
    println!("reader:  {} bytes", public.len());

    // 1. Создать запись — если её ещё нет. Незавершённую регистрацию
    // доканчиваем с этого места, а не начинаем заново: аккаунт уже оплачен
    // рентой, второй раз за него платить незачем.
    if rpc.get_account(&entry).is_ok() {
        println!("entry already exists — finishing the reader");
    } else {
        let ix = Instruction {
            program_id,
            accounts: tidex6_registry::accounts::InitReader {
                wallet,
                entry,
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: tidex6_registry::instruction::InitReader {
                version: IDENTITY_VERSION,
            }
            .data(),
        };
        let hash = rpc.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&wallet), &[&keypair], hash);
        let sig = rpc.send_and_confirm_transaction(&tx)?;
        println!("entry created: {sig}");

        // Дождаться, пока узел увидит созданный аккаунт. Подтверждение
        // транзакции и видимость аккаунта на том узле, который ответит
        // следующему запросу, — разные события: у провайдера за одним адресом
        // стоит несколько нод. Без этой паузы первый же кусок ключа падает с
        // `AccountNotInitialized`, как оно и случилось.
        for _ in 0..20 {
            if rpc.get_account(&entry).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    // 2. Записать адрес читателя кусками — с того места, где запись остановилась.
    //
    // Реестр принимает кусок только как продолжение уже записанного
    // (`OffsetMismatch` иначе). Раньше здесь всегда начинали с нуля, и после
    // любого сбоя посреди записи повторный запуск упирался в этот отказ
    // навсегда: 24.09.2026 кошелёк казны на mainnet застрял на 900 байтах из
    // 1216. Поэтому смещение берём из самой записи, а записанное начало
    // сверяем с нашим ключом: чужое начало дописывать нельзя.
    let (mut offset, written) = written_so_far(&rpc, &entry)?;
    if public[..offset] != written[..] {
        bail!(
            "the entry already holds {offset} bytes of a DIFFERENT reader key — \
             close it first (close_reader) and register again"
        );
    }
    if offset > 0 {
        println!("resuming at byte {offset} of {}", public.len());
    }
    while offset < public.len() {
        let end = (offset + MAX_CHUNK).min(public.len());
        write_chunk(
            &rpc,
            &keypair,
            program_id,
            entry,
            offset,
            &public[offset..end],
        )?;
        offset = end;
    }

    // Проверяем не по своему следу, а тем же способом, что и служба: читается
    // ли ключ читателя целиком. Сказать «включено», не спросив об этом, значит
    // повторить ту же ошибку — на этот раз в отчёте.
    match tidex6_client::registry::lookup(&rpc, &wallet)
        .ok()
        .flatten()
    {
        Some(_) => println!("done — private payments are enabled for {wallet}"),
        None => bail!(
            "chunks are written but the reader still does not read back — \
             run this again; the account is paid for and nothing is lost"
        ),
    }
    Ok(())
}
