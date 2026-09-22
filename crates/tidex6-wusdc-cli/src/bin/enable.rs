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
//! ```

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

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("enable — turn on private payments for the local wallet");
        eprintln!("Usage:\n  enable <mainnet|devnet>");
        std::process::exit(2);
    }

    let home = std::env::var("HOME").context("HOME")?;
    let raw = std::fs::read_to_string(format!("{home}/.tidex6-local/config.toml"))
        .context("~/.tidex6-local/config.toml")?;
    let cfg: Config = toml::from_str(&raw).context("parse config")?;

    let url = match args[0].as_str() {
        "mainnet" => cfg.rpc_mainnet.clone(),
        "devnet" => cfg.rpc_devnet.clone(),
        other => bail!("unknown network: {other}"),
    };

    let keypair = load_keypair(&cfg.keypair_path)?;
    let identity = LocalIdentity::from_keypair(&keypair)?;
    let wallet = keypair.pubkey();

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

    let public = identity.reader.to_bytes();
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

    // 2. Записать адрес читателя кусками.
    let mut offset = 0usize;
    while offset < public.len() {
        let end = (offset + MAX_CHUNK).min(public.len());
        let ix = Instruction {
            program_id,
            accounts: tidex6_registry::accounts::WriteReaderChunk { wallet, entry }
                .to_account_metas(None),
            data: tidex6_registry::instruction::WriteReaderChunk {
                offset: offset as u32,
                chunk: public[offset..end].to_vec(),
            }
            .data(),
        };
        let hash = rpc.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&wallet), &[&keypair], hash);
        let sig = rpc.send_and_confirm_transaction(&tx)?;
        println!("chunk {offset}..{end}: {sig}");
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
