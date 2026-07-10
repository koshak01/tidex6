//! tidex6-wusdc — единый сервис двухслойного флоу (5-й процесс).
//!
//! Слушает unix-socket `/tmp/tidex6-wusdc.sock`, принимает JSON-запрос
//! `{"op":"deposit","amount":1000000}` (или withdraw/wrap/configure/mover/
//! cashout с параметрами note/recipient), выполняет операцию IN-PROCESS
//! (lib-функции `flow::*`/`ct::*`, БЕЗ спавна бинарников) и возвращает
//! JSON-ответ `{"ok":true,"output":"..."}`. `ws` (forge) зовёт по этому сокету
//! обычным UnixStream — общий Rust-тип не нужен, версии не пересекаются.
//!
//! Запуск: cargo run --manifest-path crates/tidex6-ct-lab/Cargo.toml --bin service

use std::sync::Arc;

use anyhow::{Context, Result};
use solana_keypair::Keypair;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use tidex6_ct_lab::config::Config;
use tidex6_ct_lab::{ct, flow, pool};

/// Сокет в owner-only каталоге ~/.tidex6-wusdc (0700) + 0600 на самом сокете —
/// сервис держит ключ и двигает средства, доступ только владельцу (не /tmp).
fn socket_path() -> Result<String> {
    use std::os::unix::fs::DirBuilderExt;
    let home = std::env::var("HOME").context("нет $HOME")?;
    let dir = format!("{home}/.tidex6-wusdc");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .ok();
    Ok(format!("{dir}/service.sock"))
}

/// Живой бэкенд одной сети: RPC + оператор-кошелёк. Один сервис держит оба
/// (devnet + mainnet) и выбирает по сети из запроса — сервис сериальный.
struct Backend {
    rpc: Arc<RpcClient>,
    payer: Keypair,
}

fn load_backend(net: tidex6_core::network::Network, config: &Config) -> Result<Backend> {
    let (rpc, payer) = flow::rpc_for_network(net, config.rpc_override(net))
        .with_context(|| format!("backend {net:?}"))?;
    Ok(Backend { rpc, payer })
}

#[tokio::main]
async fn main() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Конфиг вместо env: allowlist + авто-мувер + RPC-оверрайды.
    let config = Config::load().context("config.toml")?;

    // Два живых бэкенда в ОДНОМ процессе — настоящий Dev/Main switch по чипу.
    // Сервис сериальный → выбор сети per-request безопасен (как чип актива).
    let dev = load_backend(tidex6_core::network::Network::Devnet, &config)?;
    let mainnet = load_backend(tidex6_core::network::Network::Mainnet, &config)?;
    tidex6_ct_lab::config::set_active_asset(config.asset());
    // Минты per-окружение: config перекрывает реестр (оператор машины ≠ автор
    // хардкод-минтов; каждый со своими минтами).
    tidex6_ct_lab::config::set_mint_overrides(config.mints.clone());
    println!(
        "dev  rpc: {}",
        dev.rpc.url().split('?').next().unwrap_or("")
    );
    println!(
        "main rpc: {}",
        mainnet.rpc.url().split('?').next().unwrap_or("")
    );

    let path = socket_path()?;
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).context("bind socket")?;
    // Только владелец: и каталог 0700, и сам сокет 0600.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .context("chmod 0600 сокета")?;
    println!("tidex6-wusdc service: listening on {path}");
    println!(
        "admins: {}, auto_mover: {} — оба бэкенда live (сеть из чипа)",
        config.admins.len(),
        config.auto_mover
    );

    // Сериализация операций (общий процесс — избегаем гонок blockhash).
    let lock = Mutex::new(());
    loop {
        let mut stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let mut buf = Vec::new();
        if stream.read_to_end(&mut buf).await.is_err() {
            continue;
        }
        let req = String::from_utf8_lossy(&buf).to_string();
        let _guard = lock.lock().await;
        let resp = handle(&dev, &mainnet, &config, &req).await;
        drop(_guard);
        let json = match resp {
            Ok(output) => format!("{{\"ok\":true,\"output\":\"{}\"}}", esc(&output)),
            Err(e) => format!("{{\"ok\":false,\"output\":\"{}\"}}", esc(&format!("{e:#}"))),
        };
        let _ = stream.write_all(json.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

/// Диспетчер: сеть+актив из запроса (чипы) → выбор бэкенда → allowlist → op.
async fn handle(dev: &Backend, mainnet: &Backend, config: &Config, req: &str) -> Result<String> {
    use tidex6_core::network::{Asset, Network};
    let op = field_str(req, "op").context("missing op")?;

    // Health-readout (редко нужен UI — чипы сами источник истины).
    if op == "network" {
        return Ok(format!(
            "both|{}",
            format!("{:?}", config.asset()).to_lowercase()
        ));
    }

    // Сеть из запроса (чип Dev/Main) → выбор живого бэкенда + active_network.
    let net = field_str(req, "network")
        .and_then(|s| Network::from_moniker(&s))
        .unwrap_or(Network::Devnet);
    tidex6_ct_lab::config::set_active_network(net);
    let backend = match net {
        Network::Mainnet => mainnet,
        Network::Devnet => dev,
    };
    let rpc = &backend.rpc;
    let payer = &backend.payer;

    // Кошелёк + флаг Telegram-одобрения. Гейт по ним применяется ТОЛЬКО к
    // депозиту (Send) на mainnet — см. "deposit_browser". Withdraw/scan/refund
    // на mainnet свободны (получить своё запрещать нельзя). Devnet открыт весь.
    let wallet = field_str(req, "wallet").unwrap_or_default();
    let approved = field_str(req, "approved").as_deref() == Some("true");

    // Per-request актив (чип USDC/USDT): override, если задан; иначе дефолт.
    if let Some(a) = field_str(req, "asset") {
        if let Some(asset) = Asset::from_symbol(&a) {
            tidex6_ct_lab::config::set_active_asset(asset);
        }
    }
    match op.as_str() {
        "deposit" => {
            let amount = field_num(req, "amount").unwrap_or(2_000_000);
            let (sig, note, commitment) = flow::deposit(rpc, payer, amount).await?;
            Ok(format!(
                "deposit ok\ncommitment: {commitment}\ntx: {sig}\nSolscan: https://solscan.io/tx/{sig}\nnote: {note}"
            ))
        }
        "withdraw" => {
            let note = field_str(req, "note").context("missing note")?;
            let (sig, recipient, payout, amount) = flow::withdraw(rpc, payer, &note).await?;
            let w = if tidex6_ct_lab::config::active_asset() == Asset::Wusdt {
                "wUSDT"
            } else {
                "wUSDC"
            };
            Ok(format!(
                "withdraw ok ({} {w})\nrecipient (fresh): {recipient}\ntx: {sig}\nSolscan: https://solscan.io/tx/{sig}\npayout: {payout}",
                amount as f64 / 1e6
            ))
        }
        "wrap" => {
            let amount = field_num(req, "amount").unwrap_or(2_000_000);
            ct::wrap(rpc.clone(), payer, amount).await
        }
        "configure" => {
            let recipient = field_str(req, "recipient").context("missing recipient")?;
            let mut out = ct::configure_recipient(rpc.clone(), payer, &recipient).await?;
            // Событийный авто-мувер: configure — последний prerequisite (получатель
            // готов) → сразу платим pending payout'ы in-process, без таймера.
            if config.auto_mover {
                out.push_str("\n[auto-mover]\n");
                match ct::mover(rpc.clone(), payer).await {
                    Ok(m) => out.push_str(&m),
                    Err(e) => out.push_str(&format!("auto-mover error: {e:#}")),
                }
            }
            Ok(out)
        }
        // One-shot: весь приватный цикл одним вызовом (сервис сериальный —
        // держит lock на всё время). note/recipient/payout остаются на
        // сервере в ~/.tidex6-wusdc (spend-material), в браузер не уходят.
        "run_all" => {
            use std::fmt::Write as _;
            let amount = field_num(req, "amount").unwrap_or(1_000_000);
            let mut out = String::new();

            let _ = writeln!(out, "━━━━ 1/5 · wrap ━━━━");
            out.push_str(&ct::wrap(rpc.clone(), payer, amount).await.context("wrap")?);

            let _ = writeln!(out, "\n━━━━ 2/5 · deposit ━━━━");
            let (dsig, note_path, commitment) =
                flow::deposit(rpc, payer, amount).await.context("deposit")?;
            let _ = writeln!(
                out,
                "deposit ok\ncommitment: {commitment}\ntx: {dsig}\nSolscan: https://solscan.io/tx/{dsig}"
            );

            let _ = writeln!(out, "\n━━━━ 3/5 · withdraw (fresh address) ━━━━");
            let (wsig, recipient, payout_path, amt) = flow::withdraw(rpc, payer, &note_path)
                .await
                .context("withdraw")?;
            let _ = writeln!(
                out,
                "withdraw ok ({} tokens)\nrecipient (fresh): {recipient}\ntx: {wsig}\nSolscan: https://solscan.io/tx/{wsig}",
                amt as f64 / 1e6
            );

            // recipient-<nh8>.json ↔ payout-<nh8>.json (spend-key лежит на сервере).
            let recipient_file = payout_path
                .rsplit('/')
                .next()
                .and_then(|n| n.strip_prefix("payout-"))
                .and_then(|n| n.strip_suffix(".json"))
                .map(|nh8| format!("recipient-{nh8}.json"))
                .context("recipient file from payout path")?;

            let _ = writeln!(
                out,
                "\n━━━━ 4/5 · configure recipient + confidential payout ━━━━"
            );
            out.push_str(
                &ct::configure_recipient(rpc.clone(), payer, &recipient_file)
                    .await
                    .context("configure")?,
            );
            out.push('\n');
            out.push_str(&ct::mover(rpc.clone(), payer).await.context("mover")?);

            let _ = writeln!(out, "\n━━━━ 5/5 · cash out → operator wallet ━━━━");
            out.push_str(
                &ct::cashout(rpc.clone(), payer, &recipient_file)
                    .await
                    .context("cashout")?,
            );

            let _ = writeln!(out, "\n════ PRIVATE CYCLE COMPLETE ════");
            Ok(out)
        }
        // Депозит из БРАУЗЕРА: нота+конверт сгенерены в табе (WASM), сюда
        // приходят готовыми (commitment + ML-KEM envelope). Сервер обёртывает
        // сумму в wUSDC (CT) и кладёт commitment+конверт в пул — ноту не хранит.
        // Квота для продукт-депозита (юзер платит своими токенами): сколько
        // отправитель платит (amount + fee), кому (operator ATA-owner) и каким
        // underlying-минтом. Браузер по этой квоте строит Phantom-перевод.
        "deposit_quote" => {
            let amount = field_num(req, "amount").unwrap_or(1_000_000);
            let fee = config.fee_micro(amount);
            let total = amount + fee;
            let underlying = ct::usdc_mint(); // active asset уже выставлен по чипу
            Ok(format!(
                "{{\"operator\":\"{}\",\"underlying_mint\":\"{}\",\"amount\":{amount},\"fee\":{fee},\"total\":{total}}}",
                payer.pubkey(),
                underlying
            ))
        }
        "deposit_browser" => {
            use std::fmt::Write as _;
            let amount = field_num(req, "amount").unwrap_or(1_000_000);
            // Гейт mainnet ТОЛЬКО на депозит (Send): белый кошелёк (admin) даёт
            // сразу, иначе — разовое Telegram-одобрение; без него отказ. Плюс кап
            // 1 токен (mainnet_gate). Devnet свободен.
            if net == Network::Mainnet {
                if !config.is_admin(&wallet) && !approved {
                    anyhow::bail!(
                        "Mainnet deposit needs approval — an admin approves it in Telegram."
                    );
                }
                config.mainnet_gate(amount)?;
            }
            let commitment = field_str(req, "commitment").context("missing commitment")?;
            let envelope = field_str(req, "envelope").context("missing envelope")?;
            let revoke = field_num(req, "revoke_window").unwrap_or(600) as i64;
            let commitment = hex32(&commitment).context("commitment: 32-byte hex")?;
            let envelope = hex_bytes(&envelope).context("envelope: hex")?;

            let mut out = String::new();
            // Продукт-модель: отправитель уже заплатил (amount + fee) оператору
            // со своего кошелька (Phantom). Проверяем перевод по payment_sig
            // ПЕРЕД wrap — иначе депозит был бы бесплатным (клиент прислал бы
            // чужой/пустой sig). Без payment_sig — legacy demo-путь (оператор
            // платит сам), оставлен для обкатки/совместимости.
            if let Some(sig_str) = field_str(req, "payment_sig") {
                use std::str::FromStr;
                let fee = config.fee_micro(amount);
                let total = amount + fee;
                let sig = solana_signature::Signature::from_str(&sig_str)
                    .context("payment_sig parse")?;
                let mint: solana_pubkey::Pubkey =
                    ct::usdc_mint().parse().context("underlying mint")?;
                pool::verify_token_payment(rpc, &sig, &payer.pubkey(), &mint, total)
                    .await
                    .context("verify payment")?;
                let _ = writeln!(
                    out,
                    "payment verified: operator received {:.6} from the sender",
                    total as f64 / 1e6
                );
            }
            let _ = writeln!(out, "━━ wrap (confidential backing) ━━");
            out.push_str(&ct::wrap(rpc.clone(), payer, amount).await.context("wrap")?);
            let _ = writeln!(out, "\n━━ deposit (commitment + ML-KEM memo) ━━");
            let (sig, commit_hex) =
                flow::deposit_browser(rpc, payer, commitment, &envelope, revoke)
                    .await
                    .context("deposit")?;
            let _ = writeln!(
                out,
                "deposit ok\ncommitment: {commit_hex}\nmemo: {} bytes\ntx: {sig}\nSolscan: https://solscan.io/tx/{sig}",
                envelope.len()
            );
            Ok(out)
        }
        // Публичный скан конвертов пула для /receive/ и /auditor/. Отдаёт
        // JSON-массив финализированных memo (публичные байты) — расшифровка
        // слотов в браузере ключом ML-KEM. Сумма скрыта (внутри конверта).
        "memo_accounts" => {
            // Скан ОБОИХ пулов (wUSDC + wUSDT): получатель/аудитор находит все
            // свои платежи одним ключом, без выбора актива. Каждый конверт помечен
            // своим активом — чтобы вывод пошёл в правильный пул.
            let mut items = Vec::new();
            for a in [Asset::Wusdc, Asset::Wusdt] {
                tidex6_ct_lab::config::set_active_asset(a);
                let sym = if a == Asset::Wusdt { "wusdt" } else { "wusdc" };
                let memos = pool::fetch_memo_accounts(rpc).await.context("memo scan")?;
                for m in &memos {
                    if !m.is_finalized {
                        continue;
                    }
                    items.push(format!(
                        "{{\"commitment_hex\":\"{}\",\"envelope_hex\":\"{}\",\"depositor\":\"{}\",\"revoke_window\":{},\"created_ts\":{},\"asset\":\"{sym}\"}}",
                        hexs(&m.commitment),
                        hexs(&m.data),
                        m.depositor,
                        m.revoke_window,
                        m.created_ts
                    ));
                }
            }
            Ok(format!("[{}]", items.join(",")))
        }
        // Публичная метрика для главной: число депозитов = PoolState.next_leaf_index.
        // Считаем обе сети × оба актива (лёгкий getAccountInfo на pool PDA, не gPA).
        "stats" => {
            let mut items = Vec::new();
            for (net_name, be) in [("mainnet", mainnet), ("devnet", dev)] {
                let n = if net_name == "mainnet" {
                    Network::Mainnet
                } else {
                    Network::Devnet
                };
                tidex6_ct_lab::config::set_active_network(n);
                for a in [Asset::Wusdc, Asset::Wusdt] {
                    tidex6_ct_lab::config::set_active_asset(a);
                    let count = pool::deposit_count(&be.rpc).await.unwrap_or(0);
                    let sym = if a == Asset::Wusdt { "wusdt" } else { "wusdc" };
                    items.push(format!(
                        "{{\"network\":\"{net_name}\",\"asset\":\"{sym}\",\"count\":{count}}}"
                    ));
                }
            }
            Ok(format!("[{}]", items.join(",")))
        }
        // Путь Меркла для браузерного withdraw (по commitment из скана).
        "merkle_path" => {
            let commitment = field_str(req, "commitment").context("missing commitment")?;
            let commitment = hex32(&commitment).context("commitment: 32-byte hex")?;
            let (root, siblings, indices) = flow::merkle_path_for(rpc, commitment)
                .await
                .context("merkle path")?;
            let idx_json = indices
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!(
                "{{\"root_hex\":\"{root}\",\"siblings_concat_hex\":\"{siblings}\",\"indices\":[{idx_json}]}}"
            ))
        }
        // Проверка «уже получено»: браузер после decrypt шлёт список
        // nullifier_hash (hex, через запятую). Для каждого — существует ли
        // nullifier PDA (создаётся при выводе) = ноту уже вывели. Один batch
        // RPC-запрос (get_multiple_accounts) на весь список.
        "nullifiers_spent" => {
            let list = field_str(req, "nullifier_hashes").unwrap_or_default();
            let mut nhs: Vec<String> = Vec::new();
            let mut pdas: Vec<solana_pubkey::Pubkey> = Vec::new();
            for h in list.split(',') {
                let h = h.trim();
                if h.is_empty() {
                    continue;
                }
                let nh = hex32(h).context("nullifier_hash: 32-byte hex")?;
                pdas.push(pool::nullifier_pda(&nh));
                nhs.push(h.to_lowercase());
            }
            let mut items = Vec::new();
            if !pdas.is_empty() {
                let accounts = rpc
                    .get_multiple_accounts(&pdas)
                    .await
                    .context("get_multiple_accounts (nullifier PDAs)")?;
                for (nh, acc) in nhs.iter().zip(accounts.iter()) {
                    items.push(format!(
                        "{{\"nullifier_hash\":\"{nh}\",\"spent\":{}}}",
                        acc.is_some()
                    ));
                }
            }
            Ok(format!("[{}]", items.join(",")))
        }
        // Браузерный withdraw: Groth16-пруф построен в табе (WASM). Сервер шлёт
        // withdraw-ix (пруф+nullifier) и выплачивает сумму на свежий адрес (CT
        // burn у оператора + vault → recipient).
        "withdraw_browser" => {
            let amount = field_num(req, "amount").unwrap_or(0);
            // Withdraw на mainnet не гейтится и не капится — получить своё
            // (уже задепонированное) запрещать нельзя. Гейт только на депозит.
            let recipient = field_str(req, "recipient").context("missing recipient")?;
            let recipient: solana_pubkey::Pubkey = recipient.parse().context("recipient pubkey")?;
            let proof_a = hex_fixed::<64>(&field_str(req, "proof_a").context("proof_a")?)
                .context("proof_a: 64-byte hex")?;
            let proof_b = hex_fixed::<128>(&field_str(req, "proof_b").context("proof_b")?)
                .context("proof_b: 128-byte hex")?;
            let proof_c = hex_fixed::<64>(&field_str(req, "proof_c").context("proof_c")?)
                .context("proof_c: 64-byte hex")?;
            let root = hex32(&field_str(req, "merkle_root").context("merkle_root")?)
                .context("merkle_root: 32-byte hex")?;
            let nh = hex32(&field_str(req, "nullifier_hash").context("nullifier_hash")?)
                .context("nullifier_hash: 32-byte hex")?;

            let mut out = String::new();
            let sig =
                flow::withdraw_browser(rpc, payer, &recipient, proof_a, proof_b, proof_c, root, nh)
                    .await
                    .context("pool withdraw")?;
            use std::fmt::Write as _;
            let _ = writeln!(
                out,
                "withdraw ok\ntx: {sig}\nSolscan: https://solscan.io/tx/{sig}\n"
            );
            out.push_str(
                &ct::cashout_to_address(rpc.clone(), payer, &recipient, amount)
                    .await
                    .context("cashout to recipient")?,
            );
            Ok(out)
        }
        "mover" => ct::mover(rpc.clone(), payer).await,
        "cashout" => {
            let recipient = field_str(req, "recipient").context("missing recipient")?;
            ct::cashout(rpc.clone(), payer, &recipient).await
        }
        // Devnet-фаусет прямо со страницы: пополнить оператор-кошелёк.
        "airdrop" => {
            if net != Network::Devnet {
                anyhow::bail!("airdrop only on devnet");
            }
            let op_pubkey = payer.pubkey();
            match rpc.request_airdrop(&op_pubkey, 1_000_000_000).await {
                Ok(sig) => {
                    for _ in 0..30 {
                        if rpc.confirm_transaction(&sig).await.unwrap_or(false) {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    let bal = rpc.get_balance(&op_pubkey).await.unwrap_or(0);
                    Ok(format!(
                        "airdropped 1 SOL to operator {op_pubkey}\nbalance: {:.3} SOL\ntx: {sig}",
                        bal as f64 / 1e9
                    ))
                }
                // Public devnet-RPC рейтлимитит фаусет — не наш баг. Даём адрес
                // + веб-фаусет как fallback (или rpc_devnet=Helius в config).
                Err(e) => {
                    let bal = rpc.get_balance(&op_pubkey).await.unwrap_or(0);
                    Ok(format!(
                        "devnet faucet unavailable ({e}).\n\
                         request_airdrop rate-limits on any RPC (Solana faucet infra) — not a config issue.\n\
                         operator: {op_pubkey}\nbalance: {:.3} SOL (already funded — airdrop not needed)\n\
                         if you really need more: fund the operator address at https://faucet.solana.com",
                        bal as f64 / 1e9
                    ))
                }
            }
        }
        other => anyhow::bail!("unknown operation: {other}"),
    }
}

fn field_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let alt = format!("\"{key}\": \"");
    let (start, off) = if let Some(p) = json.find(&needle) {
        (p, needle.len())
    } else {
        (json.find(&alt)?, alt.len())
    };
    let s = start + off;
    let end = json[s..].find('"')? + s;
    Some(json[s..end].to_owned())
}

/// байты → hex (для JSON-ответа memo_accounts).
fn hexs(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0x0f) as usize] as char);
    }
    out
}

/// hex → байты (чёткая длина, только hex-символы).
fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// hex → ровно 32 байта.
fn hex32(s: &str) -> Option<[u8; 32]> {
    hex_fixed::<32>(s)
}

/// hex → ровно N байт.
fn hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = hex_bytes(s)?;
    (v.len() == N).then(|| {
        let mut a = [0u8; N];
        a.copy_from_slice(&v);
        a
    })
}

fn field_num(json: &str, key: &str) -> Option<u64> {
    for needle in [format!("\"{key}\":"), format!("\"{key}\": ")] {
        if let Some(p) = json.find(&needle) {
            let rest = json[p + needle.len()..].trim_start();
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            if let Ok(v) = rest[..end].parse() {
                return Some(v);
            }
        }
    }
    None
}

/// JSON-экранирование вывода (кавычки, слэши, переводы строк).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
