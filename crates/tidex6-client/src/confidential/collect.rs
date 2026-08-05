//! Забрать найденный платёж — без браузера, своим ключом.
//!
//! Отправка и приём несимметричны, и это устройство протокола, а не недоделка
//! обвязки. Отправить — сложить конверт и записать хеш в дерево: одна
//! транзакция, никаких доказательств. Забрать — доказать в нуле, что ты знаешь
//! секрет ноты, лежащей где-то в дереве на двадцать уровней, не показав, какой
//! именно. Отсюда три шага вместо одного.
//!
//! **Транзакцию отправляет служба, не мы.** Доказательство считается здесь, на
//! машине владельца ключа, и уходит службе готовым — она лишь передаёт его
//! верификатору. Поэтому забор не требует ни соединения с узлом Solana, ни
//! совпадения версий солановских крейтов: HTTP и арифметика.
//!
//! Секрет ноты при этом никуда не уходит: в запросе к службе едет
//! доказательство и публичные входы, а `secret` остаётся в этом процессе.
//!
//! CLI и local MCP зовут **один** код: [`collect_waiting`] (все waiting-ноты)
//! и [`collect_with_progress`] (одна нота). Входы разные (терминал / tool),
//! крипто-путь один.

use anchor_client::anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::thread_rng;
use serde::Deserialize;
use solana_rpc_client::rpc_client::RpcClient;
use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::withdraw::{
    WITHDRAW_TREE_DEPTH, WithdrawWitness, prove_withdraw, relayer_fee_bytes_from_u64,
};
use tidex6_core::network::{Asset, Network};
use tidex6_core::types::Nullifier;

use crate::confidential::local::LocalIdentity;
use crate::confidential::prover_runtime::init_prover_runtime;
use crate::confidential::scan::{ReadAs, SpendMaterial, scan};
use crate::confidential::send::PoolService;

/// Путь ноты в дереве — ответ службы на `merkle_path`.
///
/// Имена полей — те, что служба отдаёт на самом деле, и это тот же ответ, что
/// разбирает браузер. Одна форма на оба пути: разойдись они, забор из агента и
/// забор из вкладки чинились бы порознь.
#[derive(Debug, Deserialize)]
pub struct MerklePath {
    /// Корень, против которого будет проверяться доказательство, hex.
    #[serde(rename = "root_hex")]
    pub root: String,
    /// Все двадцать соседей одной строкой: 20 × 32 байта, hex, снизу вверх.
    #[serde(rename = "siblings_concat_hex")]
    pub siblings_concat: String,
    /// Куда идти на каждом уровне: 0 — лист слева, 1 — справа. Снизу вверх.
    pub indices: Vec<u8>,
}

/// Чем кончился забор одной ноты.
#[derive(Debug)]
pub struct Collected {
    /// Подпись транзакции вывода.
    pub signature: String,
    /// Куда ушли деньги.
    pub recipient: String,
    /// Сколько.
    pub amount_micro: u64,
}

/// Одна успешно забранная нота из [`collect_waiting`].
#[derive(Debug)]
pub struct CollectedNote {
    pub signature: String,
    pub amount_micro: u64,
    pub symbol: &'static str,
    pub asset: Asset,
}

/// Итог [`collect_waiting`]: все waiting-ноты USDC+USDT.
#[derive(Debug)]
pub struct CollectWaitingResult {
    pub notes: Vec<CollectedNote>,
    pub recipient: String,
    /// Сколько waiting-нот увидели (включая те, на которых остановились с ошибкой).
    pub waiting_found: usize,
    /// Ошибка на одной из нот; уже забранные до неё лежат в `notes`.
    pub stopped_by: Option<String>,
}

impl CollectWaitingResult {
    /// Сколько микро по каждому символу, для отчёта.
    pub fn totals_line(&self) -> String {
        if self.notes.is_empty() {
            return "nothing".to_string();
        }
        let mut totals: Vec<(&'static str, u64)> = Vec::new();
        for n in &self.notes {
            match totals.iter_mut().find(|(s, _)| *s == n.symbol) {
                Some((_, t)) => *t += n.amount_micro,
                None => totals.push((n.symbol, n.amount_micro)),
            }
        }
        totals
            .iter()
            .map(|(symbol, total)| {
                let whole = total / 1_000_000;
                let frac = total % 1_000_000;
                let amount = if frac == 0 {
                    whole.to_string()
                } else {
                    format!("{whole}.{frac:06}")
                        .trim_end_matches('0')
                        .to_string()
                };
                format!("{amount} {symbol}")
            })
            .collect::<Vec<_>>()
            .join(" + ")
    }
}

/// Забрать **все** waiting-ноты этого identity в сети — USDC, затем USDT.
///
/// Это та функция, которую зовут **и CLI, и local MCP**. Цикл scan →
/// [`collect_with_progress`] на каждую waiting-ноту — здесь, не в обвязке.
///
/// `on_step` — редкие вехи (например `prove_withdraw_*`); без dense TRACE.
pub fn collect_waiting(
    rpc_url: &str,
    service: &PoolService,
    identity: &LocalIdentity,
    proving_key_path: &str,
    network: Network,
    recipient: &str,
    mut on_step: impl FnMut(&str),
) -> Result<CollectWaitingResult> {
    // Long-lived hosts (MCP) must pin rayon before the first prove.
    init_prover_runtime();

    let wallet = identity.wallet.to_string();
    let rpc = RpcClient::new_with_timeout(rpc_url.to_string(), std::time::Duration::from_secs(60));
    let mut notes: Vec<CollectedNote> = Vec::new();
    let mut waiting_found = 0usize;
    let mut stopped_by: Option<String> = None;

    'assets: for asset in [Asset::Wusdc, Asset::Wusdt] {
        let Some(info) = network.asset(asset) else {
            continue;
        };
        let Some(program) = info.pool_program else {
            continue;
        };
        let symbol = info.symbol.trim_start_matches('w');
        let program = program
            .parse()
            .with_context(|| format!("pool program for {symbol}"))?;
        let report = scan(&rpc, &program, identity, ReadAs::Recipient)
            .with_context(|| format!("scan {symbol}"))?;

        for payment in &report.payments {
            if payment.is_collected != Some(false) {
                continue;
            }
            let Some(spend) = payment.spend.as_ref() else {
                continue;
            };
            waiting_found += 1;
            let amount = payment.amount_micro as f64 / 1e6;
            let note_label = format!("{symbol}_{amount}");

            match collect_with_progress(
                service,
                proving_key_path,
                spend,
                payment.commitment,
                payment.amount_micro,
                asset,
                network,
                recipient,
                &wallet,
                |lib_step| on_step(&format!("note_{note_label}:{lib_step}")),
            ) {
                Ok(done) => {
                    notes.push(CollectedNote {
                        signature: done.signature,
                        amount_micro: payment.amount_micro,
                        symbol,
                        asset,
                    });
                }
                Err(e) => {
                    stopped_by = Some(format!("{e:#}"));
                    break 'assets;
                }
            }
        }
    }

    Ok(CollectWaitingResult {
        notes,
        recipient: recipient.to_string(),
        waiting_found,
        stopped_by,
    })
}

/// Забрать один платёж (без callback). См. [`collect_with_progress`].
#[allow(clippy::too_many_arguments)]
pub fn collect(
    service: &PoolService,
    proving_key_path: &str,
    spend: &SpendMaterial,
    commitment: [u8; 32],
    amount_micro: u64,
    asset: Asset,
    network: Network,
    recipient: &str,
    wallet: &str,
) -> Result<Collected> {
    collect_with_progress(
        service,
        proving_key_path,
        spend,
        commitment,
        amount_micro,
        asset,
        network,
        recipient,
        wallet,
        |_| {},
    )
}

/// Забрать один платёж. `on_step` зовётся только вокруг hang-site (`prove_withdraw_*`).
// Аргументов много, и каждый — отдельное решение вызывающего: какую ноту,
// куда, в какой сети. Сворачивать их в структуру ради счётчика значит завести
// тип, существующий только чтобы пройти проверку.
#[allow(clippy::too_many_arguments)]
pub fn collect_with_progress(
    service: &PoolService,
    proving_key_path: &str,
    spend: &SpendMaterial,
    commitment: [u8; 32],
    amount_micro: u64,
    asset: Asset,
    network: Network,
    recipient: &str,
    wallet: &str,
    mut on_step: impl FnMut(&str),
) -> Result<Collected> {
    // 1. Где нота лежит в дереве. Спрашиваем службу: полное дерево живёт у неё,
    //    держать его копию здесь значило бы читать всю цепочку ради одной ноты.
    let path = service
        .merkle_path(&hex(&commitment), asset, network, wallet)
        .context("ask the pool where this note sits in the tree")?;

    let root = hex_to_32(&path.root).context("merkle root from the service")?;
    // Соседи приходят склеенными в одну строку — режем по 32 байта.
    let concat = path.siblings_concat.trim().trim_start_matches("0x");
    if concat.len() != WITHDRAW_TREE_DEPTH * 64 {
        anyhow::bail!(
            "the tree path is {} hex characters, the circuit expects {} ({WITHDRAW_TREE_DEPTH} levels)",
            concat.len(),
            WITHDRAW_TREE_DEPTH * 64
        );
    }
    let siblings: Vec<[u8; 32]> = (0..WITHDRAW_TREE_DEPTH)
        .map(|i| hex_to_32(&concat[i * 64..(i + 1) * 64]))
        .collect::<Result<_>>()
        .context("merkle siblings from the service")?;
    if path.indices.len() != WITHDRAW_TREE_DEPTH {
        anyhow::bail!(
            "the path has {} turns, the circuit expects {WITHDRAW_TREE_DEPTH}",
            path.indices.len()
        );
    }
    // Схема ждёт ровно двадцать соседей массивом: длину мы уже проверили выше,
    // так что развернуть вектор в массив здесь безопасно.
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] = std::array::from_fn(|i| &siblings[i]);
    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = path.indices[i] == 1;
    }

    // 2. Доказательство. Считается здесь — секрет ноты не покидает процесс.
    let nullifier_hash = Nullifier::from_bytes(spend.nullifier)
        .derive_hash()
        .context("nullifier hash")?
        .to_bytes();
    let recipient_pubkey: Pubkey = recipient
        .parse()
        .context("recipient must be a Solana address")?;
    let recipient_bytes = recipient_pubkey.to_bytes();
    // Без релеера: платим сами, комиссия ему нулевая. Поле всё равно в схеме —
    // его молчаливое отсутствие переписало бы публичные входы.
    let relayer_fee = relayer_fee_bytes_from_u64(0);

    let key_bytes = std::fs::read(proving_key_path).with_context(|| {
        format!("no proving key at {proving_key_path} — it ships with the repository")
    })?;
    // `_unchecked`, как и на всех остальных путях проекта. Проверяемый вариант
    // умножает на порядок группы каждую точку ключа, а их здесь десятки тысяч:
    // забор считался бы десять минут вместо секунды. Защиты это не даёт —
    // испорченный ключ даст неверное доказательство, и его отвергнет
    // верификатор, а не наша загрузка.
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&key_bytes[..])
        .context("the proving key could not be read")?;
    drop(key_bytes);

    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: &spend.secret,
        nullifier: &spend.nullifier,
        path_siblings: sibling_refs,
        path_indices,
        merkle_root: &root,
        nullifier_hash: &nullifier_hash,
        recipient: &recipient_bytes,
        relayer_address: &recipient_bytes,
        relayer_fee: &relayer_fee,
    };
    // RNG — из энтропии системы, не с фиксированным зерном: одинаковое зерно
    // делает два доказательства по одной ноте связуемыми, а это ровно та
    // связь, которую пул и прячет.
    //
    // Hang site under MCP: generate_constraints → merkle Poseidon (see
    // withdraw_gc: merkle_L* lines). HARD_TIMEOUT lives in MCP host.
    on_step("prove_withdraw_start");
    let (proof, _public_inputs) =
        prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&pk, witness, &mut thread_rng())
            .context("build the withdrawal proof")?;
    on_step("prove_withdraw_ok");

    let bytes: Groth16SolanaBytes =
        groth16_to_solana_bytes(&proof, &pk.vk).context("proof to on-chain layout")?;
    drop(pk);

    // 3. Отдаём доказательство службе — транзакцию в верификатор шлёт она.
    let signature = service
        .withdraw(
            &hex(&bytes.proof_a),
            &hex(&bytes.proof_b),
            &hex(&bytes.proof_c),
            &hex(&root),
            &hex(&nullifier_hash),
            recipient,
            amount_micro,
            asset,
            network,
            wallet,
        )
        .context("hand the proof to the pool")?;

    Ok(Collected {
        signature,
        recipient: recipient.to_string(),
        amount_micro,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 {
        anyhow::bail!("expected 32 bytes as hex, got {} characters", s.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).context("not hexadecimal")?;
    }
    Ok(out)
}
