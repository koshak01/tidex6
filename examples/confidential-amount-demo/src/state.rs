//! Локальное состояние демо: JSON-файл со списком аккаунтов.
//!
//! Каждый аккаунт хранит:
//! - `public_commitment` — то что увидел бы наблюдатель на chain.
//!   32 байта компрессированной G1 точки.
//! - `private_balance` / `private_blinding` — реальная сумма и
//!   суммарный blinding factor. Эту пару держит **владелец
//!   аккаунта**; в реальной системе private_blinding шифруется
//!   под его ElGamal ключ и тоже кладётся в chain, чтобы
//!   владелец мог восстановить состояние после потери локального
//!   файла.
//!
//! В демо мы храним это всё в одном файле — и public, и private —
//! чтобы удобно играть одним процессом за обоих пользователей.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};

use crate::pedersen::{self, Commitment, POINT_LEN};

/// То что мы сериализуем в JSON для одного аккаунта.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountEntry {
    /// `Com(balance, sum_blinding)` — публичный коммитмент. Hex 64.
    pub public_commitment_hex: String,
    /// Реальный баланс (приватная информация владельца).
    pub private_balance: u64,
    /// Суммарный blinding factor после всех транзакций. Hex 64.
    /// В настоящей системе не лежал бы рядом с public — здесь
    /// для удобства демо.
    pub private_blinding_hex: String,
}

/// Весь state демо: отображение `name → AccountEntry`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DemoState {
    pub accounts: BTreeMap<String, AccountEntry>,
}

impl DemoState {
    /// Прочитать JSON-файл, либо вернуть пустой state если файла нет.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)?;
        let state: DemoState = serde_json::from_str(&raw)?;
        Ok(state)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Открыть новый аккаунт с нулевым балансом и свежим blinding.
    /// Публичный коммитмент = `Com(0, r)` = `h^r` — по нему никто
    /// не сможет понять что это ноль vs большое число (без знания r).
    pub fn open_account(&mut self, name: &str) -> anyhow::Result<()> {
        if self.accounts.contains_key(name) {
            anyhow::bail!("account `{name}` already exists");
        }
        let blinding = pedersen::fresh_blinding()?;
        let commitment = Commitment::zero_with_blinding(blinding);
        let entry = AccountEntry {
            public_commitment_hex: hex_encode(&commitment.to_bytes()),
            private_balance: 0,
            private_blinding_hex: fr_to_hex(&blinding),
        };
        self.accounts.insert(name.to_string(), entry);
        Ok(())
    }

    /// Наивный deposit — увеличиваем баланс на `amount`. В реальной
    /// системе deposit'ит SOL и amount раскрывается (т.к. он пришёл
    /// из публичного source). Здесь просто имитируем.
    pub fn deposit(&mut self, name: &str, amount: u64) -> anyhow::Result<()> {
        let entry = self
            .accounts
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{name}`"))?
            .clone();

        let old_blinding = fr_from_hex(&entry.private_blinding_hex)?;

        // Свежий blinding для «добавочного» commitment'а, складываем
        // гомоморфно с существующим.
        let extra_blinding = pedersen::fresh_blinding()?;
        let delta_commitment = Commitment::create(amount, extra_blinding);
        let old_commitment =
            Commitment::from_bytes(&hex_decode::<POINT_LEN>(&entry.public_commitment_hex)?)?;
        let new_commitment = old_commitment.add(&delta_commitment);

        let new_blinding = old_blinding + extra_blinding;
        let new_balance = entry.private_balance + amount;

        let updated = AccountEntry {
            public_commitment_hex: hex_encode(&new_commitment.to_bytes()),
            private_balance: new_balance,
            private_blinding_hex: fr_to_hex(&new_blinding),
        };
        self.accounts.insert(name.to_string(), updated);
        Ok(())
    }

    /// Перевод `amount` от `from` к `to`. Гомоморфно обновляет оба
    /// commitment'а: из sender вычитаем `Com(amount, r_t)`, к
    /// receiver'у прибавляем то же самое с тем же r_t.
    ///
    /// **r_t** называется «transfer blinding». В настоящей системе
    /// его надо было бы передать получателю зашифрованно (через
    /// ElGamal под его pubkey) чтобы он мог восстановить свой
    /// `sum_blinding`. Здесь — раз state общий, мы просто обновляем
    /// оба blinding factor'а в одном файле.
    pub fn transfer(&mut self, from: &str, to: &str, amount: u64) -> anyhow::Result<()> {
        if from == to {
            anyhow::bail!("sender and recipient must differ");
        }
        let sender = self
            .accounts
            .get(from)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{from}`"))?
            .clone();
        let receiver = self
            .accounts
            .get(to)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{to}`"))?
            .clone();

        if sender.private_balance < amount {
            anyhow::bail!(
                "account `{from}` only has {} — cannot send {amount}",
                sender.private_balance
            );
        }

        let transfer_blinding = pedersen::fresh_blinding()?;
        let transfer_commitment = Commitment::create(amount, transfer_blinding);

        let sender_old_blinding = fr_from_hex(&sender.private_blinding_hex)?;
        let sender_old_commitment =
            Commitment::from_bytes(&hex_decode::<POINT_LEN>(&sender.public_commitment_hex)?)?;
        let sender_new_commitment = sender_old_commitment.sub(&transfer_commitment);
        let sender_new_blinding = sender_old_blinding - transfer_blinding;

        let receiver_old_blinding = fr_from_hex(&receiver.private_blinding_hex)?;
        let receiver_old_commitment =
            Commitment::from_bytes(&hex_decode::<POINT_LEN>(&receiver.public_commitment_hex)?)?;
        let receiver_new_commitment = receiver_old_commitment.add(&transfer_commitment);
        let receiver_new_blinding = receiver_old_blinding + transfer_blinding;

        self.accounts.insert(
            from.to_string(),
            AccountEntry {
                public_commitment_hex: hex_encode(&sender_new_commitment.to_bytes()),
                private_balance: sender.private_balance - amount,
                private_blinding_hex: fr_to_hex(&sender_new_blinding),
            },
        );
        self.accounts.insert(
            to.to_string(),
            AccountEntry {
                public_commitment_hex: hex_encode(&receiver_new_commitment.to_bytes()),
                private_balance: receiver.private_balance + amount,
                private_blinding_hex: fr_to_hex(&receiver_new_blinding),
            },
        );

        Ok(())
    }

    /// Проверить, что `public_commitment` действительно соответствует
    /// заявленному (balance, blinding). Это то что делает «владелец»
    /// при декодировании своего счёта — верифицирует что сервер не
    /// обманывает.
    pub fn verify_owner_view(&self, name: &str) -> anyhow::Result<bool> {
        let entry = self
            .accounts
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{name}`"))?;
        let blinding = fr_from_hex(&entry.private_blinding_hex)?;
        let expected = Commitment::create(entry.private_balance, blinding);
        let actual = Commitment::from_bytes(&hex_decode::<POINT_LEN>(&entry.public_commitment_hex)?)?;
        Ok(expected == actual)
    }
}

// ──────────────────────────────────────────────────────────────
// Hex helpers (локальные, чтобы не тащить hex-крейт в демо).
// ──────────────────────────────────────────────────────────────

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode<const N: usize>(input: &str) -> anyhow::Result<[u8; N]> {
    let stripped = input.strip_prefix("0x").unwrap_or(input);
    if stripped.len() != N * 2 {
        anyhow::bail!("expected {} hex chars, got {}", N * 2, stripped.len());
    }
    let mut out = [0u8; N];
    for (i, chunk) in stripped.as_bytes().chunks(2).enumerate() {
        let hi = nibble(chunk[0])?;
        let lo = nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(byte: u8) -> anyhow::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(anyhow::anyhow!("invalid hex character 0x{byte:02x}")),
    }
}

pub fn fr_to_hex(scalar: &Fr) -> String {
    let mut bytes = [0u8; 32];
    scalar
        .serialize_compressed(&mut bytes[..])
        .expect("Fr serialises into 32 bytes");
    hex_encode(&bytes)
}

pub fn fr_from_hex(input: &str) -> anyhow::Result<Fr> {
    let bytes = hex_decode::<32>(input)?;
    Ok(Fr::from_le_bytes_mod_order(&bytes))
}
