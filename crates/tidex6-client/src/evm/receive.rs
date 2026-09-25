//! Найти свои платежи в пуле и забрать их — без газа у получателя.
//!
//! Список листьев отдаёт индекс релеера (`/evm-deposits/`), тот же, что
//! читает страница: одним ответом вместо сотен окон `eth_getLogs`. Индексу
//! при этом доверять не нужно: корень, пересобранный из списка, пул сверяет
//! сам, и неполный список обходится отказом до отправки, а не деньгами.
//!
//! Вывод отправляет релеер (`/evm-withdraw/`): у получателя может не быть
//! газа на этой цепи вовсе. Адрес релеера — публичный вход доказательства,
//! поэтому он спрашивается до доказательства (`/evm-relayer/`).

use anyhow::{Context, Result, bail};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use serde::Deserialize;
use serde_json::json;

use crate::confidential::LocalIdentity;

use super::note::{
    OpenNote, Opened, WithdrawParties, build_tree, leaves_in_order, open_note, prove_withdraw,
};
use super::pools::EvmPool;
use super::rpc::Node;
use super::send::address_word;

/// Релеер tidex6 по умолчанию.
pub const DEFAULT_RELAYER: &str = "https://relayer.tidex6.com";

/// `nullifierSpent(uint256)`.
const SEL_NULLIFIER_SPENT: [u8; 4] = [0x69, 0xaa, 0x80, 0x88];

/// Лист пула, как его отдаёт индекс релеера.
#[derive(Debug, Clone, Deserialize)]
pub struct DepositRecord {
    #[serde(rename = "leafIndex")]
    pub leaf_index: u64,
    #[serde(rename = "commitmentHex")]
    pub commitment_hex: String,
    #[serde(rename = "envelopeHex")]
    pub envelope_hex: String,
    #[serde(rename = "txHash")]
    pub tx_hash: String,
    #[serde(rename = "sentTs", default)]
    pub sent_ts: u64,
}

#[derive(Deserialize)]
struct Snapshot {
    deposits: Vec<DepositRecord>,
}

/// Наша нота и потрачена ли она.
#[derive(Debug)]
pub struct MyNote {
    pub note: OpenNote,
    pub is_spent: bool,
    pub tx_hash: String,
    pub sent_ts: u64,
}

/// Клиент релеера.
pub struct Relayer {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl Relayer {
    pub fn new(base_url: &str) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            // Вывод ждёт включения транзакции — до трёх минут на тестнете.
            .timeout(std::time::Duration::from_secs(240))
            .build()
            .context("http client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Все листья пула по порядку.
    ///
    /// Индекс, не закончивший первый проход, отвечает 503: пустой список в
    /// этот момент значил бы «платежей нет», а это неправда.
    pub fn deposits(&self, pool: &EvmPool) -> Result<Vec<DepositRecord>> {
        let url = format!(
            "{}/evm-deposits/?chain={}&pool=hidden",
            self.base_url, pool.key
        );
        let reply = self
            .http
            .get(&url)
            .send()
            .context("the relayer did not answer")?;
        if !reply.status().is_success() {
            bail!("{}: {}", pool.key, reply.text().unwrap_or_default());
        }
        let snapshot: Snapshot = reply.json().context("unreadable deposit list")?;
        Ok(snapshot.deposits)
    }

    /// Адрес, который релеер ставит в вывод, — вход доказательства.
    fn address(&self, pool: &EvmPool) -> Result<[u8; 20]> {
        #[derive(Deserialize)]
        struct Info {
            relayer: String,
        }
        let url = format!("{}/evm-relayer/?chain={}", self.base_url, pool.key);
        let info: Info = self
            .http
            .get(&url)
            .send()
            .context("the relayer did not answer")?
            .json()
            .context("unreadable relayer info")?;
        let word = address_word(&info.relayer)?;
        Ok(word[12..].try_into()?)
    }

    fn withdraw(&self, body: serde_json::Value) -> Result<String> {
        #[derive(Deserialize)]
        struct Sent {
            tx_hash: String,
        }
        let reply = self
            .http
            .post(format!("{}/evm-withdraw/", self.base_url))
            .json(&body)
            .send()
            .context("the relayer did not answer")?;
        if !reply.status().is_success() {
            bail!("withdrawal refused: {}", reply.text().unwrap_or_default());
        }
        Ok(reply.json::<Sent>().context("unreadable answer")?.tx_hash)
    }
}

/// Прочитать ключ доказательства вывода (`hidden_withdraw_pk.bin`).
///
/// Файл весит десятки мегабайт; читается один раз на вызов `collect`, а не на
/// каждую ноту.
pub fn load_proving_key(path: &std::path::Path) -> Result<ProvingKey<Bn254>> {
    use ark_serialize::CanonicalDeserialize;
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&bytes[..])
        .map_err(|e| anyhow::anyhow!("{}: not a proving key: {e}", path.display()))
}

/// Свои ноты в пуле: открытые нашим ключом и сверенные с commitment.
///
/// # Параметры
/// * `leaves` — список листьев пула из [`Relayer::deposits`]
/// * `identity` — наша личность: её ключом чтения открываются ноты
pub fn my_notes(
    pool: &EvmPool,
    leaves: &[DepositRecord],
    identity: &LocalIdentity,
) -> Result<Vec<MyNote>> {
    let node = Node::new(pool.read_url)?;
    let units = pool.base_units_per_micro();
    let mut out = Vec::new();
    for record in leaves {
        let Opened::Mine(note) = open_note(
            record.leaf_index,
            &record.commitment_hex,
            &record.envelope_hex,
            identity.reader_secret(),
            units,
        ) else {
            continue;
        };
        let data = [&SEL_NULLIFIER_SPENT[..], &note.nullifier_hash].concat();
        let answer = node.eth_call(pool.hidden_pool, &data)?;
        out.push(MyNote {
            is_spent: answer.last() == Some(&1),
            note,
            tx_hash: record.tx_hash.clone(),
            sent_ts: record.sent_ts,
        });
    }
    Ok(out)
}

/// Забрать одну ноту на `recipient` через релеер.
///
/// # Параметры
/// * `leaves` — все листья пула: путь по дереву требует каждого соседа
/// * `note` — непотраченная нота из [`my_notes`]
/// * `recipient` — куда уходят деньги, `0x…`
///
/// # Возвращает
/// * `Result<String>` — хеш транзакции вывода
pub fn collect_note(
    pool: &EvmPool,
    relayer: &Relayer,
    proving_key: &ProvingKey<Bn254>,
    leaves: &[DepositRecord],
    note: &OpenNote,
    recipient: &str,
) -> Result<String> {
    let ordered = leaves_in_order(
        leaves
            .iter()
            .map(|r| (r.leaf_index, r.commitment_hex.as_str())),
    )?;
    let tree = build_tree(&ordered)?;
    let recipient_word = address_word(recipient)?;
    let parties = WithdrawParties {
        recipient: recipient_word[12..].try_into()?,
        relayer: relayer.address(pool)?,
        // Комиссия заплачена нотой казне при платеже; второй раз её не берут.
        relayer_fee: 0,
    };
    let proof = prove_withdraw(proving_key, &tree, note, &parties)?;
    relayer.withdraw(json!({
        "chain": pool.key,
        "pool": "hidden",
        "proof_hex": hex::encode(&proof.proof),
        "merkle_root_hex": hex::encode(proof.root),
        "nullifier_hash_hex": hex::encode(note.nullifier_hash),
        "recipient": recipient,
        "fee": "0",
        "amount": note.amount.to_string(),
    }))
}
