//! Ноты пула со скрытой суммой на EVM — запечатать, открыть, доказать вывод.
//!
//! Одни и те же функции у агента (`tidex6-mcp-local`) и у сборщика казны в
//! релеере. Доказательство вывода — то же, что строит браузер
//! (`proveHiddenWithdrawEvm` в `tidex6-prover-wasm`): схема одна, и копия,
//! разошедшаяся с ней на одну правку, дала бы доказательства, которые пул
//! отвергает.
//!
//! `secret` и `nullifier` не пишутся в лог и не попадают в `Debug`.

use anyhow::{Context, Result, bail};
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::ProvingKey;
use tidex6_confidential::withdraw::{self as hidden, POOL_TREE_DEPTH, WithdrawWitness};
use tidex6_core::envelope::{self, ReaderAddress};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::pqc::PqcSecretKey;
use tidex6_core::types::{Commitment, Nullifier, Secret};

/// Комиссия сервиса — 1% суммы.
pub const FEE_BPS: u64 = 100;
/// Нижний порог комиссии: 0.1 токена в микро-единицах.
pub const FEE_FLOOR_MICRO: u64 = 100_000;

/// Комиссия за платёж, в микро-единицах: 1%, но не меньше 0.1 токена.
///
/// Та же формула, что у страницы отправки (`hiddenPoolFeeMicro`): получатель
/// получает ровно ту сумму, что назвали, комиссия идёт сверху.
pub fn fee_micro(amount_micro: u64) -> u64 {
    let percent = u128::from(amount_micro) * u128::from(FEE_BPS) / 10_000;
    u64::try_from(percent)
        .unwrap_or(u64::MAX)
        .max(FEE_FLOOR_MICRO)
}

/// Нота, готовая лечь в пул: commitment и конверт.
pub struct SealedNote {
    /// `Poseidon(secret, nullifier, amount)` — лист дерева.
    pub commitment: [u8; 32],
    pub envelope: Vec<u8>,
    /// Сумма в базовых единицах токена — её пул и списывает.
    pub amount: u64,
}

impl std::fmt::Debug for SealedNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedNote")
            .field("commitment", &hex::encode(self.commitment))
            .field("envelope_len", &self.envelope.len())
            .field("amount", &self.amount)
            .finish()
    }
}

/// Запечатать ноту читателю.
///
/// # Параметры
/// * `reader` — кому нота: получатель платежа или казна (нота комиссии)
/// * `auditors` — кому раскрыть сумму и назначение, без права траты
/// * `amount_micro` — сумма в микро-единицах; её несёт конверт
/// * `units_per_micro` — базовых единиц токена в микро-единице
/// * `memo` — назначение
///
/// # Возвращает
/// * `SealedNote` — commitment над базовыми единицами и конверт над
///   микро-единицами, как у браузера; сумма, не влезающая в 64 бита, — ошибка
pub fn seal_note(
    reader: &ReaderAddress,
    auditors: &[ReaderAddress],
    amount_micro: u64,
    units_per_micro: u64,
    memo: &str,
) -> Result<SealedNote> {
    let amount = amount_micro
        .checked_mul(units_per_micro)
        .context("a note holds at most 2^64 − 1 base units — split the payment")?;
    // Случайность только у ОС: предсказуемый secret отдаёт платёж чужому.
    let secret = Secret::random().context("secret")?;
    let nullifier = Nullifier::random().context("nullifier")?;
    let leaf = hidden::note_commitment(
        fr(secret.as_bytes()),
        fr(nullifier.as_bytes()),
        Fr::from(amount),
    );
    let envelope = envelope::build(
        reader,
        secret.as_bytes(),
        nullifier.as_bytes(),
        amount_micro,
        memo.as_bytes(),
        auditors,
    )
    .context("seal the envelope")?;
    Ok(SealedNote {
        commitment: fr_to_word(leaf),
        envelope,
        amount,
    })
}

/// Нота, которую открыл наш ключ.
pub struct OpenNote {
    pub leaf_index: u64,
    pub secret: Fr,
    pub nullifier: Fr,
    /// Публичный вход вывода; по нему пул помнит, что нота потрачена.
    pub nullifier_hash: [u8; 32],
    /// Базовые единицы токена.
    pub amount: u64,
    pub amount_micro: u64,
    pub memo: String,
}

impl std::fmt::Debug for OpenNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenNote")
            .field("leaf_index", &self.leaf_index)
            .field("amount", &self.amount)
            .field("secret", &"<redacted>")
            .field("nullifier", &"<redacted>")
            .finish()
    }
}

/// Что вышло из попытки открыть лист.
pub enum Opened {
    /// Нота наша и сходится со своим commitment.
    Mine(OpenNote),
    /// Не наша — обычный случай для почти всех листьев пула.
    NotMine,
    /// Конверт открылся, но сумма в нём не та, что в commitment, или не
    /// влезает в 64 бита. Доказывать такую ноту бесполезно: пул отвергнет.
    Mismatch,
}

/// Открыть лист пула своим ключом.
///
/// # Параметры
/// * `leaf_index`, `commitment_hex`, `envelope_hex` — лист из индекса релеера
/// * `reader_secret` — секретная половина адреса читателя
/// * `units_per_micro` — базовых единиц токена в микро-единице
pub fn open_note(
    leaf_index: u64,
    commitment_hex: &str,
    envelope_hex: &str,
    reader_secret: &PqcSecretKey,
    units_per_micro: u64,
) -> Opened {
    let Ok(envelope_bytes) = hex::decode(envelope_hex.trim_start_matches("0x")) else {
        return Opened::NotMine;
    };
    let Ok(Some(view)) = envelope::open_as_recipient(&envelope_bytes, reader_secret) else {
        return Opened::NotMine;
    };
    let Some(amount) = view.denomination.checked_mul(units_per_micro) else {
        return Opened::Mismatch;
    };
    let secret = Fr::from_be_bytes_mod_order(&view.secret);
    let nullifier = Fr::from_be_bytes_mod_order(&view.nullifier);
    let leaf = hidden::note_commitment(secret, nullifier, Fr::from(amount));
    let claimed = commitment_hex.trim_start_matches("0x").to_lowercase();
    if hex::encode(fr_to_word(leaf)) != claimed {
        return Opened::Mismatch;
    }
    Opened::Mine(OpenNote {
        leaf_index,
        secret,
        nullifier,
        nullifier_hash: fr_to_word(hidden::nullifier_hash(nullifier)),
        amount,
        amount_micro: view.denomination,
        memo: String::from_utf8_lossy(&view.memo).into_owned(),
    })
}

/// Commitment'ы по порядку листьев. Список с дырой отвергается: путь по
/// дереву с пропуском даёт корень, которого у пула никогда не было.
///
/// # Параметры
/// * `leaves` — `(leaf_index, commitment_hex)` в порядке индекса
pub fn leaves_in_order<'a>(
    leaves: impl IntoIterator<Item = (u64, &'a str)>,
) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    for (position, (leaf_index, commitment_hex)) in leaves.into_iter().enumerate() {
        if leaf_index != position as u64 {
            bail!("the deposit list has a hole: leaf {leaf_index} at position {position}");
        }
        let bytes = hex::decode(commitment_hex.trim_start_matches("0x"))
            .with_context(|| format!("leaf {leaf_index}: commitment is not hex"))?;
        let word: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("leaf {leaf_index}: commitment is not 32 bytes"))?;
        out.push(word);
    }
    Ok(out)
}

/// Дерево пула из его листьев.
pub fn build_tree(leaves: &[[u8; 32]]) -> Result<MerkleTree> {
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH).context("tree")?;
    for (index, leaf) in leaves.iter().enumerate() {
        tree.insert(Commitment::from_bytes(*leaf))
            .with_context(|| format!("leaf {index}"))?;
    }
    Ok(tree)
}

/// Доказательство вывода и корень, под который оно построено.
pub struct WithdrawProof {
    /// 256 байт в раскладке, которую читает EVM-верификатор.
    pub proof: Vec<u8>,
    pub root: [u8; 32],
}

/// Кто получает деньги и кто отправляет вывод. Оба — публичные входы
/// доказательства: подменить их после доказательства нельзя.
pub struct WithdrawParties {
    pub recipient: [u8; 20],
    pub relayer: [u8; 20],
    /// Базовые единицы; у пула со скрытой суммой — ноль, комиссия уже
    /// заплачена отдельной нотой при платеже.
    pub relayer_fee: u64,
}

/// Доказать вывод ноты.
///
/// Тяжёлая работа (секунды процессора); асинхронный вызывающий зовёт её из
/// `spawn_blocking`. Трассировка на время доказательства выключена: под
/// логгером arkworks держит живой span на каждое ограничение, и так сборщик
/// дорос до 50 ГБ 24.09.2026.
pub fn prove_withdraw(
    proving_key: &ProvingKey<Bn254>,
    tree: &MerkleTree,
    note: &OpenNote,
    parties: &WithdrawParties,
) -> Result<WithdrawProof> {
    let path = tree
        .proof(note.leaf_index)
        .with_context(|| format!("leaf {}: merkle path", note.leaf_index))?;
    let root = tree.root().to_bytes();
    let witness = WithdrawWitness {
        amount: note.amount,
        secret: note.secret,
        nullifier: note.nullifier,
        path_siblings: std::array::from_fn(|i| fr(path.siblings[i].as_bytes())),
        path_indices: std::array::from_fn(|i| (note.leaf_index >> i) & 1 == 1),
        merkle_root: fr(&root),
        recipient: address_word(parties.recipient),
        relayer: address_word(parties.relayer),
        relayer_fee: parties.relayer_fee,
    };
    let mut rng = rand::thread_rng();
    let (proof, _) = crate::confidential::prover_runtime::without_tracing(|| {
        hidden::prove_ceremony(proving_key, &witness, &mut rng)
    })
    .map_err(|e| anyhow::anyhow!("leaf {}: prove: {e}", note.leaf_index))?;
    Ok(WithdrawProof {
        proof: tidex6_circuits::evm_solidity::groth16_proof_to_evm_bytes(&proof).to_vec(),
        root,
    })
}

fn fr(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Элемент поля как 32-байтное слово big-endian.
pub fn fr_to_word(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    word
}

/// Адрес EVM так, как его берёт схема: дополнен нулями слева до 32 байт.
pub fn address_word(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address);
    word
}
