//! Ноты формата v2 на EVM (ADR-022): запечатать, открыть, доказать вывод,
//! заплатить в пул и опубликовать ключ владельца.
//!
//! Отличия от v1 для клиента:
//!
//! - отправитель передаёт пулу **ядро** ноты (кому и случайность), а лист пул
//!   считает сам из полученной суммы — сумму нельзя соврать;
//! - нота привязана к ключу владельца получателя: его берут из реестра
//!   `Tidex6OwnerKeys`, а потратить её может только владелец ключа траты;
//! - комиссию пул берёт сам: отправитель лишь приносит случайность ноты
//!   комиссии и конверт казне, сумму и владельца назначает пул.
//!
//! Конверт v2 — тот же ML-KEM-конверт, в слоте получателя вместо
//! `secret ‖ nullifier` лежат `rho ‖ aux`: владелец восстанавливает по ним
//! ядро своей ноты. Сумма в конверте — **в базовых единицах токена**, не в
//! микро: комиссию считает пул (1% с округлением вверх), и у 18-значного
//! токена она не обязана делиться на микро-единицу, а лист казна пересчитать
//! обязана. 64 бита базовых единиц — тот же предел, что держит сам пул.

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail};
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::ProvingKey;
use tidex6_confidential::note_v2;
use tidex6_confidential::withdraw_v2::{self, WithdrawV2Witness};
use tidex6_core::envelope::{self, ReaderAddress};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::pqc::PqcSecretKey;
use tidex6_core::types::Secret;

use super::note::{WithdrawParties, WithdrawProof, address_word, fr_to_word};
use super::pools::EvmPool;
use super::rpc::{Call, Node, send_call};

/// `deposit(uint256,uint256,uint256,bytes,uint256,bytes)` пула v2.
const SEL_DEPOSIT: [u8; 4] = [0xe0, 0xb7, 0xf3, 0x2b];
/// `feeFor(uint256)`.
const SEL_FEE_FOR: [u8; 4] = [0xad, 0x6f, 0x49, 0xa3];
/// `ownerKeyOf(address)` реестра ключей владельца.
const SEL_OWNER_KEY_OF: [u8; 4] = [0xae, 0xbc, 0x7e, 0x98];
/// `publishOwnerKey(uint256)`.
const SEL_PUBLISH_OWNER_KEY: [u8; 4] = [0x5d, 0x1a, 0xe8, 0xb1];
/// `refund(uint256,uint256,uint256,uint256,uint256)`.
const SEL_REFUND: [u8; 4] = [0x03, 0x03, 0xf2, 0xe0];
const SEL_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const SEL_ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
const SEL_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// Нота, которую отправитель несёт в пул: ядро и конверт. Сумму к ядру
/// добавит пул.
pub struct SealedCore {
    pub core: [u8; 32],
    pub envelope: Vec<u8>,
}

impl std::fmt::Debug for SealedCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedCore")
            .field("core", &hex::encode(self.core))
            .field("envelope_len", &self.envelope.len())
            .finish()
    }
}

/// Запечатать платёж владельцу `owner_pk`.
///
/// # Параметры
/// * `reader` — адрес читателя получателя: ему уходит конверт
/// * `owner_pk` — ключ владельца получателя из реестра: к нему привязана нота
/// * `auditors` — кому раскрыть сумму и назначение
/// * `amount` — сумма для конверта, базовые единицы токена
/// * `funder` — свой адрес чтения, если платёж можно вернуть: в конверт ляжет
///   копия ноты для отправителя, и возврат соберётся по цепи с любого
///   устройства, без хранения чего-либо у себя
pub fn seal_payment(
    reader: &ReaderAddress,
    owner_pk: &[u8; 32],
    auditors: &[ReaderAddress],
    amount: u64,
    memo: &str,
    funder: Option<&ReaderAddress>,
) -> Result<SealedCore> {
    let rho = random_field()?;
    let aux = [0u8; 32];
    let core = note_v2::core(fr(owner_pk), fr(&rho), fr(&aux));
    let mut envelope = envelope::build(reader, &rho, &aux, amount, memo.as_bytes(), auditors)
        .context("seal the envelope")?;
    if let Some(funder) = funder {
        let copy = envelope::FunderView {
            owner_pk: *owner_pk,
            rho,
            aux,
            amount,
        };
        envelope::add_funder_slot(&mut envelope, funder, &copy)
            .context("seal the funder's copy")?;
    }
    Ok(SealedCore {
        core: fr_to_word(core),
        envelope,
    })
}

/// Случайность ноты комиссии и конверт казне. Ядро ноты комиссии пул
/// строит сам из ключа казны — казна найдёт по конверту свою `rho`.
/// `fee` — базовые единицы, ровно та сумма, что назовёт пул ([`fee_for`]).
pub fn seal_fee(treasury: &ReaderAddress, fee: u64) -> Result<([u8; 32], Vec<u8>)> {
    let rho = random_field()?;
    let envelope = envelope::build(treasury, &rho, &[0u8; 32], fee, b"fee", &[])
        .context("seal the fee envelope")?;
    Ok((rho, envelope))
}

/// Лист пула v2, как его отдаёт индекс релеера.
pub struct LeafRecord<'a> {
    pub leaf_index: u64,
    pub commitment_hex: &'a str,
    pub envelope_hex: &'a str,
    /// Кто внёс; для листа важен только при возврате.
    pub depositor: [u8; 20],
    /// 0 — без возврата (комиссии и ноты, рождённые в пуле).
    pub refund_after: u64,
}

/// Наша нота v2.
pub struct OpenNoteV2 {
    pub leaf_index: u64,
    pub rho: Fr,
    pub aux: Fr,
    pub amount: u64,
    pub amount_micro: u64,
    pub memo: String,
    /// Метка возврата листа — свидетель вывода.
    pub refund: Fr,
    pub nullifier: [u8; 32],
}

impl std::fmt::Debug for OpenNoteV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenNoteV2")
            .field("leaf_index", &self.leaf_index)
            .field("amount", &self.amount)
            .field("rho", &"<redacted>")
            .finish()
    }
}

/// Открыть лист своим ключом чтения и сверить его с формулой пула под
/// своим ключом владельца. `None` — лист не наш или не сходится.
pub fn open_note(
    record: &LeafRecord,
    reader_secret: &PqcSecretKey,
    owner_pk: &[u8; 32],
    units_per_micro: u64,
) -> Option<OpenNoteV2> {
    let bytes = hex::decode(record.envelope_hex.trim_start_matches("0x")).ok()?;
    let view = envelope::open_as_recipient(&bytes, reader_secret).ok()??;
    let amount = view.denomination;
    let rho = fr(&view.secret);
    let aux = fr(&view.nullifier);
    let refund = if record.refund_after == 0 {
        Fr::from(0u64)
    } else {
        note_v2::refund_tag(
            note_v2::refund_addr_evm(record.depositor),
            record.refund_after,
        )
    };
    let core = note_v2::core(fr(owner_pk), rho, aux);
    let leaf = note_v2::leaf(note_v2::body(core, amount), refund);
    let claimed = record
        .commitment_hex
        .trim_start_matches("0x")
        .to_lowercase();
    if hex::encode(fr_to_word(leaf)) != claimed {
        return None;
    }
    Some(OpenNoteV2 {
        leaf_index: record.leaf_index,
        rho,
        aux,
        amount,
        amount_micro: amount / units_per_micro.max(1),
        memo: String::from_utf8_lossy(&view.memo).into_owned(),
        refund,
        nullifier: fr_to_word(note_v2::nullifier(rho, record.leaf_index)),
    })
}

/// Свой платёж v2, который можно вернуть: всё, что просит `refund` пула.
pub struct RefundableV2 {
    pub leaf_index: u64,
    pub owner_pk: [u8; 32],
    pub rho: [u8; 32],
    pub aux: [u8; 32],
    pub amount: u64,
    /// С какого момента (unix-секунды) пул отдаст ноту назад.
    pub refund_after: u64,
    pub nullifier: [u8; 32],
}

impl std::fmt::Debug for RefundableV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefundableV2")
            .field("leaf_index", &self.leaf_index)
            .field("amount", &self.amount)
            .field("refund_after", &self.refund_after)
            .finish_non_exhaustive()
    }
}

/// Открыть свою копию платежа из слота отправителя и сверить её с листом,
/// который записал пул. `None` — лист не наш, без возврата или не сходится.
pub fn open_refund(record: &LeafRecord, reader_secret: &PqcSecretKey) -> Option<RefundableV2> {
    if record.refund_after == 0 {
        return None;
    }
    let bytes = hex::decode(record.envelope_hex.trim_start_matches("0x")).ok()?;
    let copy = envelope::open_as_funder(&bytes, reader_secret).ok()??;
    let refund = note_v2::refund_tag(
        note_v2::refund_addr_evm(record.depositor),
        record.refund_after,
    );
    let core = note_v2::core(fr(&copy.owner_pk), fr(&copy.rho), fr(&copy.aux));
    let leaf = note_v2::leaf(note_v2::body(core, copy.amount), refund);
    let claimed = record
        .commitment_hex
        .trim_start_matches("0x")
        .to_lowercase();
    if hex::encode(fr_to_word(leaf)) != claimed {
        return None;
    }
    Some(RefundableV2 {
        leaf_index: record.leaf_index,
        owner_pk: copy.owner_pk,
        rho: copy.rho,
        aux: copy.aux,
        amount: copy.amount,
        refund_after: record.refund_after,
        nullifier: fr_to_word(note_v2::nullifier(fr(&copy.rho), record.leaf_index)),
    })
}

/// Вернуть свой платёж после окна: `refund(ownerPk, rho, aux, amount,
/// refundAfter)`. Доказательства не нужно — пул узнаёт отправителя по
/// `msg.sender`, поэтому подписывать должен тот же кошелёк, что платил.
pub fn refund(pool: &EvmPool, signer: &PrivateKeySigner, note: &RefundableV2) -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    if now < note.refund_after {
        bail!(
            "the refund opens in {} s; until then only the recipient can take this payment",
            note.refund_after - now
        );
    }
    let data = [
        &SEL_REFUND[..],
        &note.owner_pk,
        &note.rho,
        &note.aux,
        &word(u128::from(note.amount)),
        &word(u128::from(note.refund_after)),
    ]
    .concat();
    let call = Call {
        to: pool.hidden_pool,
        data,
    };
    send_call(&Node::new(pool.send_url)?, signer, pool.chain_id, &call)
}

/// Доказать вывод ноты v2 ключом траты владельца.
pub fn prove_withdraw(
    proving_key: &ProvingKey<Bn254>,
    tree: &MerkleTree,
    note: &OpenNoteV2,
    spending_key: &[u8; 32],
    parties: &WithdrawParties,
) -> Result<WithdrawProof> {
    let path = tree
        .proof(note.leaf_index)
        .with_context(|| format!("leaf {}: merkle path", note.leaf_index))?;
    let root = tree.root().to_bytes();
    let witness = WithdrawV2Witness {
        sk_spend: fr(spending_key),
        rho: note.rho,
        aux: note.aux,
        amount: note.amount,
        refund: note.refund,
        path_siblings: std::array::from_fn(|i| fr(path.siblings[i].as_bytes())),
        path_indices: std::array::from_fn(|i| (note.leaf_index >> i) & 1 == 1),
        merkle_root: fr(&root),
        recipient: super::note::address_word(parties.recipient),
        relayer: super::note::address_word(parties.relayer),
        relayer_fee: parties.relayer_fee,
    };
    let mut rng = rand::thread_rng();
    let (proof, _) = crate::confidential::prover_runtime::without_tracing(|| {
        withdraw_v2::prove_ceremony(proving_key, &witness, &mut rng)
    })
    .map_err(|e| anyhow::anyhow!("leaf {}: prove: {e}", note.leaf_index))?;
    Ok(WithdrawProof {
        proof: tidex6_circuits::evm_solidity::groth16_proof_to_evm_bytes(&proof).to_vec(),
        root,
    })
}

/// Ключ владельца кошелька из реестра цепи; `None` — не опубликован.
pub fn lookup_owner_key(pool: &EvmPool, wallet: &str) -> Result<Option<[u8; 32]>> {
    let node = Node::new(pool.read_url)?;
    let data = [&SEL_OWNER_KEY_OF[..], &address_word_str(wallet)?].concat();
    let answer = node.eth_call(pool.owner_keys, &data)?;
    let word: [u8; 32] = answer
        .get(..32)
        .and_then(|w| w.try_into().ok())
        .context("ownerKeyOf: short answer")?;
    Ok((word != [0u8; 32]).then_some(word))
}

/// Опубликовать свой ключ владельца. `None` — уже опубликован этот же.
pub fn publish_owner_key(
    pool: &EvmPool,
    signer: &PrivateKeySigner,
    owner_pk: &[u8; 32],
) -> Result<Option<String>> {
    let me = format!("{:#x}", signer.address());
    if lookup_owner_key(pool, &me)?.as_ref() == Some(owner_pk) {
        return Ok(None);
    }
    let call = Call {
        to: pool.owner_keys,
        data: [&SEL_PUBLISH_OWNER_KEY[..], owner_pk].concat(),
    };
    send_call(&Node::new(pool.send_url)?, signer, pool.chain_id, &call).map(Some)
}

/// Комиссия, которую пул возьмёт с платежа `amount` (базовые единицы) —
/// спрашивается у самого пула, чтобы конверт казне нёс ровно её.
pub fn fee_for(pool: &EvmPool, amount: u64) -> Result<u64> {
    let node = Node::new(pool.read_url)?;
    word_u64(&node.eth_call(
        pool.hidden_pool,
        &[&SEL_FEE_FOR[..], &word(u128::from(amount))].concat(),
    )?)
}

/// Чем кончился платёж v2.
#[derive(Debug)]
pub struct PaymentV2 {
    pub transactions: Vec<String>,
    pub core_hex: String,
    pub amount: u64,
    pub fee: u64,
}

/// Заплатить в пул v2: `approve` ровно на сумму с комиссией (если не
/// хватает) и один `deposit`. Комиссию называет сам пул (`feeFor`).
///
/// # Параметры
/// * `payment` — ядро и конверт получателя из [`seal_payment`]
/// * `amount` — базовые единицы токена, которые получит адресат
/// * `refund_window` — через сколько секунд можно вернуть, 0 — нельзя
/// * `fee_rho`, `fee_envelope` — из [`seal_fee`]
#[allow(clippy::too_many_arguments)]
pub fn pay(
    pool: &EvmPool,
    signer: &PrivateKeySigner,
    payment: &SealedCore,
    amount: u64,
    refund_window: u64,
    fee_rho: &[u8; 32],
    fee_envelope: &[u8],
) -> Result<PaymentV2> {
    if pool.is_withdraw_only {
        bail!("{} is an earlier pool kept for withdrawals only", pool.name);
    }
    let read = Node::new(pool.read_url)?;
    let send = Node::new(pool.send_url)?;
    let me = format!("{:#x}", signer.address());

    let fee = fee_for(pool, amount)?;
    let total = u128::from(amount) + u128::from(fee);
    let balance = word_u128(&read.eth_call(
        pool.token,
        &[&SEL_BALANCE_OF[..], &address_word_str(&me)?].concat(),
    )?)?;
    if balance < total {
        bail!(
            "not enough {} on {}: have {balance} base units, the payment with its fee is {total} — nothing was sent",
            pool.token_symbol,
            pool.name
        );
    }

    let mut transactions = Vec::new();
    let allowance = word_u128(
        &read.eth_call(
            pool.token,
            &[
                &SEL_ALLOWANCE[..],
                &address_word_str(&me)?,
                &address_word_str(pool.hidden_pool)?,
            ]
            .concat(),
        )?,
    )?;
    if allowance < total {
        let approve = Call {
            to: pool.token,
            data: [
                &SEL_APPROVE[..],
                &address_word_str(pool.hidden_pool)?,
                &word(total),
            ]
            .concat(),
        };
        transactions.push(send_call(&send, signer, pool.chain_id, &approve)?);
    }

    // deposit(core, amount, refundWindow, envelope, feeRho, feeEnvelope):
    // шесть слов головы, два хвоста `bytes`.
    let envelope = encode_bytes(&payment.envelope);
    let fee_env = encode_bytes(fee_envelope);
    let data = [
        &SEL_DEPOSIT[..],
        &payment.core,
        &word(u128::from(amount)),
        &word(u128::from(refund_window)),
        &word(192),
        fee_rho,
        &word(192 + envelope.len() as u128),
        &envelope,
        &fee_env,
    ]
    .concat();
    let deposit = Call {
        to: pool.hidden_pool,
        data,
    };
    transactions.push(send_call(&send, signer, pool.chain_id, &deposit)?);
    Ok(PaymentV2 {
        transactions,
        core_hex: hex::encode(payment.core),
        amount,
        fee,
    })
}

fn random_field() -> Result<[u8; 32]> {
    // Секрет ядра — поле BN254 из ОС, та же выборка, что у `secret` v1.
    Ok(*Secret::random().context("randomness")?.as_bytes())
}

fn fr(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

fn word(value: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&value.to_be_bytes());
    w
}

fn word_u128(bytes: &[u8]) -> Result<u128> {
    if bytes.len() < 32 || bytes[..16].iter().any(|b| *b != 0) {
        bail!("the contract answered a value that is not a 128-bit amount");
    }
    Ok(u128::from_be_bytes(bytes[16..32].try_into()?))
}

fn word_u64(bytes: &[u8]) -> Result<u64> {
    u64::try_from(word_u128(bytes)?).context("amount over 64 bits")
}

fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let padded = data.len().div_ceil(32) * 32;
    let mut out = word(data.len() as u128).to_vec();
    out.extend_from_slice(data);
    out.resize(32 + padded, 0);
    out
}

fn address_word_str(address: &str) -> Result<[u8; 32]> {
    let bytes: [u8; 20] = hex::decode(address.trim().trim_start_matches("0x"))
        .with_context(|| format!("{address} is not an EVM address"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{address} is not an EVM address"))?;
    Ok(address_word(bytes))
}
