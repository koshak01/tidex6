//! Сборка платёжной ноты и конверта — без браузера.
//!
//! Ровно то же, что делает вкладка отправителя, только нативно. Браузерный
//! `tidex6-prover-wasm` — тонкая обёртка над теми же вызовами `tidex6-core`, и
//! это не совпадение: конверт, собранный здесь и там, должен быть одним и тем
//! же байт в байт, иначе получатель откроет один и не откроет другой.
//!
//! Что здесь **не** происходит: ни `secret`, ни `nullifier` не пишутся в лог,
//! не попадают в `Debug` и не уходят по сети. Наружу выходит конверт и
//! commitment — то, что и так ляжет в цепочку у всех на виду.

use anyhow::{Context, Result};
use tidex6_core::envelope::{self, ReaderAddress};
use tidex6_core::types::{Commitment, Nullifier, Secret};

/// Готовый к отправке платёж: что кладём в цепочку и что остаётся у нас.
pub struct SealedPayment {
    /// Хеш, который увидит любой наблюдатель. Больше он не увидит ничего.
    pub commitment: Commitment,
    /// Запечатанный конверт: слот получателя, при наличии — слоты аудиторов.
    pub envelope: Vec<u8>,
    /// Сумма в микро-единицах. Лежит внутри конверта; здесь — для вызывающего.
    pub amount_micro: u64,
    /// Материал траты. Кто им владеет, тот и заберёт платёж.
    ///
    /// В нашем потоке отправитель его **не сохраняет**: нота уезжает получателю
    /// внутри конверта, и это делает платёж стелсовым — передавать нечего.
    /// Поле остаётся публичным на случай, когда вызывающему нужен возврат по
    /// истечении срока; тогда хранить его — осознанное решение вызывающего, а
    /// не побочный эффект вызова.
    pub secret: Secret,
    pub nullifier: Nullifier,
}

impl std::fmt::Debug for SealedPayment {
    /// Материал траты в отладочный вывод не попадает.
    ///
    /// `#[derive(Debug)]` был бы миной: одно `dbg!` или `?payment` в
    /// трассировке — и `secret` оказывается в логах, файлах, системах
    /// наблюдения. Пишем руками, чтобы этого не могло случиться по
    /// невнимательности.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedPayment")
            .field("commitment", &self.commitment)
            .field("envelope_len", &self.envelope.len())
            .field("amount_micro", &self.amount_micro)
            .field("secret", &"<redacted>")
            .field("nullifier", &"<redacted>")
            .finish()
    }
}

/// Запечатать платёж получателю, при желании открыв его аудиторам.
///
/// # Параметры
/// * `recipient` — адрес читателя из реестра на цепочке (`mlkem ‖ x25519`)
/// * `auditors` — кому раскрыть сумму и назначение; пусто — никому
/// * `amount_micro` — сумма в микро-единицах
/// * `memo` — назначение платежа
///
/// # Возвращает
/// * `SealedPayment` — commitment и конверт, готовые к отправке в цепочку
pub fn seal_payment(
    recipient: &ReaderAddress,
    auditors: &[ReaderAddress],
    amount_micro: u64,
    memo: &str,
) -> Result<SealedPayment> {
    // Случайность берётся у ОС и только у неё. Предсказуемый `secret` означает,
    // что платёж заберёт не тот, кому он предназначен.
    let secret = Secret::random().context("secret")?;
    let nullifier = Nullifier::random().context("nullifier")?;
    let commitment = Commitment::derive(&secret, &nullifier).context("commitment")?;

    let envelope = envelope::build(
        recipient,
        secret.as_bytes(),
        nullifier.as_bytes(),
        amount_micro,
        memo.as_bytes(),
        auditors,
    )
    .context("seal the envelope")?;

    Ok(SealedPayment {
        commitment,
        envelope,
        amount_micro,
        secret,
        nullifier,
    })
}
