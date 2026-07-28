//! Личность и чтение платежей на своей машине, без браузера.
//!
//! Ключевое свойство, ради которого всё это устроено именно так: **один и тот
//! же кошелёк даёт одну и ту же личность**, подписал он фразу в Phantom или
//! файлом ключа здесь. Личность выводится из подписи над постоянной фразой
//! (ADR-018 §3), а подпись ed25519 детерминирована — значит ключ чтения
//! совпадёт до байта.
//!
//! Иначе получилось бы худшее из возможного: человек отправляет платёж из
//! браузера, ищет его локальным агентом и не находит. Не ошибка, не отказ —
//! пустой список, и никакого способа понять, почему.

use anyhow::{Context, Result};
// `Signer` берём через anchor_client, как и весь остальной SDK: отдельная
// зависимость на `solana-signer` дала бы второй путь к тому же трейту и шанс
// однажды разъехаться версиями.
use anchor_client::Signer;
use solana_keypair::Keypair;
use tidex6_core::envelope::{self, AuditorView, ReaderAddress, RecipientView};
use tidex6_core::identity::{self, IDENTITY_MESSAGE};
use tidex6_core::pqc::PqcSecretKey;

/// Кто мы для протокола: адрес кошелька и ключи чтения, выведенные из него.
pub struct LocalIdentity {
    /// Обычный адрес Solana. Публичен, его и называют, когда платят.
    pub wallet: anchor_client::anchor_lang::prelude::Pubkey,
    /// Адрес читателя (`mlkem ‖ x25519`) — то, что публикуется в реестре.
    pub reader: ReaderAddress,
    /// Секрет чтения. Им открываются адресованные нам слоты — и ничего больше:
    /// потратить он не позволяет.
    mlkem_secret: PqcSecretKey,
}

impl std::fmt::Debug for LocalIdentity {
    /// Секрет чтения из отладочного вывода исключён. Он не даёт тратить, но
    /// даёт читать чужие платежи, адресованные нам, — этого достаточно, чтобы
    /// не хотеть видеть его в логах.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("wallet", &self.wallet)
            .field("reader", &"<reader address>")
            .field("mlkem_secret", &"<redacted>")
            .finish()
    }
}

impl LocalIdentity {
    /// Вывести личность из локального ключа кошелька.
    ///
    /// Подписываем ту же фразу, что подписывает браузер, и получаем те же
    /// ключи. Фраза берётся из `tidex6-core`, а не пишется здесь строкой:
    /// разойдясь на один символ, две реализации дали бы две разные личности
    /// одному кошельку, и обнаружилось бы это пустым списком платежей.
    pub fn from_keypair(keypair: &Keypair) -> Result<Self> {
        let signature = keypair.sign_message(IDENTITY_MESSAGE.as_bytes());
        let derived = identity::from_signature(signature.as_ref())
            .context("вывести личность из подписи")?;
        let reader =
            ReaderAddress::from_secret(derived.mlkem_public.clone(), &derived.mlkem_secret);

        Ok(Self {
            wallet: keypair.pubkey(),
            reader,
            mlkem_secret: derived.mlkem_secret,
        })
    }

    /// Открыть конверт как получатель.
    ///
    /// Возвращает `None`, когда конверт адресован не нам. Это **не ошибка**:
    /// пул отдаёт все конверты подряд, и неудачная расшифровка и есть фильтр
    /// «моё / не моё». Отличать чужой конверт от испорченного здесь незачем —
    /// снаружи они выглядят одинаково, и в этом смысл.
    pub fn open_as_recipient(&self, envelope_bytes: &[u8]) -> Option<RecipientView> {
        envelope::open_as_recipient(envelope_bytes, &self.mlkem_secret)
            .ok()
            .flatten()
    }

    /// Открыть конверт как аудитор: сумма и назначение, без материала траты.
    ///
    /// Разделение живёт в шифротексте, а не в правиле, которое кто-то обещает
    /// соблюдать: `secret` в аудиторский слот не кладётся вовсе, поэтому
    /// аудитор физически не может потратить то, что читает.
    pub fn open_as_auditor(&self, envelope_bytes: &[u8]) -> Option<AuditorView> {
        envelope::open_as_auditor(envelope_bytes, &self.mlkem_secret)
            .ok()
            .flatten()
    }
}

/// Прочитать ключ кошелька из файла (формат `solana-keygen`).
///
/// Отдельная функция, потому что это единственное место, где локальный режим
/// касается материала подписи, и его стоит держать на виду.
pub fn load_keypair(path: &str) -> Result<Keypair> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("прочитать ключ {path}"))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .with_context(|| format!("{path}: ожидался массив байт, как у solana-keygen"))?;
    Keypair::try_from(bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("{path}: не похоже на ключ Solana: {e}"))
}
