//! Пределы, которые проверяет библиотека, а не агент.
//!
//! Локальный режим означает ключ подписи на машине оператора и языковую модель,
//! читающую сообщения из открытого чата. Между ними должно стоять что-то, чего
//! нельзя уговорить словами.
//!
//! Промпт уговорить можно — он и есть текст. Инструкцию в `SKILL.md` можно
//! перебить другой инструкцией, пришедшей в сообщении. А `checked_sub` нельзя:
//! он либо возвращает значение, либо не возвращает, и никакая формулировка на
//! это не влияет. Поэтому потолки живут здесь, в коде, ниже всякого текста.
//!
//! Это же требует и лестница доверия ZeroClaw: подписывающий агент допустим
//! только с лимитами трат и allowlist активов, **прописанными в коде**, на
//! ключе с ограниченными средствами. Без них — отказ на входе.

use std::time::{Duration, SystemTime};

use tidex6_core::network::Asset;

/// Что запрещено, и почему отказано.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LimitError {
    #[error("payment of {requested} exceeds the per-payment cap of {cap} (micro-units)")]
    PerPayment { requested: u64, cap: u64 },

    #[error(
        "payment of {requested} would exceed today's remaining budget of {remaining} \
         (spent {spent} of {cap} micro-units)"
    )]
    Daily {
        requested: u64,
        spent: u64,
        cap: u64,
        remaining: u64,
    },

    #[error("asset {asset:?} is not on the allowlist")]
    AssetNotAllowed { asset: Asset },

    #[error(
        "this key holds {balance} micro-units, more than the {cap} allowed for a session key — \
         move the surplus out, or raise `session_balance_cap` on purpose"
    )]
    KeyTooRich { balance: u64, cap: u64 },
}

/// Потолки одного локального ключа.
///
/// Числа в микро-единицах (1 USDC = 1_000_000), как и везде в протоколе:
/// десятичная дробь в денежном пороге — это способ однажды ошибиться на
/// множитель.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Максимум одного платежа.
    pub per_payment: u64,
    /// Максимум за сутки, суммой.
    pub per_day: u64,
    /// Какие активы вообще разрешено подписывать.
    ///
    /// Список, а не флаг «всё разрешено»: инъекция, попросившая заплатить
    /// незнакомым минтом, должна упереться в перечисление, а не в проверку,
    /// которую забыли включить.
    pub allowed_assets: Vec<Asset>,
    /// Сколько максимум может лежать на этом ключе.
    ///
    /// Не про траты, а про то, чем рискуем. Ключ, доступный процессу с моделью
    /// внутри, — сессионный, и держать на нём основной баланс не следует.
    /// `None` — проверка выключена сознательно, и это должно быть решением, а
    /// не умолчанием.
    pub session_balance_cap: Option<u64>,
}

impl Default for Limits {
    /// Умолчания намеренно тесные.
    ///
    /// Оператор, не читавший документацию, должен получить работающую систему
    /// с маленькими числами, а не свободу до первого сюрприза. Поднять потолок
    /// — осознанное действие; опустить его задним числом уже поздно.
    fn default() -> Self {
        Self {
            per_payment: 5_000_000,          // 5
            per_day: 25_000_000,             // 25
            allowed_assets: vec![Asset::Wusdc, Asset::Wusdt],
            session_balance_cap: Some(100_000_000), // 100
        }
    }
}

/// Сколько потрачено за скользящие сутки.
///
/// Скользящее окно, а не календарный день: иначе в полночь потолок обнуляется,
/// и «пять за день» превращается в «десять за пять минут» на стыке дат.
#[derive(Debug, Default)]
pub struct DailySpend {
    payments: Vec<(SystemTime, u64)>,
}

impl DailySpend {
    /// Сумма за последние 24 часа. Заодно выбрасывает всё, что старше.
    pub fn spent(&mut self, now: SystemTime) -> u64 {
        let window = Duration::from_secs(24 * 3600);
        self.payments
            .retain(|(at, _)| now.duration_since(*at).map(|d| d < window).unwrap_or(false));
        self.payments.iter().map(|(_, amount)| amount).sum()
    }

    /// Записать состоявшийся платёж.
    ///
    /// Зовётся ПОСЛЕ отправки, а не до: неудавшийся платёж денег не потратил, и
    /// съедать им дневной лимит значит наказывать за сбой сети.
    pub fn record(&mut self, at: SystemTime, amount: u64) {
        self.payments.push((at, amount));
    }
}

impl Limits {
    /// Можно ли подписать этот платёж.
    ///
    /// Все четыре проверки, по порядку от дешёвой к дорогой. Первый отказ
    /// прекращает разбор: человеку нужна причина, а не список всего, что не так.
    pub fn check(
        &self,
        asset: Asset,
        amount_micro: u64,
        key_balance_micro: Option<u64>,
        spend: &mut DailySpend,
        now: SystemTime,
    ) -> Result<(), LimitError> {
        if !self.allowed_assets.contains(&asset) {
            return Err(LimitError::AssetNotAllowed { asset });
        }

        if amount_micro > self.per_payment {
            return Err(LimitError::PerPayment {
                requested: amount_micro,
                cap: self.per_payment,
            });
        }

        if let (Some(cap), Some(balance)) = (self.session_balance_cap, key_balance_micro)
            && balance > cap
        {
            return Err(LimitError::KeyTooRich { balance, cap });
        }

        let spent = spend.spent(now);
        let remaining = self.per_day.saturating_sub(spent);
        if amount_micro > remaining {
            return Err(LimitError::Daily {
                requested: amount_micro,
                spent,
                cap: self.per_day,
                remaining,
            });
        }

        Ok(())
    }
}
