//! Структурированные ошибки службы — без «угадай по подстроке».
//!
//! Ошибка — объект: `code`, `message` (человеку), `stage`, `funds_moved`,
//! опционально `signature` и `detail` (оператору). Web/MCP/Telegram **не**
//! переводят raw-текст Solana в «недостаточно средств» поиском слова
//! `insufficient`: формулировку задаёт тот, кто ошибку *классифицировал*
//! (тип `TransactionError`, исход шага), а не regex по Display.

use std::fmt;

use serde::Serialize;
use solana_transaction_error::TransactionError;

/// Машинный код. Сериализуется snake_case строкой — клиенты матчят enum, не прозу.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// У fee-payer реально нет SOL на fee/rent (`TransactionError::InsufficientFunds*`).
    FeePayerSol,
    /// Tx ушла (или могла уйти), confirm не дождались. Повтор вслепую опасен.
    ConfirmUncertain,
    /// On-chain program reject (не fee-payer).
    Program,
    /// Устаревший blockhash — безопасно повторить *до* send success.
    Blockhash,
    /// RPC/сеть без ясной семантики денег.
    Rpc,
    /// Pool withdraw прошёл, cashout — нет. Нота сожжена.
    CashoutAfterWithdraw,
    /// Всё остальное.
    Internal,
}

/// Двинулись ли деньги / state on-chain к моменту ошибки.
///
/// Три значения, не bool: «не знаем» нельзя схлопнуть в «нет» — иначе человек
/// повторит платёж, который уже ушёл.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FundsMoved {
    No,
    Yes,
    Unknown,
}

/// Ошибка операции, готовая к JSON-ответу службы.
#[derive(Debug, Clone, Serialize)]
pub struct OpError {
    pub code: ErrorCode,
    /// Текст для человека / Telegram / агента. Задаётся здесь, не переписывается
    /// web'ом из raw.
    pub message: String,
    /// Где оборвалось: `pool_withdraw`, `cashout`, `send_ix`, …
    pub stage: String,
    pub funds_moved: FundsMoved,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Сырьё для оператора (тип/Display RPC). Не для «перевода» в UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl OpError {
    pub fn new(
        code: ErrorCode,
        stage: impl Into<String>,
        message: impl Into<String>,
        funds_moved: FundsMoved,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            stage: stage.into(),
            funds_moved,
            signature: None,
            detail: None,
        }
    }

    pub fn with_signature(mut self, sig: impl Into<String>) -> Self {
        self.signature = Some(sig.into());
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Из on-chain `TransactionError` — по **варианту enum**, не по тексту.
    pub fn from_transaction_error(stage: &str, err: &TransactionError) -> Self {
        match err {
            TransactionError::InsufficientFundsForFee
            | TransactionError::InsufficientFundsForRent { .. } => Self::new(
                ErrorCode::FeePayerSol,
                stage,
                "У операторского кошелька не хватает SOL на комиссию или rent. \
                 Это fee-payer службы, не баланс получателя USDC. Пополни SOL \
                 operator и повтори.",
                FundsMoved::No,
            )
            .with_detail(format!("{err:?}")),
            TransactionError::BlockhashNotFound => Self::new(
                ErrorCode::Blockhash,
                stage,
                "Blockhash устарел (нода отстаёт). Повтори — состояние on-chain \
                 при этой ошибке обычно не менялось.",
                FundsMoved::No,
            )
            .with_detail(format!("{err:?}")),
            other => Self::new(
                ErrorCode::Program,
                stage,
                format!("Транзакция отклонена программой: {other:?}"),
                FundsMoved::No,
            )
            .with_detail(format!("{other:?}")),
        }
    }

    /// Confirm не пришёл: tx **могла** уйти. Всегда `Unknown` + signature если есть.
    pub fn confirm_uncertain(
        stage: &str,
        signature: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        let mut e = Self::new(
            ErrorCode::ConfirmUncertain,
            stage,
            "Сеть не подтвердила транзакцию вовремя. Это НЕ «мало USDC у тебя». \
             Деньги или нота МОГЛИ уже сдвинуться — не повторяй вслепую: проверь \
             receive / explorer по signature, потом решай.",
            FundsMoved::Unknown,
        )
        .with_detail(detail);
        if let Some(sig) = signature {
            e = e.with_signature(sig);
        }
        e
    }

    pub fn cashout_after_withdraw(signature: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::CashoutAfterWithdraw,
            "cashout",
            "Withdraw из пула ПРОШЁЛ, cashout USDC — нет. Нота уже потрачена \
             (nullifier on-chain). НЕ повторяй collect этой ноты. Нужен добор \
             cashout оператором / поддержкой.",
            FundsMoved::Yes,
        )
        .with_signature(signature)
        .with_detail(detail)
    }

    pub fn internal(stage: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self::new(
            ErrorCode::Internal,
            stage,
            "Внутренняя ошибка службы. Если это был вывод — проверь receive, \
             не повторяй платёж/collect вслепую.",
            FundsMoved::Unknown,
        )
        .with_detail(detail)
    }

    /// Свернуть anyhow-цепочку: если внутри уже `OpError` — он главный.
    pub fn from_anyhow(stage: &str, err: &anyhow::Error) -> Self {
        for cause in err.chain() {
            if let Some(op) = cause.downcast_ref::<OpError>() {
                return op.clone();
            }
        }
        Self::internal(stage, format!("{err:#}"))
    }
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(sig) = &self.signature {
            write!(f, " [sig {sig}]")?;
        }
        if let Some(d) = &self.detail {
            write!(f, " ({d})")?;
        }
        Ok(())
    }
}

impl std::error::Error for OpError {}
