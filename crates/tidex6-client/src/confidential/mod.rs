//! Конфиденциальный поток (wUSDC / wUSDT) для локального подписанта.
//!
//! Тот же протокол, что и в браузере, но ключ подписи лежит файлом на машине
//! оператора: агент платит сам, без вкладки и без человека. Это вторая ступень
//! доверия — и она допустима только вместе с [`limits`], поэтому они здесь
//! рядом, а не в отдельном необязательном месте.
//!
//! Библиотека одна на все лица: CLI, локальный MCP и веб зовут её же. Разница
//! между ними — кто держит ключ и чем отвечает инструмент, а не какой код
//! исполняется.

pub mod limits;
pub mod local;
pub mod note;
pub mod scan;
pub mod send;
pub mod transfer;

pub use limits::{DailySpend, LimitError, Limits};
pub use local::{LocalIdentity, load_keypair};
pub use note::{SealedPayment, seal_payment};
pub use scan::{FoundPayment, ReadAs, ScanReport, scan};
pub use send::{PoolService, Quote, SentPayment, send_payment};
