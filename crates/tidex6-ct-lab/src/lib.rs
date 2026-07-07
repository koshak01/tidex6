//! tidex6-ct-lab — unified-клиент двухслойного wUSDC-флоу.
//!
//! Одна версия-вселенная (spl-token-client): CT-часть (wrap/mover/cashout,
//! Token-2022 Confidential Transfer) и пул-часть (deposit/withdraw) БЕЗ
//! anchor-client — сырые `Instruction` (дискриминатор `sha256("global:…")`,
//! borsh аргументов, метаданные аккаунтов). Так всё живёт в одном процессе,
//! без спавна внешних бинарников, и переносимо в WASM.

pub mod config;
pub mod ct;
pub mod flow;
pub mod pool;
