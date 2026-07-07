//! tidex6-confidential — крипто-ядро Этапа 2 (скрытая произвольная сумма).
//!
//! Две боевые Groth16-схемы над BN254, обе с суммой внутри commitment
//! (`commitment = Poseidon(secret, nullifier, amount)`, ADR-015):
//!
//! - [`withdraw`] — вывод ноты: range(amount), exact recipient/relayer
//!   binding (фикс GAP2), relayer_fee (ADR-011). Сумма выплаты публична на
//!   границе пула (программа должна знать, сколько отдать); полное скрытие
//!   границы делает CT-слой (wUSDC) поверх, привязанный через G-bind.
//! - [`transfer`] — JoinSplit 1→2 со ВСЕМИ суммами приватными
//!   (conservation + range). Внутренние переводы полностью конфиденциальны:
//!   на цепи только два opaque-commitment'а, ни одной суммы.
//!
//! Оба доказательства проверяются как off-chain (arkworks), так и байт-в-байт
//! через `groth16-solana` ([`onchain::verify_onchain_compat`]) — тем же
//! крейтом и тем же `alt_bn128`-путём, что крутит верификатор на mainnet.

pub mod bytes;
pub mod onchain;
pub mod transfer;
pub mod withdraw;
