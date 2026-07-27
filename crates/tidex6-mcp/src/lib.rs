//! tidex6 MCP server — private payments as an agent capability (ADR-018).
//!
//! An AI agent connecting here can quote a payment, prepare one, and hand its
//! operator the links for receiving and auditing. It cannot sign: the signature
//! is produced by the user's wallet, out of band. That is not a policy this
//! crate enforces — it is the consequence of never holding a spending key. A
//! prompt injection that talks the agent into paying an attacker produces a
//! link the human declines.
//!
//! This is a **library**, not a binary. The server is one deployment at
//! `mcp.tidex6.com`, mounted by `tidex6-web` over streamable HTTP with OAuth
//! (ADR-018 §8). There is deliberately no stdio bootstrap: asking a person to
//! build a Rust project before they can talk to their agent about a payment is
//! not a product, and a development-only transport kept alive beside the real
//! one is a second thing to keep correct.
//!
//! Because there is one deployment for everyone, the **network is an argument**
//! rather than the server's configuration: mainnet unless the caller says
//! devnet.

pub mod handler;
pub mod quote;
pub mod registry;

pub use handler::Tidex6Mcp;

/// Кошелёк того, чьим токеном сделан вызов.
///
/// Кладётся в расширения HTTP-запроса тем, кто монтирует сервер: только он
/// знает, как из токена получить учётную запись, а из неё — адрес. Здесь мы
/// его читаем, а не выясняем — этот крейт не ходит в базу и не проверяет
/// токены (ADR-018 §1: тонкий слой).
///
/// Позволяет инструменту ответить «на этом кошельке столько-то, платёж не
/// пройдёт» ещё до того, как ссылка создана и человек куда-то пошёл. Без него
/// отправитель серверу неизвестен: он тот, кто откроет ссылку и подпишет.
#[derive(Debug, Clone)]
pub struct CallerWallet(pub String);
