//! Shared IPC types and async client for the tidex6 Notifier service.
//!
//! The Notifier process (hosted in `tidex6-web::services::notifier::server`)
//! exposes a Unix-socket IPC at `/tmp/tidex6_notifier.sock`. This crate
//! is the *only* place where the wire types and the framing protocol
//! are defined, so that every consumer (the host service itself, the
//! WS gateway, the Solana service, the relayer) speaks the same
//! bitcode-encoded protocol with no chance of drift.
//!
//! # Wire format
//!
//! Every IPC message — request and response — is preceded by a 4-byte
//! little-endian length prefix:
//!
//! ```text
//! [u32 LE message_len] [bitcode-encoded payload]
//! ```
//!
//! The payload encodes either [`NotifierCommand`] (caller → server)
//! or [`NotifierResponse`] (server → caller).
//!
//! # Fire-and-forget semantics
//!
//! The Notifier server queues every send-style command in an internal
//! `tokio::mpsc` channel and returns [`NotifierResponse::Queued`]
//! immediately. Actual delivery to Telegram happens on a background
//! worker with rate-limit so callers never wait on the bot API
//! latency. This crate's [`NotifierClient`] handles both `Queued`
//! and the legacy `Sent` response transparently — both mean
//! "successfully accepted by the queue".

pub mod ipc;
pub mod types;
pub mod client;

pub use client::NotifierClient;
pub use types::{NotifierCommand, NotifierResponse};

/// Default socket path. Hard-coded to match the production deploy
/// (`/etc/supervisor/conf.d/tidex6.conf`'s notifier service binds
/// here). Kept in this crate so consumers don't have to reach into
/// `tidex6-web::types::common` — they would otherwise have to depend
/// on the whole web crate just for this one constant.
pub const DEFAULT_NOTIFIER_SOCKET_PATH: &str = "/tmp/tidex6_notifier.sock";
