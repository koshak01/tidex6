//! IPC message types — single source of truth for the Notifier wire
//! format. Both the server (in `tidex6-web::services::notifier`) and
//! every client (`tidex6-relayer`, `tidex6-web::ws_gateway`, etc.)
//! depend on this module, so there is no chance of one half drifting
//! ahead of the other and producing un-decodable messages on the
//! wire.

/// Commands sent by callers to the Notifier IPC service.
///
/// All variants are fire-and-forget: the server pushes them into an
/// internal mpsc queue and returns immediately. Actual delivery to
/// Telegram happens on a background worker with rate-limit. Callers
/// never wait on Bot API latency.
///
/// # Wire-format invariant
///
/// **Variant order is part of the ABI.** Adding new commands MUST go
/// at the end; removing or reordering existing variants breaks every
/// running consumer. Bumping major version of the bitcode format
/// requires a coordinated redeploy of the Notifier server and every
/// client.
#[derive(bitcode::Encode, bitcode::Decode, Debug, Clone)]
pub enum NotifierCommand {
    /// Send to a specific chat_id, optionally inside a forum topic.
    SendTelegramDirect {
        chat_id: i64,
        topic_id: Option<i64>,
        message: String,
    },

    /// Send to a topic looked up by code (e.g. "general", "invites",
    /// "errors") in the `telegrams` DB table.
    SendTelegramByCode { code: String, message: String },

    /// Send to the bot's default chat (no topic).
    SendTelegramDefault { message: String },

    /// Send a message with one inline button. Used for invite-approval
    /// and similar callback flows.
    SendTelegramWithButton {
        code: String,
        message: String,
        button_text: String,
        button_data: String,
    },

    /// Send a message with multiple inline buttons.
    SendTelegramWithButtons {
        code: String,
        message: String,
        /// Pairs of (text, callback_data).
        buttons: Vec<(String, String)>,
    },

    /// Notify operators about a failure in some component. The server
    /// formats the message in a uniform `⚠️ component\n<pre>msg</pre>`
    /// shape and routes it to the dedicated `errors` topic (with
    /// fallback to `general`, then default chat). Every component
    /// — web, ws_gateway, relayer, solana — calls this on its error
    /// branches so the operator sees production failures in real time.
    NotifyError { component: String, message: String },
}

/// Responses returned by the Notifier IPC service.
#[derive(bitcode::Encode, bitcode::Decode, Debug, Clone)]
pub enum NotifierResponse {
    /// Command accepted into the in-memory queue. Actual delivery
    /// happens asynchronously on the worker and the result is logged
    /// only — no further IPC notification.
    Queued,

    /// Legacy synonym for `Queued`. Older clients expect this variant;
    /// the server still returns it for some commands. Treated as
    /// success by [`crate::client::NotifierClient`].
    Sent,

    /// Command rejected at the IPC boundary (queue full, unknown
    /// channel code, malformed payload). Calls into the bot API never
    /// surface here — those are handled silently by the worker.
    Error(String),
}
