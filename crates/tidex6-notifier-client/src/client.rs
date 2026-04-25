//! High-level async client for the Notifier IPC service.
//!
//! Every method dispatches one bitcode-framed command over the Unix
//! socket and returns as soon as the server enqueues the work. All
//! Bot-API latency stays inside the Notifier process, hidden from
//! the caller.

use tokio::net::UnixStream;

use crate::ipc;
use crate::types::{NotifierCommand, NotifierResponse};

/// IPC client. Cheap to construct — every call opens a fresh socket
/// (the IPC boundary is short-lived per-request, no connection pool).
pub struct NotifierClient {
    socket_path: String,
}

impl NotifierClient {
    /// Build a client pointing at the given Unix socket path. Use
    /// [`crate::DEFAULT_NOTIFIER_SOCKET_PATH`] in production.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Default-path constructor. Equivalent to
    /// `NotifierClient::new(DEFAULT_NOTIFIER_SOCKET_PATH)`.
    pub fn default_socket() -> Self {
        Self::new(crate::DEFAULT_NOTIFIER_SOCKET_PATH)
    }

    /// Send a plain text message to a specific chat (+ optional
    /// forum topic).
    pub async fn send_telegram_direct(
        &self,
        chat_id: i64,
        topic_id: Option<i64>,
        message: impl Into<String>,
    ) -> anyhow::Result<()> {
        self.dispatch(NotifierCommand::SendTelegramDirect {
            chat_id,
            topic_id,
            message: message.into(),
        })
        .await
    }

    /// Send a plain text message to a topic looked up by code.
    pub async fn send_by_code(
        &self,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> anyhow::Result<()> {
        self.dispatch(NotifierCommand::SendTelegramByCode {
            code: code.into(),
            message: message.into(),
        })
        .await
    }

    /// Notify the operator about a failure in `component`. The
    /// Notifier formats the message and routes it to the `errors`
    /// topic (with fallback to `general`, then default chat). Use
    /// this on every error branch so the operator never misses a
    /// production failure.
    pub async fn notify_error(
        &self,
        component: impl Into<String>,
        message: impl Into<String>,
    ) -> anyhow::Result<()> {
        self.dispatch(NotifierCommand::NotifyError {
            component: component.into(),
            message: message.into(),
        })
        .await
    }

    /// Internal: open a fresh UnixStream, send one command, read
    /// one response, close. The Notifier server treats every
    /// connection as one-shot.
    async fn dispatch(&self, cmd: NotifierCommand) -> anyhow::Result<()> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        ipc::send(&mut stream, &cmd).await?;
        let response: NotifierResponse = ipc::read(&mut stream)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Empty response from Notifier"))?;
        match response {
            NotifierResponse::Queued | NotifierResponse::Sent => Ok(()),
            NotifierResponse::Error(msg) => Err(anyhow::anyhow!(msg)),
        }
    }
}
