//! tidex6 MCP server — private payments as an agent capability (ADR-018).
//!
//! An AI agent connecting here can quote a payment, build the transaction and
//! read what has arrived. It cannot sign: the signature is produced by the
//! user's wallet, out of band. That is not a policy this server enforces — it
//! is the consequence of never holding a spending key. A prompt injection that
//! talks the agent into paying an attacker produces a link the human declines.
//!
//! Transport is stdio (ADR-018 §8), which is what MCP clients spawn as a child
//! process — Claude Code, ZeroClaw, Cursor. The production transport is
//! streamable HTTP mounted in `tidex6-web`; it lands after the tools settle.

use anyhow::{Context, Result};
use rmcp::ServiceExt;
use rmcp::transport::io::stdio;
use tracing_subscriber::EnvFilter;

mod handler;
mod quote;

use crate::handler::Tidex6Mcp;

#[tokio::main]
async fn main() -> Result<()> {
    // stdio carries the MCP protocol itself, so every diagnostic must go to
    // stderr. A stray println! here corrupts the session.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let handler = Tidex6Mcp::from_env().context("build MCP handler")?;

    tracing::info!(
        network = %handler.network(),
        "tidex6-mcp starting on stdio"
    );

    let service = handler
        .serve(stdio())
        .await
        .context("serve MCP over stdio")?;

    service.waiting().await.context("MCP session")?;
    Ok(())
}
