//! tidex6 в локальном режиме: агент платит своим ключом, без браузера.
//!
//! Транспорт — stdio: MCP-клиент (ZeroClaw, Claude Desktop) запускает этот
//! процесс у себя на машине. Ключ не уезжает никуда, потому что уезжать
//! некуда — процесс и ключ живут в одной системе.
//!
//! **Логи идут в stderr, и это не мелочь.** stdout занят протоколом; строка,
//! напечатанная туда, ломает разбор кадра и выглядит для клиента как
//! испорченный сервер.

mod config;
mod handler;

use anyhow::Result;
use rmcp::ServiceExt;
use rmcp::transport::stdio;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = config::Config::load()?;
    let network = config.network()?;
    let tools = handler::LocalTools::new(config)?;

    tracing::info!(?network, "tidex6 local MCP: ключ загружен, слушаю stdio");

    let service = tools.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
