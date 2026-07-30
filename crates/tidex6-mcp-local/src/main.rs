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
mod jobs;
mod notify;

use anyhow::Result;
use rmcp::ServiceExt;
use rmcp::transport::stdio;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = config::Config::load()?;
    let network = config.network()?;
    let tools = handler::LocalTools::new(config)?;

    // Лог по-английски: он попадает в кадр демо-записи и читают его не только
    // мы. Комментарии остаются на русском — их читаем мы.
    tracing::info!(
        ?network,
        wallet = %tools.wallet(),
        "tidex6 local MCP ready: key loaded, listening on stdio"
    );

    // Держим ссылку на работы: сервис забирает `tools` себе, а нам после его
    // остановки надо знать, не остался ли кто-то в полёте.
    let jobs = tools.jobs().clone();

    let service = tools.serve(stdio()).await?;
    service.waiting().await?;

    // Клиент отключился — но платёж мог быть в середине. Между переводом
    // оператору и записью конверта деньги уже списаны, а платежа ещё нет:
    // выйти в этот момент значит оставить человека без того и без другого.
    //
    // Ждём до пяти минут. Дольше — уже не «доделываем», а держим мёртвый
    // процесс; тогда лучше выйти и сказать об этом в лог, чем висеть молча.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while jobs.in_flight() > 0 && std::time::Instant::now() < deadline {
        tracing::info!(
            in_flight = jobs.in_flight(),
            "client disconnected; finishing payments already in flight"
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    if jobs.in_flight() > 0 {
        tracing::error!(
            in_flight = jobs.in_flight(),
            "giving up the wait: payments may be left unfinished"
        );
    }
    Ok(())
}
