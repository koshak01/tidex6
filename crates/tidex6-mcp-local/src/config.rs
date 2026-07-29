//! Настройка локального сервера — файл, а не аргументы командной строки.
//!
//! Путь к ключу и потолки трат в `ps aux` видеть незачем, а MCP-клиент
//! запускает нас своей строкой запуска, которую мы не контролируем. Файл в
//! каталоге `0700` — единственное место, где всё это может лежать спокойно.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use tidex6_client::Limits;
use tidex6_core::network::{Asset, Network};

/// Всё, что серверу нужно знать о хозяине и его пределах.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Ключ, которым подписываются платежи. Формат `solana-keygen`.
    pub keypair_path: String,

    /// Узел Solana. Публичные узлы медленные и режут по частоте — свой или
    /// платный.
    pub rpc_url: String,

    /// Служба пула: у кого спрашивать котировку и кто заворачивает сумму.
    #[serde(default = "default_pool_service")]
    pub pool_service: String,

    /// `mainnet` | `devnet`.
    #[serde(default = "default_network")]
    pub network: String,

    /// Сколько времени у получателя, чтобы забрать платёж, прежде чем
    /// отправитель сможет вернуть его себе.
    #[serde(default = "default_revoke_window")]
    pub revoke_window_secs: i64,

    /// Потолки. Отсутствие секции означает умолчания из библиотеки, а они
    /// намеренно тесные.
    #[serde(default)]
    pub limits: LimitsToml,

    /// Куда досылать ход работы. Нет секции — сервер работает молча, и
    /// состояние спрашивают через `payment_status`.
    #[serde(default)]
    pub notify: Option<crate::notify::Notify>,
}

/// Потолки в том виде, в каком их пишет человек: в токенах, не в микро-единицах.
///
/// Микро-единицы в конфиге — верный способ однажды ошибиться на шесть нулей и
/// узнать об этом по факту списания.
#[derive(Debug, Deserialize)]
pub struct LimitsToml {
    #[serde(default = "default_per_payment")]
    pub per_payment: f64,
    #[serde(default = "default_per_day")]
    pub per_day: f64,
    /// Сколько максимум может лежать на этом ключе. Он сессионный: держать на
    /// нём основной баланс не следует, потому что читать его команды может
    /// языковая модель.
    #[serde(default = "default_session_balance_cap")]
    pub session_balance_cap: f64,
}

impl Default for LimitsToml {
    fn default() -> Self {
        Self {
            per_payment: default_per_payment(),
            per_day: default_per_day(),
            session_balance_cap: default_session_balance_cap(),
        }
    }
}

fn default_pool_service() -> String {
    "https://tidex6.com".to_string()
}
fn default_network() -> String {
    // Devnet по умолчанию: настоящие деньги должны быть выбором, а не тем, во
    // что попадаешь, ничего не написав.
    "devnet".to_string()
}
fn default_revoke_window() -> i64 {
    24 * 3600
}
fn default_per_payment() -> f64 {
    5.0
}
fn default_per_day() -> f64 {
    25.0
}
fn default_session_balance_cap() -> f64 {
    100.0
}

impl Config {
    /// Прочитать конфиг. Путь берётся из `TIDEX6_LOCAL_CONFIG`, иначе
    /// `~/.tidex6-local/config.toml`.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let raw = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "нет конфига {}. Создайте его: keypair_path, rpc_url, network",
                path.display()
            )
        })?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("{}: разбор не удался", path.display()))?;
        config.check_key_permissions()?;
        Ok(config)
    }

    fn path() -> Result<PathBuf> {
        if let Ok(explicit) = std::env::var("TIDEX6_LOCAL_CONFIG") {
            return Ok(PathBuf::from(explicit));
        }
        let home = std::env::var("HOME").context("нет $HOME")?;
        Ok(Path::new(&home).join(".tidex6-local").join("config.toml"))
    }

    /// Отказаться работать с ключом, который читают все.
    ///
    /// Проверка, а не совет в документации: ключ с правами `0644` — это ключ,
    /// который уже могли скопировать, и запускаться так, будто ничего не
    /// произошло, значит делать вид.
    fn check_key_permissions(&self) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&self.keypair_path)
            .with_context(|| format!("нет ключа {}", self.keypair_path))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} доступен не только владельцу (права {:o}). Исправьте: chmod 600 {}",
                self.keypair_path,
                mode,
                self.keypair_path
            );
        }
        Ok(())
    }

    pub fn network(&self) -> Result<Network> {
        match self.network.as_str() {
            "mainnet" | "mainnet-beta" => Ok(Network::Mainnet),
            "devnet" => Ok(Network::Devnet),
            other => anyhow::bail!("network: ожидалось mainnet или devnet, получено {other}"),
        }
    }

    /// Потолки в микро-единицах, как их понимает библиотека.
    pub fn limits(&self) -> Limits {
        let micro = |tokens: f64| (tokens * 1_000_000.0).round() as u64;
        Limits {
            per_payment: micro(self.limits.per_payment),
            per_day: micro(self.limits.per_day),
            allowed_assets: vec![Asset::Wusdc, Asset::Wusdt],
            session_balance_cap: Some(micro(self.limits.session_balance_cap)),
        }
    }
}
