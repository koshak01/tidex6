//! Конфиг сервиса: ~/.tidex6-wusdc/config.toml (вместо env). Хранит allowlist
//! кошельков и режим авто-мувера. Создаётся с дефолтом при отсутствии.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tidex6_core::network::{Asset, Network};

const DEFAULT_ADMIN: &str = "Cs9F9sdycNUfYDLg7WGsYwbxRMubo2b4u8V4Mdv8Y8n6";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Кошельки (base58 pubkey), которым разрешено запускать операции.
    #[serde(default)]
    pub admins: Vec<String>,
    /// Авто-выплата: после `configure` сразу гнать мувер in-process (событийно,
    /// без таймер-поллинга). false — шаг Mover остаётся ручным.
    #[serde(default = "default_true")]
    pub auto_mover: bool,
    /// Сеть: "mainnet-beta" | "devnet". Определяет минты/пул из реестра
    /// `tidex6_core::network`. Флип на devnet — одна строка (после devnet-деплоя).
    #[serde(default = "default_network")]
    pub network: String,
    /// Актив: "wusdc" | "wusdt". Определяет пул + минты из реестра.
    /// Флип на wusdt — одна строка (после деплоя wUSDT-пула).
    #[serde(default = "default_asset")]
    pub asset: String,
    /// RPC-оверрайд для mainnet-бэкенда (напр. Helius); пусто → registry default.
    #[serde(default)]
    pub rpc_mainnet: Option<String>,
    /// RPC-оверрайд для devnet-бэкенда; пусто → registry default.
    #[serde(default)]
    pub rpc_devnet: Option<String>,
    /// Политика mainnet на время церемонии/показа: "closed" (mainnet заблокирован),
    /// "cap_1" (не больше 1 токена за операцию), "open" (без лимита). Дефолт
    /// "closed" — безопасно; devnet всегда открыт.
    #[serde(default = "default_mainnet_policy")]
    pub mainnet_policy: String,
}

fn default_mainnet_policy() -> String {
    // cap_1 — mainnet включён, но каждая операция капится 1 токеном (демо/церемония).
    // "closed" оставлен как аварийный выключатель (правится в config.toml).
    "cap_1".to_string()
}

fn default_true() -> bool {
    true
}
fn default_network() -> String {
    "mainnet-beta".to_string()
}
fn default_asset() -> String {
    "wusdc".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            admins: vec![DEFAULT_ADMIN.to_string()],
            auto_mover: true,
            network: default_network(),
            asset: default_asset(),
            rpc_mainnet: None,
            rpc_devnet: None,
            mainnet_policy: default_mainnet_policy(),
        }
    }
}

/// Активная сеть — per-request (один сервис держит оба бэкенда и выбирает по
/// сети из запроса). RwLock, дефолт Mainnet (строгий). Сервис сериальный.
static ACTIVE_NETWORK: RwLock<Network> = RwLock::new(Network::Mainnet);

/// Установить активную сеть (per-request из поля запроса).
pub fn set_active_network(net: Network) {
    if let Ok(mut n) = ACTIVE_NETWORK.write() {
        *n = net;
    }
}

/// Активная сеть (дефолт Mainnet).
pub fn active_network() -> Network {
    ACTIVE_NETWORK.read().map(|n| *n).unwrap_or(Network::Mainnet)
}

/// Активный актив (wUSDC / wUSDT) — определяет пул + минты из реестра.
/// RwLock (не OnceLock): сервис сериальный, актив переключается per-request
/// (чип на странице). Дефолт wUSDC.
static ACTIVE_ASSET: RwLock<Asset> = RwLock::new(Asset::Wusdc);

pub fn set_active_asset(asset: Asset) {
    if let Ok(mut a) = ACTIVE_ASSET.write() {
        *a = asset;
    }
}

/// Активный актив (по умолчанию wUSDC).
pub fn active_asset() -> Asset {
    ACTIVE_ASSET.read().map(|a| *a).unwrap_or(Asset::Wusdc)
}

impl Config {
    fn path() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("нет $HOME")?;
        Ok(PathBuf::from(home)
            .join(".tidex6-wusdc")
            .join("config.toml"))
    }

    /// Читает config.toml; при отсутствии создаёт дефолтный и возвращает его.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(raw) => toml::from_str(&raw).context("parse config.toml"),
            Err(_) => {
                let cfg = Config::default();
                cfg.write_default(&path).ok();
                Ok(cfg)
            }
        }
    }

    fn write_default(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        if let Some(dir) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .ok();
        }
        let body = format!(
            "# tidex6-wusdc service config\n\
             # Wallets (base58) allowed to trigger operations.\n\
             admins = [\"{}\"]\n\
             # Auto-pay: run the mover in-process right after 'configure'\n\
             # (event-driven, no timer polling). false = keep Mover manual.\n\
             auto_mover = {}\n\
             # Network: \"mainnet-beta\" | \"devnet\". Picks mints/pool from the\n\
             # tidex6-core registry. Flip to \"devnet\" after the devnet deploy.\n\
             network = \"{}\"\n\
             # Asset: \"wusdc\" | \"wusdt\". Picks pool + mints from the registry.\n\
             asset = \"{}\"\n\
             # Mainnet policy during the ceremony/demo: \"closed\" (mainnet blocked),\n\
             # \"cap_1\" (max 1 token per op), \"open\" (no limit). Devnet is always open.\n\
             mainnet_policy = \"{}\"\n",
            self.admins.first().map(String::as_str).unwrap_or(DEFAULT_ADMIN),
            self.auto_mover,
            self.network,
            self.asset,
            self.mainnet_policy,
        );
        std::fs::write(path, body).context("write config.toml")?;
        Ok(())
    }

    /// Разрешён ли кошелёк запускать операции.
    pub fn is_admin(&self, wallet: &str) -> bool {
        !wallet.is_empty() && self.admins.iter().any(|a| a == wallet)
    }

    /// Сеть из конфига (по умолчанию Mainnet при неизвестном moniker).
    pub fn network(&self) -> Network {
        Network::from_moniker(&self.network).unwrap_or(Network::Mainnet)
    }

    /// Актив из конфига (по умолчанию wUSDC при неизвестном symbol).
    pub fn asset(&self) -> Asset {
        Asset::from_symbol(&self.asset).unwrap_or(Asset::Wusdc)
    }

    /// Гейт mainnet на время церемонии/показа. Возвращает Err с человекочитаемой
    /// причиной, если операция на сумму `amount_micro` запрещена. Devnet эту
    /// проверку не вызывает (всегда открыт).
    pub fn mainnet_gate(&self, amount_micro: u64) -> Result<()> {
        match self.mainnet_policy.as_str() {
            "open" => Ok(()),
            "cap_1" => {
                if amount_micro > 1_000_000 {
                    anyhow::bail!(
                        "Mainnet is capped at 1 token during the ceremony/demo (requested {}).",
                        amount_micro as f64 / 1e6
                    );
                }
                Ok(())
            }
            // "closed" и любое неизвестное значение — строго закрыто.
            _ => anyhow::bail!(
                "Mainnet is closed during the ceremony and demo — use devnet. (set mainnet_policy = \"cap_1\" or \"open\" to allow)"
            ),
        }
    }

    /// RPC-оверрайд для сети (None → registry default_rpc).
    pub fn rpc_override(&self, net: Network) -> Option<&str> {
        match net {
            Network::Mainnet => self.rpc_mainnet.as_deref(),
            Network::Devnet => self.rpc_devnet.as_deref(),
        }
    }
}
