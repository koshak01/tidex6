//! Реестр сетей и активов — единый источник RPC / program-id / mint для всех
//! поверхностей (client SDK, wUSDC-сервис, web). Один раз задаём здесь — оба
//! трека (переключатель mainnet/testnet и мультиактив USDT) становятся почти
//! конфигом.
//!
//! Данные — плоские `&str` намеренно: модуль не тянет solana/anchor, чтобы его
//! мог включать кто угодно (даже WASM). Потребители парсят строки в свои
//! `Pubkey` / `Cluster`.
//!
//! `None` в адресах = «на этой сети ещё не задеплоено» (devnet-инстансы и
//! wrapped-минты заполняются после деплоя на devnet).

/// Solana-сеть, в которой работает приложение.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Mainnet,
    Devnet,
}

/// Актив, который приватизируем (SOL или обёрнутый стейблкоин Token-2022 CT).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Asset {
    Sol,
    Wusdc,
    Wusdt,
}

/// Сетевые параметры (RPC + asset-agnostic верификатор).
#[derive(Clone, Copy, Debug)]
pub struct NetworkInfo {
    pub network: Network,
    /// Solana/anchor moniker: "mainnet-beta" | "devnet".
    pub moniker: &'static str,
    /// Дефолтный публичный RPC (в проде переопределяется конфигом).
    pub default_rpc: &'static str,
    /// Groth16-верификатор (общий для всех активов); `None` — не задеплоен.
    pub verifier_program: Option<&'static str>,
}

/// Параметры одного актива на конкретной сети.
#[derive(Clone, Copy, Debug)]
pub struct AssetInfo {
    pub asset: Asset,
    pub symbol: &'static str,
    pub decimals: u8,
    /// Базовый минт (реальный USDC/USDT); `None` для SOL.
    pub underlying_mint: Option<&'static str>,
    /// Обёрнутый Token-2022 CT минт (скрывает сумму); `None` для SOL / не создан.
    pub wrapped_mint: Option<&'static str>,
    /// Пул этого актива (Groth16-связь); `None` — не задеплоен.
    pub pool_program: Option<&'static str>,
}

impl Network {
    /// Разобрать сеть из moniker'а (для конфигов / UI-тумблера).
    pub fn from_moniker(s: &str) -> Option<Self> {
        match s {
            "mainnet-beta" | "mainnet" => Some(Network::Mainnet),
            "devnet" => Some(Network::Devnet),
            _ => None,
        }
    }

    /// Определить сеть по RPC-URL (то, на что реально указывает `solana config`).
    /// Убирает рассинхрон config.network ↔ фактический RPC.
    pub fn from_rpc_url(url: &str) -> Self {
        if url.to_ascii_lowercase().contains("devnet") {
            Network::Devnet
        } else {
            Network::Mainnet
        }
    }

    /// Сетевые параметры.
    pub fn info(self) -> NetworkInfo {
        match self {
            Network::Mainnet => NetworkInfo {
                network: Network::Mainnet,
                moniker: "mainnet-beta",
                default_rpc: "https://api.mainnet-beta.solana.com",
                verifier_program: Some("CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd"),
            },
            Network::Devnet => NetworkInfo {
                network: Network::Devnet,
                moniker: "devnet",
                default_rpc: "https://api.devnet.solana.com",
                // TODO(devnet-deploy): задеплоить верификатор на devnet.
                verifier_program: None,
            },
        }
    }

    /// Параметры актива на этой сети (`None` — актив не поддержан здесь).
    pub fn asset(self, asset: Asset) -> Option<AssetInfo> {
        match (self, asset) {
            // ── Mainnet ──────────────────────────────────────────────
            (Network::Mainnet, Asset::Sol) => Some(AssetInfo {
                asset: Asset::Sol,
                symbol: "SOL",
                decimals: 9,
                underlying_mint: None,
                wrapped_mint: None,
                pool_program: None,
            }),
            (Network::Mainnet, Asset::Wusdc) => Some(AssetInfo {
                asset: Asset::Wusdc,
                symbol: "wUSDC",
                decimals: 6,
                underlying_mint: Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
                // Реальная Token-2022 CT-обёртка wUSDC на mainnet (совпадает
                // с оператор-конфигом `mainnet-beta_wusdc.wrapped`).
                wrapped_mint: Some("A1weSN5XnmTqjTR5YzdiriucEhFSnC7LgRq7VCnnBjLA"),
                pool_program: Some("AYTRKmF8VBdqRWGZr9c6Mx582SRm2tbUEwMesFMhcPcU"),
            }),
            (Network::Mainnet, Asset::Wusdt) => Some(AssetInfo {
                asset: Asset::Wusdt,
                symbol: "wUSDT",
                decimals: 6,
                // Реальный USDT (Tether) на Solana mainnet.
                underlying_mint: Some("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"),
                // Token-2022 CT-обёртка wUSDT на mainnet (создана при сетапе #103,
                // совпадает с оператор-конфигом `mainnet-beta_wusdt.wrapped`).
                wrapped_mint: Some("9s3nhzm6PooPA86jgPgHvFNHgXxvmBDjw64wwdzG6EZ2"),
                // Отдельный пул wUSDT (feature "wusdt", program keypair QGPY…).
                pool_program: Some("QGPYpwyMnWhJUPGieXyJU5jhAkKsKuU7iGN53VCWPz2"),
            }),
            // ── Devnet (заполняется после devnet-деплоя) ─────────────
            (Network::Devnet, Asset::Sol) => Some(AssetInfo {
                asset: Asset::Sol,
                symbol: "SOL",
                decimals: 9,
                underlying_mint: None,
                wrapped_mint: None,
                pool_program: None,
            }),
            (Network::Devnet, Asset::Wusdc) => Some(AssetInfo {
                asset: Asset::Wusdc,
                symbol: "wUSDC",
                decimals: 6,
                // Тестовый USDC (create_test_usdc, 2026-07-06).
                underlying_mint: Some("5h1rPrDgYBk6tYrKt3jnso6qHK2B5YKueSALKpaY2rEi"),
                // wUSDC Token-2022 CT (create_wusdc, 2026-07-06).
                wrapped_mint: Some("8XZT4i3FXAUo4vNSBQF4g69WumtxgxaVEgj36VBJg7Tn"),
                // Пул задеплоен на devnet по тому же адресу (2026-07-06,
                // tx 5dFvpRAraE3g…). Пул сам верифицирует — verifier не нужен.
                pool_program: Some("AYTRKmF8VBdqRWGZr9c6Mx582SRm2tbUEwMesFMhcPcU"),
            }),
            (Network::Devnet, Asset::Wusdt) => Some(AssetInfo {
                asset: Asset::Wusdt,
                symbol: "wUSDT",
                decimals: 6,
                // Тестовый USDT (create_test_usdc usdt, 2026-07-06).
                underlying_mint: Some("dPs6SKngzBC6Pdd8rPFAncH4q6z43KfLaVR5aRrAQQ5"),
                // wUSDT Token-2022 CT (create_wusdc wusdt, 2026-07-06).
                wrapped_mint: Some("2QRPbsXiLJLFU4LYbhfktwR6ifJVkqLy4xMC6aH6DTZZ"),
                // Тот же program-id QGPY на devnet (деплой того же .so).
                pool_program: Some("QGPYpwyMnWhJUPGieXyJU5jhAkKsKuU7iGN53VCWPz2"),
            }),
        }
    }
}

impl Asset {
    pub fn from_symbol(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SOL" => Some(Asset::Sol),
            "WUSDC" | "USDC" => Some(Asset::Wusdc),
            "WUSDT" | "USDT" => Some(Asset::Wusdt),
            _ => None,
        }
    }
}
