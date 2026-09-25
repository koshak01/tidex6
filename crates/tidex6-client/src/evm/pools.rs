//! Пулы со скрытой суммой на EVM-цепях — те же, что у сайта и релеера.
//!
//! Запись — это пул, а не цепь: второй токен на той же цепи идёт отдельной
//! записью со своим ключом, как у сайта (`static/js/core/evm-chain.js`) и
//! релеера (`src/evm.rs`). Ключи у всех трёх одинаковые — по ключу релеер
//! отдаёт индекс депозитов и принимает вывод.
//!
//! Записи `-v1` — прежние версии пулов, заменённые 25.09.2026 пулами с
//! `depositWithFee`. Ноты в них по-прежнему тратятся, поэтому их читают
//! `payments` и `collect`; новых денег они не принимают.

/// Один пул со скрытой суммой.
#[derive(Debug, Clone, Copy)]
pub struct EvmPool {
    /// Ключ, общий с сайтом и релеером: `arc-mainnet`, `base-sepolia`, …
    pub key: &'static str,
    /// Как пул называть человеку.
    pub name: &'static str,
    pub chain_id: u64,
    /// Узел, через который уходит подписанная транзакция: публичный узел
    /// цепи, тот же, что кошелёк получает при добавлении сети.
    pub send_url: &'static str,
    /// Узел для чтения — прокси релеера: адрес агента не уходит чужому узлу.
    pub read_url: &'static str,
    pub explorer: &'static str,
    pub hidden_pool: &'static str,
    /// ERC-20, который держит пул.
    pub token: &'static str,
    pub token_symbol: &'static str,
    pub token_decimals: u8,
    /// Реестр читателей этой цепи: кошелёк публикует в нём свой ключ.
    pub registry: &'static str,
    /// Пул принимает платёж и ноту комиссии одним вызовом.
    pub has_deposit_with_fee: bool,
    /// Прежняя версия пула: только вывод.
    pub is_withdraw_only: bool,
    /// Реестр ключей владельца этой цепи (`Tidex6OwnerKeys`) — у пулов формата
    /// v2 (ADR-022); пусто у v1.
    pub owner_keys: &'static str,
    /// Деньги настоящие — действуют потолки трат, как на Solana mainnet.
    pub is_mainnet: bool,
}

impl EvmPool {
    /// Пул формата v2: лист считает пул, тратит только владелец.
    pub fn is_v2(&self) -> bool {
        !self.owner_keys.is_empty()
    }

    /// Сколько базовых единиц токена в одной микро-единице конверта.
    ///
    /// Конверт везде несёт микро-единицы (шесть знаков), commitment и вывод —
    /// базовые единицы токена. У USDC это одно и то же, у TSLA — `10^12`.
    pub fn base_units_per_micro(&self) -> u64 {
        10u64.pow(u32::from(self.token_decimals.saturating_sub(6)))
    }
}

/// Найти пул по ключу.
pub fn pool(key: &str) -> Option<&'static EvmPool> {
    POOLS.iter().find(|p| p.key == key)
}

/// Все пулы, в которые можно платить.
pub fn payable() -> impl Iterator<Item = &'static EvmPool> {
    POOLS.iter().filter(|p| !p.is_withdraw_only)
}

/// Все пулы одной цепи — текущие и прежние, всех токенов.
///
/// Получатель не знает, каким токеном и в какую версию пула ему заплатили:
/// это знает только отправитель. Искать поэтому надо во всех.
pub fn on_chain(chain_id: u64) -> impl Iterator<Item = &'static EvmPool> {
    POOLS.iter().filter(move |p| p.chain_id == chain_id)
}

const ARB_SEPOLIA_SEND: &str = "https://sepolia-rollup.arbitrum.io/rpc";
const ARB_SEPOLIA_READ: &str = "https://relayer.tidex6.com/rpc-arbitrum-sepolia/";
const ARB_SEPOLIA_EXPLORER: &str = "https://sepolia.arbiscan.io";
const ARB_SEPOLIA_REGISTRY: &str = "0x6d6fe78aa241ee2f8f1c49e7fa2044be5f3f6101";
const ROBINHOOD_SEND: &str = "https://rpc.testnet.chain.robinhood.com";
const ROBINHOOD_READ: &str = "https://relayer.tidex6.com/rpc-robinhood-testnet/";
const ROBINHOOD_EXPLORER: &str = "https://explorer.testnet.chain.robinhood.com";
const ROBINHOOD_REGISTRY: &str = "0x28855dbf155de429069aabc2020a613901d707d9";
const BASE_SEPOLIA_SEND: &str = "https://sepolia.base.org";
const BASE_SEPOLIA_READ: &str = "https://relayer.tidex6.com/rpc-base-sepolia/";
const BASE_SEPOLIA_EXPLORER: &str = "https://sepolia.basescan.org";
const BASE_SEPOLIA_REGISTRY: &str = "0x6F6F07e14E8381D13D01f99867985D8c7D23E914";
const HYPERLIQUID_SEND: &str = "https://rpc.hyperliquid-testnet.xyz/evm";
const HYPERLIQUID_READ: &str = "https://relayer.tidex6.com/rpc-hyperliquid-testnet/";
const HYPERLIQUID_EXPLORER: &str = "https://testnet.purrsec.com";
const HYPERLIQUID_REGISTRY: &str = "0x8eb05Cb1b5E46e58C8ca91E3A3738CF534c1E74f";
const ARC_TESTNET_SEND: &str = "https://rpc.testnet.arc.io";
const ARC_TESTNET_READ: &str = "https://relayer.tidex6.com/rpc-arc-testnet/";
const ARC_TESTNET_EXPLORER: &str = "https://explorer.testnet.arc.io";
const ARC_MAINNET_SEND: &str = "https://rpc.mainnet.arc.io";
const ARC_MAINNET_READ: &str = "https://relayer.tidex6.com/rpc-arc-mainnet/";
const ARC_MAINNET_EXPLORER: &str = "https://explorer.arc.io";
const ARC_REGISTRY: &str = "0x6F6F07e14E8381D13D01f99867985D8c7D23E914";
/// USDC на Arc — это и газ, и ERC-20 по этому адресу (шесть знаков).
const ARC_USDC: &str = "0x3600000000000000000000000000000000000000";

const ARB_SEPOLIA_USDC: &str = "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d";
const ARB_SEPOLIA_USDG: &str = "0xFFC95faa3d63Cde504a05B567C600B78C0b41892";
const ROBINHOOD_TSLA: &str = "0xC9f9c86933092BbbfFF3CCb4b105A4A94bf3Bd4E";
const ROBINHOOD_USDG: &str = "0x7E955252E15c84f5768B83c41a71F9eba181802F";
const BASE_SEPOLIA_USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const HYPERLIQUID_TUSDC: &str = "0x2c94135FB49840a0D6e0985AB1A6c48EE6c140d6";

/// Строка таблицы. Семь из двенадцати полей у пулов одной цепи общие, и
/// функция держит их в одном месте вместо повтора на каждой записи.
#[allow(clippy::too_many_arguments)]
const fn row(
    key: &'static str,
    name: &'static str,
    chain_id: u64,
    urls: (&'static str, &'static str, &'static str),
    registry: &'static str,
    hidden_pool: &'static str,
    token: (&'static str, &'static str, u8),
    flags: (bool, bool, bool),
) -> EvmPool {
    EvmPool {
        key,
        name,
        chain_id,
        send_url: urls.0,
        read_url: urls.1,
        explorer: urls.2,
        hidden_pool,
        token: token.0,
        token_symbol: token.1,
        token_decimals: token.2,
        registry,
        has_deposit_with_fee: flags.0,
        is_withdraw_only: flags.1,
        is_mainnet: flags.2,
        owner_keys: "",
    }
}

const ARB: (&str, &str, &str) = (ARB_SEPOLIA_SEND, ARB_SEPOLIA_READ, ARB_SEPOLIA_EXPLORER);
const RH: (&str, &str, &str) = (ROBINHOOD_SEND, ROBINHOOD_READ, ROBINHOOD_EXPLORER);
const BASE: (&str, &str, &str) = (BASE_SEPOLIA_SEND, BASE_SEPOLIA_READ, BASE_SEPOLIA_EXPLORER);
const HL: (&str, &str, &str) = (HYPERLIQUID_SEND, HYPERLIQUID_READ, HYPERLIQUID_EXPLORER);
const ARC_T: (&str, &str, &str) = (ARC_TESTNET_SEND, ARC_TESTNET_READ, ARC_TESTNET_EXPLORER);
const ARC_M: (&str, &str, &str) = (ARC_MAINNET_SEND, ARC_MAINNET_READ, ARC_MAINNET_EXPLORER);

/// Флаги `(has_deposit_with_fee, is_withdraw_only, is_mainnet)`.
const CURRENT: (bool, bool, bool) = (true, false, false);
const CURRENT_MAINNET: (bool, bool, bool) = (true, false, true);
const THREE_STEP: (bool, bool, bool) = (false, false, false);
const EARLIER: (bool, bool, bool) = (false, true, false);
const EARLIER_MAINNET: (bool, bool, bool) = (false, true, true);

pub const POOLS: &[EvmPool] = &[
    row(
        "arbitrum-sepolia",
        "Arbitrum Sepolia",
        421_614,
        ARB,
        ARB_SEPOLIA_REGISTRY,
        "0xf3393Da300A29499e96A963b5C52edd0f0125702",
        (ARB_SEPOLIA_USDC, "USDC", 6),
        CURRENT,
    ),
    row(
        "arbitrum-sepolia-usdg",
        "Arbitrum Sepolia · USDG",
        421_614,
        ARB,
        ARB_SEPOLIA_REGISTRY,
        "0xA7a415E9edA7Ff90bb0D33C6db7078f577C23155",
        (ARB_SEPOLIA_USDG, "USDG", 6),
        CURRENT,
    ),
    row(
        "robinhood-testnet",
        "Robinhood Chain Testnet",
        46_630,
        RH,
        ROBINHOOD_REGISTRY,
        "0x0AaB0D98f2a0Da6F2002dA8D3ddB314208341725",
        (ROBINHOOD_TSLA, "TSLA", 18),
        CURRENT,
    ),
    row(
        "robinhood-usdg",
        "Robinhood Chain · USDG",
        46_630,
        RH,
        ROBINHOOD_REGISTRY,
        "0x819c6Ea7E7AeA2Eb95D1926D520A76cD03c53acA",
        (ROBINHOOD_USDG, "USDG", 6),
        CURRENT,
    ),
    row(
        "base-sepolia",
        "Base Sepolia",
        84_532,
        BASE,
        BASE_SEPOLIA_REGISTRY,
        "0x17F6cb7C4De0dbFE18e37fdF4CE08DdA33b9DEf3",
        (BASE_SEPOLIA_USDC, "USDC", 6),
        CURRENT,
    ),
    // Пул с `depositWithFee` на HyperEVM ещё не задеплоен (не влез в быстрый
    // блок); до тех пор платёж там — три шага.
    row(
        "hyperliquid-testnet",
        "Hyperliquid Testnet",
        998,
        HL,
        HYPERLIQUID_REGISTRY,
        "0x9776E68B41CA42970b81e4D33cc0f5729F4D8D5f",
        (HYPERLIQUID_TUSDC, "tUSDC", 6),
        THREE_STEP,
    ),
    row(
        "arc-testnet",
        "Arc Testnet",
        5_042_002,
        ARC_T,
        ARC_REGISTRY,
        "0xbAF576FFA109af38E2b2573b063e5A230eEf3070",
        (ARC_USDC, "USDC", 6),
        CURRENT,
    ),
    row(
        "arc-mainnet",
        "Arc",
        5_042,
        ARC_M,
        ARC_REGISTRY,
        "0xE9182c3B0cdf5bFb8871aC162fa28A501a3Cfa82",
        (ARC_USDC, "USDC", 6),
        CURRENT_MAINNET,
    ),
    // Стенд формата v2 (ADR-022), 25.09.2026: лист считает пул, тратит только
    // владелец, комиссия обязательная. Ключи — генезис церемонии v2 (ноль
    // вкладов), только тестнет; на выкате v2 займёт место основного пула.
    EvmPool {
        owner_keys: "0x6CEDF1b9877bd980cE0a90eDC5a1c5BEfb6C2B81",
        ..row(
            "arc-testnet-v2",
            "Arc Testnet · v2",
            5_042_002,
            ARC_T,
            ARC_REGISTRY,
            "0x1D680c59Ddad60A1352d50DEC15908C2B4a1660A",
            (ARC_USDC, "USDC", 6),
            CURRENT,
        )
    },
    row(
        "arbitrum-sepolia-v1",
        "Earlier pool · Arbitrum Sepolia",
        421_614,
        ARB,
        ARB_SEPOLIA_REGISTRY,
        "0xe4c1f2bc121800b8e56ff11dced9a62d6ce3b383",
        (ARB_SEPOLIA_USDC, "USDC", 6),
        EARLIER,
    ),
    row(
        "arbitrum-sepolia-usdg-v1",
        "Earlier pool · Arbitrum Sepolia · USDG",
        421_614,
        ARB,
        ARB_SEPOLIA_REGISTRY,
        "0x27ee24bea73088095b2898b3098e2b6040515275",
        (ARB_SEPOLIA_USDG, "USDG", 6),
        EARLIER,
    ),
    row(
        "robinhood-testnet-v1",
        "Earlier pool · Robinhood Chain Testnet",
        46_630,
        RH,
        ROBINHOOD_REGISTRY,
        "0xf4029451b6988d32ed1a9de847bf3250e83a87fe",
        (ROBINHOOD_TSLA, "TSLA", 18),
        EARLIER,
    ),
    row(
        "robinhood-usdg-v1",
        "Earlier pool · Robinhood Chain · USDG",
        46_630,
        RH,
        ROBINHOOD_REGISTRY,
        "0x73f68e1e4d02557e6cefd0292ffac13da5d18490",
        (ROBINHOOD_USDG, "USDG", 6),
        EARLIER,
    ),
    row(
        "base-sepolia-v1",
        "Earlier pool · Base Sepolia",
        84_532,
        BASE,
        BASE_SEPOLIA_REGISTRY,
        "0xC821B4BF26CF181253b60C1116Bb1Fa6D7dCB0D4",
        (BASE_SEPOLIA_USDC, "USDC", 6),
        EARLIER,
    ),
    row(
        "arc-testnet-v1",
        "Earlier pool · Arc Testnet",
        5_042_002,
        ARC_T,
        ARC_REGISTRY,
        "0x28fbB1500875EaEbe303D195C1a3721BBed8AF5f",
        (ARC_USDC, "USDC", 6),
        EARLIER,
    ),
    row(
        "arc-mainnet-v1",
        "Earlier pool · Arc",
        5_042,
        ARC_M,
        ARC_REGISTRY,
        "0x28fbB1500875EaEbe303D195C1a3721BBed8AF5f",
        (ARC_USDC, "USDC", 6),
        EARLIER_MAINNET,
    ),
];
