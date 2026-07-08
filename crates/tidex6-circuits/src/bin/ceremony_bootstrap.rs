//! Одноразовый bootstrap церемонии (Путь A, Rust-native): готовит стартовый
//! `genesis.state` (эталон для verify) и `current.state` (то, что качает
//! браузер) в `~/.tidex6-ceremony/`, а также пустой `log.json`.
//!
//! Источник genesis (все три дают байт-в-байт одинаковый детерминированный
//! результат — setup без энтропии):
//!   1. явный аргумент — путь к snarkjs zkey (setup, 0 вкладов);
//!   2. дефолтный dev-zkey `~/work/rust/tidex6/_ceremony/withdraw_0000.zkey`;
//!   3. фоллбэк для прода (zkey нет) — готовый `ceremony/withdraw_genesis.state`
//!      из репозитория (снимает нужду тащить snarkjs/zkey на сервер).
//!
//! Дальше snarkjs не нужен — вклады идут нашим WASM `ceremony_contribute`,
//! сервер проверяет `mpc::verify_extension`.
//!
//! Запуск: cargo run -p tidex6-circuits --bin ceremony_bootstrap [-- <zkey>]

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;

use tidex6_circuits::mpc::CeremonyState;
use tidex6_circuits::zkey::read_zkey_pk;

/// Воспроизводимый genesis-ассет в репе — фоллбэк для прода без snarkjs.
const GENESIS_ASSET: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/ceremony/withdraw_genesis.state"
);

fn main() {
    let home = std::env::var("HOME").unwrap();
    let dir = format!("{home}/.tidex6-ceremony");
    fs::create_dir_all(&dir).expect("mkdir ceremony dir");

    let arg = std::env::args().nth(1);
    let default_zkey = format!("{home}/work/rust/tidex6/_ceremony/withdraw_0000.zkey");
    let zkey = arg.unwrap_or(default_zkey);

    // zkey есть (dev) → парсим его; иначе (прод) → берём готовый genesis-ассет.
    let genesis_bytes: Vec<u8> = if Path::new(&zkey).exists() {
        println!("reading initial zkey: {zkey}");
        let mut reader = BufReader::new(File::open(&zkey).expect("open zkey"));
        let pk = read_zkey_pk(&mut reader).expect("read_zkey_pk");
        CeremonyState::genesis(pk).to_bytes()
    } else {
        println!("zkey not found — using committed genesis asset: {GENESIS_ASSET}");
        fs::read(GENESIS_ASSET).expect("read committed genesis asset")
    };

    println!("genesis CeremonyState: {} bytes", genesis_bytes.len());
    fs::write(format!("{dir}/genesis.state"), &genesis_bytes).expect("write genesis.state");
    fs::write(format!("{dir}/current.state"), &genesis_bytes).expect("write current.state");
    fs::write(format!("{dir}/log.json"), "[]").expect("write log.json");

    println!("wrote {dir}/{{genesis.state, current.state, log.json}}");
    println!("bootstrap done — snarkjs больше не нужен для церемонии");
}
