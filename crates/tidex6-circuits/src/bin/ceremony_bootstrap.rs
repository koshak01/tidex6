//! Одноразовый bootstrap церемонии (Путь A, Rust-native): читает стартовый
//! snarkjs zkey (setup, 0 вкладов) нашим парсером → `CeremonyState::genesis`
//! → пишет `genesis.state` (эталон для verify) и `current.state` (то, что
//! качает браузер) в `~/.tidex6-ceremony/`.
//!
//! Дальше snarkjs не нужен — вклады идут нашим WASM `ceremony_contribute`,
//! сервер проверяет `mpc::verify_extension`.
//!
//! Запуск: cargo run -p tidex6-circuits --bin ceremony_bootstrap [-- <zkey>]

use std::fs::{self, File};
use std::io::BufReader;

use tidex6_circuits::mpc::CeremonyState;
use tidex6_circuits::zkey::read_zkey_pk;

fn main() {
    let home = std::env::var("HOME").unwrap();
    let zkey = std::env::args()
        .nth(1)
        .unwrap_or_else(|| format!("{home}/work/rust/tidex6/_ceremony/withdraw_0000.zkey"));
    let dir = format!("{home}/.tidex6-ceremony");
    fs::create_dir_all(&dir).expect("mkdir ceremony dir");

    println!("reading initial zkey: {zkey}");
    let mut reader = BufReader::new(File::open(&zkey).expect("open zkey"));
    let pk = read_zkey_pk(&mut reader).expect("read_zkey_pk");

    let state = CeremonyState::genesis(pk);
    let bytes = state.to_bytes();
    println!("genesis CeremonyState: {} bytes, cs_hash[..8]={:02x?}", bytes.len(), &state.cs_hash[..8]);

    fs::write(format!("{dir}/genesis.state"), &bytes).expect("write genesis.state");
    fs::write(format!("{dir}/current.state"), &bytes).expect("write current.state");
    fs::write(format!("{dir}/log.json"), "[]").expect("write log.json");

    println!("wrote {dir}/{{genesis.state, current.state, log.json}}");
    println!("bootstrap done — snarkjs больше не нужен для церемонии");
}
