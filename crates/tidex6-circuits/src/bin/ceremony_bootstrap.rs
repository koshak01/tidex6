//! One-shot ceremony bootstrap (Path A, Rust-native): prepares the initial
//! `genesis.state` (the reference for verification) and `current.state` (what
//! the browser downloads) in `~/.tidex6-ceremony/`, plus an empty `log.json`.
//!
//! Genesis source (all three yield the same deterministic bytes — the setup has
//! no entropy of its own):
//!   1. an explicit argument — path to a snarkjs zkey (setup, 0 contributions);
//!   2. the default dev zkey `~/work/rust/tidex6/_ceremony/withdraw_0000.zkey`;
//!   3. the production fallback (no zkey) — the committed genesis asset from the
//!      repository (no need to ship snarkjs/zkey to the server).
//!
//! From there snarkjs is not needed — contributions go through our WASM
//! `ceremony_contribute`, the server checks `mpc::verify_extension`.
//!
//! Two circuits — two geneses. `--scheme confidential` takes the asset of the
//! second circuit (`tidex6-confidential/ceremony/withdraw_genesis.state`);
//! without the flag — the old one. An explicit zkey path overrides both: the
//! genesis is built from it directly, and the circuit is whichever the zkey is for.
//!
//! Run: cargo run -p tidex6-circuits --bin ceremony_bootstrap [-- [--scheme confidential] [<zkey>]]

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;

use tidex6_circuits::mpc::CeremonyState;
use tidex6_circuits::zkey::read_zkey_pk;

/// Reproducible genesis asset in the repo — production fallback without snarkjs.
const GENESIS_ASSET: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/ceremony/withdraw_genesis.state"
);

/// Same fallback for the hidden-amount circuit (8 public inputs).
const GENESIS_ASSET_CONFIDENTIAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tidex6-confidential/ceremony/withdraw_genesis.state"
);

fn main() {
    let home = std::env::var("HOME").unwrap();
    let dir = format!("{home}/.tidex6-ceremony");
    fs::create_dir_all(&dir).expect("mkdir ceremony dir");

    // Hand-rolled argument parsing: a circuit flag and an optional zkey path.
    let mut confidential = false;
    let mut zkey_arg: Option<String> = None;
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--scheme" => {}
            "confidential" => confidential = true,
            other => zkey_arg = Some(other.to_string()),
        }
    }
    let asset = if confidential {
        GENESIS_ASSET_CONFIDENTIAL
    } else {
        GENESIS_ASSET
    };
    // Only the old circuit has a default dev zkey; the new one gets its genesis
    // either from an explicit zkey or from the asset.
    let default_zkey = format!("{home}/work/rust/tidex6/_ceremony/withdraw_0000.zkey");
    let zkey = match (zkey_arg, confidential) {
        (Some(z), _) => z,
        (None, false) => default_zkey,
        (None, true) => String::new(),
    };

    // zkey present (dev) → parse it; otherwise (prod) → take the committed genesis asset.
    let genesis_bytes: Vec<u8> = if !zkey.is_empty() && Path::new(&zkey).exists() {
        println!("reading initial zkey: {zkey}");
        let mut reader = BufReader::new(File::open(&zkey).expect("open zkey"));
        let pk = read_zkey_pk(&mut reader).expect("read_zkey_pk");
        CeremonyState::genesis(pk).to_bytes()
    } else {
        println!("zkey not given — using committed genesis asset: {asset}");
        fs::read(asset).expect("read committed genesis asset")
    };
    println!("genesis CeremonyState: {} bytes", genesis_bytes.len());

    fs::write(format!("{dir}/genesis.state"), &genesis_bytes).expect("write genesis.state");
    fs::write(format!("{dir}/current.state"), &genesis_bytes).expect("write current.state");
    fs::write(format!("{dir}/log.json"), "[]").expect("write log.json");
    println!("wrote {dir}/{{genesis.state, current.state, log.json}}");
    println!("bootstrap done — snarkjs is no longer needed for the ceremony");
}
