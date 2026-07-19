//! Public, independent verification of the ceremony contribution chain
//! (ADR-017 stage 4 — "the server log is not the source of truth, the
//! published reproducible chain is").
//!
//! Any contributor (or observer) downloads the published transcript —
//! `genesis.state` + the latest `current.state` (or the frozen `final.state`)
//! — and runs this tool. It re-checks, with no trust in the coordinator:
//!
//! 1. `genesis.state` is internally consistent (`cs_hash` matches its pk);
//! 2. the downloaded state belongs to the SAME circuit (`cs_hash` equality);
//! 3. the full MPC chain (`mpc::verify_chain`): every contribution carries a
//!    valid proof-of-knowledge, the delta chain links genesis → … → current,
//!    and no setup section was tampered with;
//! 4. prints every contribution's name + attestation (compressed
//!    `delta_after`, the same hex shown in the ceremony page log) so each
//!    contributor can confirm their own entry is included and unaltered.
//!
//! Usage:
//!
//! ```text
//! cargo run --release -p tidex6-circuits --bin ceremony_verify -- \
//!     <genesis.state> <current-or-final.state>
//! ```
//!
//! Without arguments it reads `~/.tidex6-ceremony/{genesis,current}.state`.

use std::fs;

use ark_serialize::CanonicalSerialize;
use tidex6_circuits::mpc::{CeremonyState, VerifyOutcome, cs_hash, verify_chain};

fn main() {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut args = std::env::args().skip(1);
    let genesis_path = args
        .next()
        .unwrap_or(format!("{home}/.tidex6-ceremony/genesis.state"));
    let state_path = args
        .next()
        .unwrap_or(format!("{home}/.tidex6-ceremony/current.state"));

    println!("genesis: {genesis_path}");
    println!("state:   {state_path}");

    let genesis = CeremonyState::from_bytes(&fs::read(&genesis_path).expect("read genesis state"))
        .expect("parse genesis CeremonyState");
    let state = CeremonyState::from_bytes(&fs::read(&state_path).expect("read ceremony state"))
        .expect("parse CeremonyState");

    // 1. Genesis is internally consistent: its recorded cs_hash matches its pk.
    if cs_hash(&genesis.pk) != genesis.cs_hash {
        eprintln!("FAIL: genesis cs_hash does not match its proving key — corrupted genesis");
        std::process::exit(1);
    }
    println!("genesis cs_hash: {} (self-consistent)", hex::encode(&genesis.cs_hash[..16]));

    // 2. Same circuit: the downloaded state must reference the same setup.
    if state.cs_hash != genesis.cs_hash {
        eprintln!("FAIL: state cs_hash differs from genesis — different circuit/setup");
        std::process::exit(1);
    }

    // 3+4. Full MPC chain check, then the human-readable contribution list.
    println!("contributions: {}", state.contributions.len());
    for (i, c) in state.contributions.iter().enumerate() {
        let mut buf = Vec::new();
        c.delta_after
            .serialize_compressed(&mut buf)
            .expect("serialize delta_after");
        println!("  #{:<3} {:<48} {}", i + 1, c.name, hex::encode(&buf));
    }

    match verify_chain(&genesis.pk, &state.pk, &state.contributions, &state.cs_hash) {
        VerifyOutcome::Ok => {
            println!(
                "verify_chain: OK — every contribution is a valid, proof-of-knowledge-backed \
                 extension of genesis; no section was tampered with"
            );
        }
        other => {
            eprintln!("verify_chain FAILED: {other:?}");
            std::process::exit(1);
        }
    }
}
