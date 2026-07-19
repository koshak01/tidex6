//! Beacon finalization of the public Phase-2 ceremony (ADR-017 stage 1).
//!
//! Closes the ceremony by applying a public random beacon (drand) as the final,
//! DETERMINISTIC contribution. The beacon value for a pre-announced future round
//! is unknown to everyone while the ceremony is open, so no contributor can bias
//! the final parameters; yet it is public and verifiable afterward, so anyone who
//! downloaded the frozen `CeremonyState` can reproduce this exact step.
//!
//! The beacon seeds a ChaCha20 CSPRNG; the finalization runs the SAME reviewed
//! `contribute_state` path as every human contribution — no new trusted
//! primitive, just a deterministic RNG instead of OS entropy.
//!
//! Usage:
//!
//! ```text
//! # take round + randomness from https://api.drand.love/public/<round>
//! cargo run --bin ceremony_finalize --release -- <drand_round> <randomness_hex>
//! ```
//!
//! Reads `~/.tidex6-ceremony/{genesis.state, current.state}`, writes
//! `final.state` (and updates `current.state`) plus `final.json` (audit record).

use std::fs;

use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha512};
use tidex6_circuits::mpc::{CeremonyState, VerifyOutcome, contribute_state, verify_chain};

fn main() {
    let mut args = std::env::args().skip(1);
    let round: u64 = args
        .next()
        .and_then(|s| s.parse().ok())
        .expect("usage: ceremony_finalize <drand_round> <randomness_hex>");
    let randomness_hex = args
        .next()
        .expect("usage: ceremony_finalize <drand_round> <randomness_hex>");
    let randomness = hex::decode(randomness_hex.trim()).expect("randomness must be hex");

    let home = std::env::var("HOME").expect("HOME");
    let dir = format!("{home}/.tidex6-ceremony");
    let genesis_path = format!("{dir}/genesis.state");
    let current_path = format!("{dir}/current.state");

    let genesis = CeremonyState::from_bytes(&fs::read(&genesis_path).expect("read genesis.state"))
        .expect("parse genesis.state");
    let mut state = CeremonyState::from_bytes(&fs::read(&current_path).expect("read current.state"))
        .expect("parse current.state");

    let contributions_before = state.contributions.len();
    println!("ceremony: {contributions_before} human contribution(s) before finalization");
    println!("drand round: {round}");

    // Deterministic finalization seed: domain-separated hash of the beacon.
    let mut h = Sha512::new();
    h.update(b"tidex6-ceremony-final-v1");
    h.update(round.to_le_bytes());
    h.update(&randomness);
    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    let mut rng = ChaCha20Rng::from_seed(seed);

    let name = format!("drand-beacon-round-{round}");
    let contribution = contribute_state(&mut state, name.clone(), &mut rng);
    println!("applied beacon contribution: {name}");
    println!("  delta_after (hex64): {}", short_hex(&contribution.delta_after));

    // Sanity: the full chain (genesis → all human contributions → beacon) must
    // verify. If this fails we do NOT write final.state.
    match verify_chain(&genesis.pk, &state.pk, &state.contributions, &state.cs_hash) {
        VerifyOutcome::Ok => println!("verify_chain: OK ({} contributions)", state.contributions.len()),
        other => panic!("verify_chain FAILED after beacon: {other:?} — final.state NOT written"),
    }

    let final_bytes = state.to_bytes();
    fs::write(format!("{dir}/final.state"), &final_bytes).expect("write final.state");
    // Freeze: current.state now equals the finalized state.
    fs::write(&current_path, &final_bytes).expect("update current.state");

    // Audit record — anyone can re-run finalization from these values.
    let audit = format!(
        "{{\n  \"drand_round\": {round},\n  \"randomness_hex\": \"{}\",\n  \"human_contributions\": {contributions_before},\n  \"total_contributions\": {},\n  \"cs_hash_hex\": \"{}\"\n}}\n",
        hex::encode(&randomness),
        state.contributions.len(),
        hex::encode(state.cs_hash),
    );
    fs::write(format!("{dir}/final.json"), audit).expect("write final.json");

    println!("wrote {dir}/{{final.state, final.json}} and froze current.state");
    println!("next: cargo run --bin ceremony_extract_vk --release");
}

/// First/last bytes of a serialized point, for a human-readable log line.
fn short_hex<T: ark_serialize::CanonicalSerialize>(point: &T) -> String {
    let mut buf = Vec::new();
    point.serialize_uncompressed(&mut buf).expect("serialize");
    let n = buf.len();
    format!("{}…{}", hex::encode(&buf[..8.min(n)]), hex::encode(&buf[n.saturating_sub(8)..]))
}
