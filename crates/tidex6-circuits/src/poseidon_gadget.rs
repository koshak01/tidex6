//! R1CS Poseidon gadget that matches `light-poseidon`'s
//! `Poseidon::<Fr>::new_circom(n)` byte-for-byte.
//!
//! The gadget implements the fixed-width Poseidon permutation used
//! by `light-poseidon`, which is the same construction circomlib
//! and the `solana-poseidon` syscall use. We reuse the round
//! constants and MDS matrix directly from
//! `light_poseidon::parameters::bn254_x5::get_poseidon_parameters`
//! so there is zero risk of a parameter drift between the offchain
//! and in-circuit implementations.
//!
//! The public entry points are:
//!
//! - `poseidon_hash_pair_var` — the two-input form used by
//!   `Commitment::derive(secret, nullifier)` and by all Merkle-tree
//!   internal hashes.
//! - `poseidon_hash_n_var` — the general form for 1..=12 inputs,
//!   matching the `new_circom(n)` public API.
//!
//! Test vector validation lives in
//! `tests/poseidon_gadget_equivalence.rs`: every circuit hash is
//! recomputed offchain via `tidex6_core::poseidon` and asserted
//! byte-for-byte equal.

use std::time::Instant;

use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use light_poseidon::{PoseidonError as LightPoseidonError, PoseidonParameters};

/// Maximum number of inputs supported, matching
/// `light-poseidon`'s circom-compatible parameter set (widths 2..=13).
pub const MAX_INPUTS: usize = 12;

/// Inflation TRACE: where R1CS/RSS grow inside Poseidon (CLI vs MCP anomaly).
/// Grep: `pos_inflate`. Survives MCP `exit(99)` → `~/.tidex6-local/inflate-trace.log`.
fn pos_snap(cs: &ConstraintSystemRef<Fr>) -> (usize, usize, u64) {
    let cons = cs.num_constraints();
    let wit = cs.num_witness_variables();
    let rss = {
        let pid = std::process::id().to_string();
        std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
            .unwrap_or(0)
    };
    (cons, wit, rss)
}

/// Dig traces only when `TIDEX6_MEM_FIRST=1` (default off — production path stays fast).
fn mem_first_enabled() -> bool {
    matches!(
        std::env::var("TIDEX6_MEM_FIRST").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
}

/// Append TRACE line to stderr + `~/.tidex6-local/inflate-trace.log` (MCP-safe).
pub fn mem_trace(line: &str) {
    if !mem_first_enabled() {
        return;
    }
    eprintln!("{line}");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    if let Ok(home) = std::env::var("HOME") {
        let path = std::path::Path::new(&home).join(".tidex6-local/inflate-trace.log");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let _ = writeln!(f, "ts_ms={ts} {line}");
            let _ = f.flush();
        }
    }
}

fn pos_log(line: &str) {
    mem_trace(line);
}

/// Fetch the circom-compatible Poseidon parameters for a given
/// hash width. `nr_inputs` is the number of user inputs; the
/// internal state width is `nr_inputs + 1` (the extra slot is the
/// domain tag).
fn parameters_for(nr_inputs: usize) -> Result<PoseidonParameters<Fr>, LightPoseidonError> {
    assert!(
        (1..=MAX_INPUTS).contains(&nr_inputs),
        "circom Poseidon supports 1..=12 inputs; got {nr_inputs}"
    );
    let width: u8 = (nr_inputs + 1)
        .try_into()
        .expect("width fits in u8 for supported widths");
    light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(width)
}

/// Compute `Poseidon(a, b)` as an R1CS constraint. Matches
/// `tidex6_core::poseidon::hash_pair` on equivalent inputs.
pub fn poseidon_hash_pair_var(
    cs: ConstraintSystemRef<Fr>,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_n_var_tagged(cs, &[left.clone(), right.clone()], "pair")
}

/// Pair hash with TRACE tag (e.g. `merkle_L2`) for inflation dig.
pub fn poseidon_hash_pair_var_tagged(
    cs: ConstraintSystemRef<Fr>,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
    tag: &str,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_n_var_tagged(cs, &[left.clone(), right.clone()], tag)
}

/// General circom Poseidon hash over `inputs.len()` field elements.
/// The number of inputs must be in `1..=MAX_INPUTS`.
pub fn poseidon_hash_n_var(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_n_var_tagged(cs, inputs, "n")
}

/// Instrumented Poseidon R1CS — **where multi-GB thrash shows under MCP**.
///
/// Each round: ark → sbox → mds. Logs `pos_inflate` with Δconstraints /
/// RSS after each phase so we see *where* growth piles up (CLI ~flat
/// +~3–4 cons/round; MCP thrash = ms/RSS explode on same Δcons).
fn poseidon_hash_n_var_tagged(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
    tag: &str,
) -> Result<FpVar<Fr>, SynthesisError> {
    assert!(
        (1..=MAX_INPUTS).contains(&inputs.len()),
        "unsupported input count: {}",
        inputs.len()
    );

    let t0 = Instant::now();
    let params = parameters_for(inputs.len()).map_err(|_| SynthesisError::AssignmentMissing)?;

    let width = params.width;
    let full_rounds = params.full_rounds;
    let partial_rounds = params.partial_rounds;
    let half_full = full_rounds / 2;
    let total_rounds = full_rounds + partial_rounds;

    // Dig path only when TIDEX6_MEM_FIRST=1 (cold CLI/MCP production = fast).
    let deep = mem_first_enabled() && tag == "commitment";

    if mem_first_enabled() {
        let enter = pos_snap(&cs);
        pos_log(&format!(
            "mem_first: ENTER tag={tag} n={} width={width} rounds={total_rounds} \
             cons={} wit={} rss_kb={} thread={:?}",
            inputs.len(),
            enter.0,
            enter.1,
            enter.2,
            std::thread::current().name().unwrap_or("?"),
        ));
    }

    // Initial state: [domain_tag, inputs...].
    //
    // `light_poseidon::Poseidon::<Fr>::new_circom` constructs the
    // hasher with domain tag zero; we match that exactly.
    let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
    state.push(FpVar::<Fr>::new_constant(cs.clone(), Fr::from(0u64))?);
    for input in inputs {
        state.push(input.clone());
    }
    assert_eq!(
        state.len(),
        width,
        "initial state length must match Poseidon width"
    );

    for round in 0..total_rounds {
        let is_full_round = round < half_full || round >= half_full + partial_rounds;

        if deep {
            let s0 = pos_snap(&cs);
            apply_ark(cs.clone(), &mut state, &params, round)?;
            let s1 = pos_snap(&cs);
            if is_full_round {
                apply_sbox_full_traced(cs.clone(), &mut state, tag, round)?;
            } else {
                apply_sbox_partial_traced(cs.clone(), &mut state, tag, round)?;
            }
            let s2 = pos_snap(&cs);
            if round < 5 {
                apply_mds_traced(cs.clone(), &mut state, &params, tag, round)?;
            } else {
                apply_mds(cs.clone(), &mut state, &params)?;
            }
            let s3 = pos_snap(&cs);
            let kind = if is_full_round { "full" } else { "partial" };
            pos_log(&format!(
                "mem_first: tag={tag} round={round}/{total_rounds} kind={kind} \
                 ark_drss={} sbox_drss={} mds_drss={} round_drss={} rss={}",
                s1.2.saturating_sub(s0.2) as i64,
                s2.2.saturating_sub(s1.2) as i64,
                s3.2.saturating_sub(s2.2) as i64,
                s3.2.saturating_sub(s0.2) as i64,
                s3.2,
            ));
        } else {
            // Production path: no ps(), no dig — same as pre-instrumentation.
            apply_ark(cs.clone(), &mut state, &params, round)?;
            if is_full_round {
                apply_sbox_full(&mut state)?;
            } else {
                apply_sbox_partial(&mut state)?;
            }
            apply_mds(cs.clone(), &mut state, &params)?;
        }
    }

    let _ = t0; // dig timer reserved when MEM_FIRST on

    // Light Poseidon returns state[0] as the digest.
    Ok(state[0].clone())
}

/// Add round-specific constants to every element of the state.
fn apply_ark(
    cs: ConstraintSystemRef<Fr>,
    state: &mut [FpVar<Fr>],
    params: &PoseidonParameters<Fr>,
    round: usize,
) -> Result<(), SynthesisError> {
    for (i, slot) in state.iter_mut().enumerate() {
        let constant_index = round * params.width + i;
        let constant = params.ark[constant_index];
        let constant_var = FpVar::<Fr>::new_constant(cs.clone(), constant)?;
        *slot = slot.clone() + constant_var;
    }
    Ok(())
}

/// Apply the x^5 S-box to every element of the state (used during
/// full rounds).
fn apply_sbox_full(state: &mut [FpVar<Fr>]) -> Result<(), SynthesisError> {
    for slot in state.iter_mut() {
        *slot = pow_five(slot)?;
    }
    Ok(())
}

/// Full S-box + per-slot RSS (commitment dig).
fn apply_sbox_full_traced(
    cs: ConstraintSystemRef<Fr>,
    state: &mut [FpVar<Fr>],
    tag: &str,
    round: usize,
) -> Result<(), SynthesisError> {
    for (i, slot) in state.iter_mut().enumerate() {
        let before = pos_snap(&cs);
        *slot = pow_five_traced(cs.clone(), slot, tag, round, i)?;
        let after = pos_snap(&cs);
        pos_log(&format!(
            "mem_first: tag={tag} round={round} sbox_full slot={i} \
             dcons={} drss={} rss_kb={}",
            after.0.saturating_sub(before.0),
            after.2.saturating_sub(before.2) as i64,
            after.2,
        ));
    }
    Ok(())
}

/// Apply the x^5 S-box only to state[0] (used during partial
/// rounds). This is what gives the partial round its name: most of
/// the state passes through untouched, which drops the constraint
/// count compared to a full round.
fn apply_sbox_partial(state: &mut [FpVar<Fr>]) -> Result<(), SynthesisError> {
    state[0] = pow_five(&state[0])?;
    Ok(())
}

fn apply_sbox_partial_traced(
    cs: ConstraintSystemRef<Fr>,
    state: &mut [FpVar<Fr>],
    tag: &str,
    round: usize,
) -> Result<(), SynthesisError> {
    let before = pos_snap(&cs);
    state[0] = pow_five_traced(cs.clone(), &state[0], tag, round, 0)?;
    let after = pos_snap(&cs);
    pos_log(&format!(
        "mem_first: tag={tag} round={round} sbox_partial slot=0 \
         dcons={} drss={} rss_kb={}",
        after.0.saturating_sub(before.0),
        after.2.saturating_sub(before.2) as i64,
        after.2,
    ));
    Ok(())
}

/// Compute `x^5` as a constraint. `x^5 = (x^2)^2 * x`, which is
/// three multiplications — the optimal non-trivial exponentiation
/// for x^5 in a multiplicative constraint system.
fn pow_five(value: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let squared = value * value;
    let fourth = &squared * &squared;
    Ok(fourth * value)
}

/// Same as [`pow_five`] with RSS after each of the 3 multiplications.
fn pow_five_traced(
    cs: ConstraintSystemRef<Fr>,
    value: &FpVar<Fr>,
    tag: &str,
    round: usize,
    slot: usize,
) -> Result<FpVar<Fr>, SynthesisError> {
    let r0 = pos_snap(&cs);
    let squared = value * value;
    let r1 = pos_snap(&cs);
    let fourth = &squared * &squared;
    let r2 = pos_snap(&cs);
    let out = fourth * value;
    let r3 = pos_snap(&cs);
    // Only log mul steps on first 3 rounds of commitment (noise control).
    if round < 3 {
        pos_log(&format!(
            "mem_first: tag={tag} round={round} slot={slot} pow5 \
             mul1_sq dcons={} drss={} \
             mul2_sq2 dcons={} drss={} \
             mul3_x dcons={} drss={} rss={}",
            r1.0.saturating_sub(r0.0),
            r1.2.saturating_sub(r0.2) as i64,
            r2.0.saturating_sub(r1.0),
            r2.2.saturating_sub(r1.2) as i64,
            r3.0.saturating_sub(r2.0),
            r3.2.saturating_sub(r2.2) as i64,
            r3.2,
        ));
    }
    Ok(out)
}

/// Mix the state with the MDS matrix: new_state[i] =
/// sum_j state[j] * mds[i][j]. This is the linear diffusion step
/// of the Poseidon permutation.
///
/// **MDS** = Maximum Distance Separable matrix (cryptography). After the
/// non-linear S-box, this linear map mixes all width lanes so a change in
/// one coordinate affects every coordinate of the next state. In R1CS we
/// implement it as width² multiplies by **constants** (`mds[i][j]`): often
/// `dcons=0` (const·var is free as a constraint), but each `*` and `+` still
/// builds temporary `FpVar`s — that is where MCP thrash shows as `mds_drss`.
fn apply_mds(
    cs: ConstraintSystemRef<Fr>,
    state: &mut Vec<FpVar<Fr>>,
    params: &PoseidonParameters<Fr>,
) -> Result<(), SynthesisError> {
    let width = params.width;
    let mut next = Vec::with_capacity(width);
    for i in 0..width {
        let mut accumulator = FpVar::<Fr>::new_constant(cs.clone(), Fr::from(0u64))?;
        for (j, state_j) in state.iter().enumerate().take(width) {
            let mds_entry = FpVar::<Fr>::new_constant(cs.clone(), params.mds[i][j])?;
            accumulator += state_j * mds_entry;
        }
        next.push(accumulator);
    }
    *state = next;
    Ok(())
}

/// Same as [`apply_mds`] with per-(row,col) RSS — commitment dig only.
fn apply_mds_traced(
    cs: ConstraintSystemRef<Fr>,
    state: &mut Vec<FpVar<Fr>>,
    params: &PoseidonParameters<Fr>,
    tag: &str,
    round: usize,
) -> Result<(), SynthesisError> {
    let width = params.width;
    let mut next = Vec::with_capacity(width);
    let mds_t0 = Instant::now();
    let mds_enter = pos_snap(&cs);
    pos_log(&format!(
        "mds: ENTER tag={tag} round={round} width={width} cons={} wit={} rss_kb={}",
        mds_enter.0, mds_enter.1, mds_enter.2
    ));

    for i in 0..width {
        let row_t0 = Instant::now();
        let row_before = pos_snap(&cs);
        let mut accumulator = FpVar::<Fr>::new_constant(cs.clone(), Fr::from(0u64))?;
        let after_zero = pos_snap(&cs);
        pos_log(&format!(
            "mds: tag={tag} round={round} row={i} after_zero_const \
             dcons={} drss={} rss={}",
            after_zero.0.saturating_sub(row_before.0),
            after_zero.2.saturating_sub(row_before.2) as i64,
            after_zero.2,
        ));

        for (j, state_j) in state.iter().enumerate().take(width) {
            let cell_before = pos_snap(&cs);
            let mds_entry = FpVar::<Fr>::new_constant(cs.clone(), params.mds[i][j])?;
            let after_const = pos_snap(&cs);
            // const·var product + add into accumulator
            let prod = state_j * mds_entry;
            let after_mul = pos_snap(&cs);
            accumulator += prod;
            let after_add = pos_snap(&cs);
            pos_log(&format!(
                "mds: tag={tag} round={round} row={i} col={j} \
                 new_const dcons={} drss={} \
                 mul dcons={} drss={} \
                 add dcons={} drss={} rss={}",
                after_const.0.saturating_sub(cell_before.0),
                after_const.2.saturating_sub(cell_before.2) as i64,
                after_mul.0.saturating_sub(after_const.0),
                after_mul.2.saturating_sub(after_const.2) as i64,
                after_add.0.saturating_sub(after_mul.0),
                after_add.2.saturating_sub(after_mul.2) as i64,
                after_add.2,
            ));
        }
        next.push(accumulator);
        let row_after = pos_snap(&cs);
        pos_log(&format!(
            "mds: tag={tag} round={round} row={i} DONE ms={} dcons={} drss={} rss={}",
            row_t0.elapsed().as_millis(),
            row_after.0.saturating_sub(row_before.0),
            row_after.2.saturating_sub(row_before.2) as i64,
            row_after.2,
        ));
    }
    *state = next;
    let mds_leave = pos_snap(&cs);
    pos_log(&format!(
        "mds: LEAVE tag={tag} round={round} ms={} dcons={} drss={} rss={}",
        mds_t0.elapsed().as_millis(),
        mds_leave.0.saturating_sub(mds_enter.0),
        mds_leave.2.saturating_sub(mds_enter.2) as i64,
        mds_leave.2,
    ));
    Ok(())
}
