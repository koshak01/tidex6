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

use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use light_poseidon::{PoseidonError as LightPoseidonError, PoseidonParameters};

/// Maximum number of inputs supported, matching
/// `light-poseidon`'s circom-compatible parameter set (widths 2..=13).
pub const MAX_INPUTS: usize = 12;

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
    poseidon_hash_n_var(cs, &[left.clone(), right.clone()])
}

/// General circom Poseidon hash over `inputs.len()` field elements.
/// The number of inputs must be in `1..=MAX_INPUTS`.
pub fn poseidon_hash_n_var(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    assert!(
        (1..=MAX_INPUTS).contains(&inputs.len()),
        "unsupported input count: {}",
        inputs.len()
    );

    let params =
        parameters_for(inputs.len()).map_err(|_| SynthesisError::AssignmentMissing)?;

    let width = params.width;
    let full_rounds = params.full_rounds;
    let partial_rounds = params.partial_rounds;
    let half_full = full_rounds / 2;
    let total_rounds = full_rounds + partial_rounds;

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
        apply_ark(cs.clone(), &mut state, &params, round)?;

        let is_full_round = round < half_full || round >= half_full + partial_rounds;
        if is_full_round {
            apply_sbox_full(&mut state)?;
        } else {
            apply_sbox_partial(&mut state)?;
        }

        apply_mds(cs.clone(), &mut state, &params)?;
    }

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

/// Apply the x^5 S-box only to state[0] (used during partial
/// rounds). This is what gives the partial round its name: most of
/// the state passes through untouched, which drops the constraint
/// count compared to a full round.
fn apply_sbox_partial(state: &mut [FpVar<Fr>]) -> Result<(), SynthesisError> {
    state[0] = pow_five(&state[0])?;
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

/// Mix the state with the MDS matrix: new_state[i] =
/// sum_j state[j] * mds[i][j]. This is the linear diffusion step
/// of the Poseidon permutation.
fn apply_mds(
    cs: ConstraintSystemRef<Fr>,
    state: &mut Vec<FpVar<Fr>>,
    params: &PoseidonParameters<Fr>,
) -> Result<(), SynthesisError> {
    let width = params.width;
    let mut next = Vec::with_capacity(width);
    for i in 0..width {
        let mut accumulator = FpVar::<Fr>::new_constant(cs.clone(), Fr::from(0u64))?;
        for j in 0..width {
            let mds_entry = FpVar::<Fr>::new_constant(cs.clone(), params.mds[i][j])?;
            accumulator += &state[j] * mds_entry;
        }
        next.push(accumulator);
    }
    *state = next;
    Ok(())
}
