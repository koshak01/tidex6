//! BN254 scalar-field arithmetic on four 64-bit limbs, in Montgomery form.
//!
//! Written by hand instead of going through `ruint`'s generic `mul_mod`: on
//! Stylus every byte of WASM counts against a 24 KB limit, and the generic
//! path (512-bit product, then long division) weighed more than the whole
//! rest of the pool. Montgomery multiplication (CIOS, Koç et al.) needs no
//! division at all — only 64×64→128 multiplies, which WASM has natively.
//!
//! Values in Montgomery form are `x·R mod p` with `R = 2^256`. The Poseidon
//! constants are stored already in that form (see `poseidon_consts.rs`), so a
//! hash converts its two inputs in, runs the permutation, and converts one
//! output back. Correctness is pinned by the same two vectors the Solidity
//! library is tested against: `hash(0, 1)` and the empty depth-20 root.

use alloy_primitives::{uint, U256};

/// Field element as little-endian 64-bit limbs.
pub type Limbs = [u64; 4];

/// Scalar field modulus `r`, as a `U256` for callers that compare inputs.
pub const R: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

/// Base field modulus `q`. Coordinates of G1 points live here; negating a
/// point means `y -> q - y`.
pub const Q: U256 =
    uint!(21888242871839275222246405745257275088696311157297823662689037894645226208583_U256);

/// Scalar field modulus, little-endian limbs.
pub const P: Limbs = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// `-p^{-1} mod 2^64` — the Montgomery reduction constant.
const INV: u64 = 0xc2e1f593efffffff;

/// `R^2 mod p`: multiplying by it (in Montgomery form) converts a plain value in.
const R2: Limbs = [
    0x1bb8e645ae216da7,
    0x53fe3ab1e35c59e3,
    0x8c49833d53bb8085,
    0x0216d0b17f4e44a5,
];

/// Plain `1`: multiplying by it (in Montgomery form) converts a value out.
const ONE: Limbs = [1, 0, 0, 0];

/// Zero is zero in both representations.
pub const ZERO: Limbs = [0, 0, 0, 0];

/// Is `value` a scalar-field element?
#[inline]
pub fn is_field_element(value: U256) -> bool {
    value < R
}

/// `a + b·c + carry` → (low word, carry).
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a + b + carry` → (low word, carry).
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a >= p`?
#[inline]
fn ge_p(a: &Limbs) -> bool {
    for i in (0..4).rev() {
        if a[i] != P[i] {
            return a[i] > P[i];
        }
    }
    true
}

/// `a - p`, assuming `a >= p` (or a pending carry above the top limb).
#[inline]
fn sub_p(a: &Limbs) -> Limbs {
    let mut out = ZERO;
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(P[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = (b1 | b2) as u64;
    }
    out
}

/// Montgomery product `a·b·R^{-1} mod p` (CIOS). Inputs below `p`.
pub fn mont_mul(a: &Limbs, b: &Limbs) -> Limbs {
    let mut t = [0u64; 6];
    for bi in b {
        let mut carry = 0u64;
        for j in 0..4 {
            let (lo, c) = mac(t[j], a[j], *bi, carry);
            t[j] = lo;
            carry = c;
        }
        let (lo, c) = adc(t[4], carry, 0);
        t[4] = lo;
        t[5] = c;

        let m = t[0].wrapping_mul(INV);
        let (_, mut carry) = mac(t[0], m, P[0], 0);
        for j in 1..4 {
            let (lo, c) = mac(t[j], m, P[j], carry);
            t[j - 1] = lo;
            carry = c;
        }
        let (lo, c) = adc(t[4], carry, 0);
        t[3] = lo;
        t[4] = t[5] + c;
    }
    let r = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 || ge_p(&r) { sub_p(&r) } else { r }
}

/// `a + b mod p`. Inputs below `p`, so the sum never carries out of 256 bits.
pub fn add_mod(a: &Limbs, b: &Limbs) -> Limbs {
    let mut out = ZERO;
    let mut carry = 0u64;
    for i in 0..4 {
        let (lo, c) = adc(a[i], b[i], carry);
        out[i] = lo;
        carry = c;
    }
    if carry != 0 || ge_p(&out) { sub_p(&out) } else { out }
}

/// Plain value → Montgomery form.
#[inline]
pub fn to_mont(a: &Limbs) -> Limbs {
    mont_mul(a, &R2)
}

/// Montgomery form → plain value.
#[inline]
pub fn from_mont(a: &Limbs) -> Limbs {
    mont_mul(a, &ONE)
}

/// `U256` → limbs, or `None` when the value is not a field element.
#[inline]
pub fn limbs_from_u256(value: U256) -> Option<Limbs> {
    if value >= R {
        return None;
    }
    Some(*value.as_limbs())
}

/// Limbs → `U256`.
#[inline]
pub fn u256_from_limbs(limbs: Limbs) -> U256 {
    U256::from_limbs(limbs)
}
