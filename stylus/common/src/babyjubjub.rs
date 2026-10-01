//! Baby Jubjub point arithmetic for confidential balances (ADR-023).
//!
//! The same curve and the same formulas as `contracts/src/BabyJubjub.sol`:
//! the form `x² + y² = 1 + d·x²y²` (`a = 1`) that `ark-ed-on-bn254` and the
//! circuits use, coordinates in the BN254 scalar field. A balance is a pair of
//! points, and every operation on it is an addition: crediting adds,
//! spending subtracts, `wrap`/`unwrap` add or subtract `m·G` for a public `m`.
//!
//! Extended coordinates `(X, Y, T, Z)` with the unified "add-2008-hwcd"
//! formulas for `a = 1`, all values in Montgomery form, one inverse per call.
//! Points that arrive as Groth16 public inputs are on the curve and in the
//! prime-order subgroup because the circuits constrain them; this module is
//! arithmetic, not validation.

use alloy_primitives::{uint, U256};

use crate::field::{
    add_mod, from_mont, limbs_from_u256, mont_inv, mont_mul, sub_mod, to_mont, u256_from_limbs,
    Limbs, ZERO,
};

/// Affine point `(x, y)`, plain coordinates. The neutral element is `(0, 1)`.
pub type Point = (U256, U256);

/// `d = 168696 / 168700 mod p` — the arkworks form of the curve.
const D: U256 =
    uint!(9706598848417545097372247223557719406784115219466060233080913168975159366771_U256);

/// Generator `G` of the prime-order subgroup, the one the circuits commit with.
const GX: U256 =
    uint!(19698561148652590122159747500897617769866003486955115824547446575314762165298_U256);
const GY: U256 =
    uint!(19298250018296453272277890825869354524455968081175474282777126169995084727839_U256);

/// Extended point, Montgomery form.
#[derive(Clone, Copy)]
struct Ext {
    x: Limbs,
    y: Limbs,
    t: Limbs,
    z: Limbs,
}

/// The neutral element `(0, 1)`.
pub fn identity() -> Point {
    (U256::ZERO, U256::from(1u8))
}

/// `p1 + p2`, or `None` when a coordinate is not a field element.
pub fn add(p1: Point, p2: Point) -> Option<Point> {
    Some(normalize(&add_ext(&to_ext(p1)?, &to_ext(p2)?)))
}

/// `p1 - p2`, or `None` when a coordinate is not a field element.
pub fn sub(p1: Point, p2: Point) -> Option<Point> {
    Some(normalize(&add_ext(&to_ext(p1)?, &to_ext(neg(p2)?)?)))
}

/// `-(x, y) = (-x, y)`.
pub fn neg(p: Point) -> Option<Point> {
    let x = limbs_from_u256(p.0)?;
    limbs_from_u256(p.1)?;
    Some((u256_from_limbs(sub_mod(&ZERO, &x)), p.1))
}

/// `m·G` for an amount. Sixty-four doublings and at most sixty-four additions
/// in extended coordinates, one inverse at the end. The scalar is `u64` on
/// purpose: it is an amount, never a secret key.
pub fn mul_g(m: u64) -> Point {
    let generator = to_ext((GX, GY)).expect("generator coordinates are field elements");
    let mut acc = to_ext(identity()).expect("identity coordinates are field elements");
    let mut base = generator;
    let mut rest = m;
    while rest != 0 {
        if rest & 1 == 1 {
            acc = add_ext(&acc, &base);
        }
        base = add_ext(&base, &base);
        rest >>= 1;
    }
    normalize(&acc)
}

/// Affine → extended: `T = x·y`, `Z = 1`, everything into Montgomery form.
fn to_ext(p: Point) -> Option<Ext> {
    let x = to_mont(&limbs_from_u256(p.0)?);
    let y = to_mont(&limbs_from_u256(p.1)?);
    Some(Ext {
        x,
        y,
        t: mont_mul(&x, &y),
        z: to_mont(&[1, 0, 0, 0]),
    })
}

/// Unified extended addition for `a = 1`, the same expression as
/// `BabyJubjub.addExt` in Solidity.
fn add_ext(q1: &Ext, q2: &Ext) -> Ext {
    let d = to_mont(&limbs_from_u256(D).expect("d is a field element"));
    let a = mont_mul(&q1.x, &q2.x);
    let b = mont_mul(&q1.y, &q2.y);
    let e = sub_mod(
        &sub_mod(
            &mont_mul(&add_mod(&q1.x, &q1.y), &add_mod(&q2.x, &q2.y)),
            &a,
        ),
        &b,
    );
    let h = sub_mod(&b, &a);
    let c = mont_mul(&d, &mont_mul(&q1.t, &q2.t));
    let dd = mont_mul(&q1.z, &q2.z);
    let f = sub_mod(&dd, &c);
    let g = add_mod(&dd, &c);
    Ext {
        x: mont_mul(&e, &f),
        y: mont_mul(&g, &h),
        t: mont_mul(&e, &h),
        z: mont_mul(&f, &g),
    }
}

/// Extended → affine plain coordinates: one inverse of `Z`.
fn normalize(q: &Ext) -> Point {
    let z_inv = mont_inv(&q.z);
    (
        u256_from_limbs(from_mont(&mont_mul(&q.x, &z_inv))),
        u256_from_limbs(from_mont(&mont_mul(&q.y, &z_inv))),
    )
}
