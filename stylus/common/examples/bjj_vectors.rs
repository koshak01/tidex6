//! Print Baby Jubjub results for fixed inputs, to compare with the Rust
//! arkworks side and the Solidity library:
//!
//! ```text
//! cargo run --example bjj_vectors -p tidex6-stylus-common
//! ```

use alloy_primitives::{uint, U256};
use tidex6_stylus_common::babyjubjub::{add, identity, mul_g, sub};

const H: (U256, U256) = (
    uint!(16465905457043935148917040939103774432138530608084226140289605407230083015565_U256),
    uint!(11338370919383712937350239847103076912175434237534229070573696180793149629513_U256),
);

fn main() {
    let g = mul_g(1);
    println!("1*G      = ({}, {})", g.0, g.1);
    let m = mul_g(250_000);
    println!("250000*G = ({}, {})", m.0, m.1);
    let s = add(m, H).expect("add");
    println!("mG + H   = ({}, {})", s.0, s.1);
    let back = sub(s, H).expect("sub");
    println!("(mG+H)-H == mG: {}", back == m);
    let zero = sub(m, m).expect("sub");
    println!("mG - mG == identity: {}", zero == identity());
    let doubled = add(g, g).expect("add");
    println!("G + G == 2*G: {}", doubled == mul_g(2));
}
