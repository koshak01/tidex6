//! Print three example notes — one per denomination — to demonstrate
//! the v3 wire format.

use tidex6_core::note::{Denomination, DepositNote};

fn main() {
    println!("=== Three example v3 notes ===\n");
    for denom in [Denomination::OneTenthSol, Denomination::OneSol, Denomination::TenSol] {
        let note = DepositNote::random(denom).unwrap();
        let text = note.to_text();
        println!("{}  ({} chars)", denom, text.len());
        println!("  {}", text);
        println!();
    }
}
