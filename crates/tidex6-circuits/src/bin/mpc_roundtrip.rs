//! Round-trip проверка Rust-native phase-2 MPC (Путь A, замена snarkjs):
//! читаем initial zkey → pk, делаем два вклада нашим `mpc::contribute`,
//! проверяем цепочку `mpc::verify_chain`, прогоняем selftest итогового pk
//! (prove+verify), и убеждаемся, что подделка отвергается.
//!
//! Запуск: cargo run -p tidex6-circuits --bin mpc_roundtrip

use std::fs::File;
use std::io::BufReader;

use ark_ec::AffineRepr;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use tidex6_circuits::ceremony::selftest_pk;
use tidex6_circuits::mpc::{contribute, cs_hash, verify_chain, VerifyOutcome};
use tidex6_circuits::zkey::read_zkey_pk;

fn main() {
    let path = format!(
        "{}/work/rust/tidex6/_ceremony/withdraw_0000.zkey",
        std::env::var("HOME").unwrap()
    );
    let mut reader = BufReader::new(File::open(&path).expect("open initial zkey"));
    let initial = read_zkey_pk(&mut reader).expect("read initial pk");
    let cs = cs_hash(&initial);
    println!("initial pk loaded, cs_hash computed");

    // Два вклада (OS-энтропия в проде; здесь фикс-сид — это лишь тест).
    let mut rng = StdRng::seed_from_u64(0xA11CE);
    let mut current = initial.clone();

    let c1 = contribute(&mut current, &[], &cs, "Alice", &mut rng);
    println!("contribution #1 (Alice) applied");
    let c2 = contribute(&mut current, std::slice::from_ref(&c1), &cs, "Bob", &mut rng);
    println!("contribution #2 (Bob) applied");

    let contributions = vec![c1.clone(), c2.clone()];

    // 1. Цепочка проверяется.
    let outcome = verify_chain(&initial, &current, &contributions, &cs);
    println!("verify_chain: {outcome:?}");
    assert_eq!(outcome, VerifyOutcome::Ok, "valid chain must verify");

    // 2. Итоговый pk всё ещё задаёт рабочий setup (prove+verify).
    match selftest_pk(&current, 0xC0FFEE) {
        Ok(vk) => println!("selftest итогового pk: OK (IC={})", vk.gamma_abc_g1.len()),
        Err(e) => {
            eprintln!("selftest FAIL: {e}");
            std::process::exit(1);
        }
    }

    // 3. Подделка delta → отвергается.
    let mut tampered = current.clone();
    tampered.delta_g1 = (tampered.delta_g1.into_group() + initial.delta_g1.into_group()).into();
    let bad = verify_chain(&initial, &tampered, &contributions, &cs);
    println!("verify_chain (подделка delta): {bad:?}");
    assert_ne!(bad, VerifyOutcome::Ok, "tampered delta must be rejected");

    // 4. Подделка вклада (подменить g2_spx) → отвергается.
    let mut bad_contribs = contributions.clone();
    bad_contribs[0].g2_spx = c2.g2_spx;
    let bad2 = verify_chain(&initial, &current, &bad_contribs, &cs);
    println!("verify_chain (подделка PoK): {bad2:?}");
    assert_ne!(bad2, VerifyOutcome::Ok, "tampered PoK must be rejected");

    println!("\nRUST-NATIVE MPC РАБОТАЕТ — contribute + verify без snarkjs");
}
