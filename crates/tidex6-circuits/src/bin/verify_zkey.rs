//! Дефинитивная проверка Rust-native церемонии (Путь A, без Node):
//! читаем церемониальный snarkjs zkey нашим парсером → arkworks pk, прувим
//! (CircomReduction) + verify через `tidex6_circuits::ceremony::selftest_zkey`.
//! Если OK — сервер может верифицировать вклады целиком в Rust-стеке.
//!
//! Запуск: cargo run -p tidex6-circuits --bin verify_zkey -- <path-to.zkey>
//!         (по умолчанию _ceremony/withdraw_0002.zkey)

use std::fs::File;
use std::io::BufReader;

use tidex6_circuits::ceremony::selftest_zkey;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        format!("{}/work/rust/tidex6/_ceremony/withdraw_0002.zkey", std::env::var("HOME").unwrap())
    });
    println!("reading {path}");

    let mut reader = BufReader::new(File::open(&path).expect("open zkey"));
    match selftest_zkey(&mut reader, 0xC0FFEE) {
        Ok(vk) => {
            println!("selftest OK: IC={}", vk.gamma_abc_g1.len());
            println!("\nRUST-NATIVE ЦЕРЕМОНИЯ РАБОТАЕТ — Node на сервере НЕ нужен");
        }
        Err(e) => {
            eprintln!("selftest FAIL: {e}");
            std::process::exit(1);
        }
    }
}
