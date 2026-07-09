#!/usr/bin/env bash
# Воспроизводимая сборка WASM-прувера tidex6 → детерминированный .wasm.
#
# Любой может собрать этим скриптом из открытого исходника и сверить sha256
# с опубликованным (docs/REPRODUCIBLE.md) и с тем, что грузится в браузере на
# https://tidex6.com/verify. Совпало → в браузере крутится открытый аудируемый
# код, а не тайный бэкдор.
#
# Детерминизм обеспечивают:
#   - rust-toolchain.toml (пин rustc 1.95.0 + wasm32 target);
#   - --remap-path-prefix (убирает абсолютные пути $HOME/cwd из бинаря, иначе
#     хеш зависел бы от того, где лежит репо у сборщика);
#   - SOURCE_DATE_EPOCH=0 (нулевые таймстемпы);
#   - Cargo.lock (пин версий зависимостей);
#   - wasm-pack применяет wasm-opt детерминированно при той же версии.
set -euo pipefail
cd "$(dirname "$0")"   # crates/tidex6-prover-wasm

export RUSTFLAGS="--remap-path-prefix=${HOME}=/h --remap-path-prefix=${PWD}=/build"
export SOURCE_DATE_EPOCH=0

wasm-pack build --release --target web --out-dir pkg

echo ""
echo "=== reproducible artifacts (sha256) ==="
shasum -a 256 pkg/tidex6_prover_wasm_bg.wasm pkg/tidex6_prover_wasm.js
echo ""
echo "Сверь эти хеши с docs/REPRODUCIBLE.md и с https://tidex6.com/verify"
