//! Phase-2 MPC trusted-setup contribution + verification (BGM17 / «MMORPG»),
//! arkworks 0.5. Rust-native замена snarkjs `zkey contribute` / `zkey verify` —
//! чтобы весь стек был на Rust/WASM (правило проекта: Node/JS вон).
//!
//! Протокол повторяет схему snarkjs phase-2 (сверено с исходником):
//! вклад со скаляром `s` умножает `delta` (G1/G2) на `s`, а L/H-секции на
//! `s⁻¹`, и публикует PoK (`g1_s`, `g1_sx=s·g1_s`, `g2_spx=s·g2_sp`), где
//! `g2_sp = hashToG2(transcript)` — точка с НЕизвестным dlog (try-and-increment),
//! а transcript привязан к цепочке (Fiat-Shamir). Verify проверяет для каждого
//! вклада: `e(g1_s,g2_spx)==e(g1_sx,g2_sp)` (согласованность s) и
//! `e(curDelta,g2_spx)==e(deltaAfter,g2_sp)` (delta умножена на s), затем
//! финальную согласованность delta G1/G2 и корректный скейл L/H (случайная
//! линейная комбинация + pairing против исходных параметров).
//!
//! TRUST-CRITICAL: этот модуль обязан пройти PR_CHECKLIST_PROOF_LOGIC
//! (Fiat-Shamir дисциплина, два ревьюера) перед продакшеном.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// Публичные данные одного вклада (PoK + получившаяся delta в G1).
/// `g2_sp` не хранится — пересчитывается из transcript при verify.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Contribution {
    pub g1_s: G1Affine,
    pub g1_sx: G1Affine,
    pub g2_spx: G2Affine,
    pub delta_after: G1Affine,
    pub name: String,
}

/// Полное состояние церемонии — то, что качает браузер и хранит сервер.
/// `initial` держит его с `contributions = []` (база delta), `current` — после
/// всех вкладов. Сериализуется целиком через arkworks (компактнее zkey).
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CeremonyState {
    pub cs_hash: [u8; 64],
    pub pk: ProvingKey<Bn254>,
    pub contributions: Vec<Contribution>,
}

impl CeremonyState {
    /// Стартовое состояние из setup-параметров (contributions пусты).
    pub fn genesis(pk: ProvingKey<Bn254>) -> Self {
        let cs_hash = cs_hash(&pk);
        Self { cs_hash, pk, contributions: Vec::new() }
    }

    /// Uncompressed — чтобы браузер не платил за decompress ~24k точек
    /// (безопасность даёт `verify_chain` на сервере, не десериализация).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_uncompressed(&mut buf).expect("serialize CeremonyState");
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ark_serialize::SerializationError> {
        Self::deserialize_uncompressed_unchecked(bytes)
    }
}

/// Результат проверки цепочки вкладов.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Ok,
    BadPok(usize),
    BadDeltaChain(usize),
    FinalDeltaMismatch,
    DeltaG1G2Inconsistent,
    LQueryBadScale,
    HQueryBadScale,
    UnchangedSectionTampered(&'static str),
    /// `new` не является продолжением `current` ровно на один вклад
    /// (переписана история / нет прогресса).
    NotAnExtension,
}

// ──────────────────────────────────────────────────────────────────────────
// Contribute
// ──────────────────────────────────────────────────────────────────────────

/// Внести вклад: скейлит `delta` и L/H в `pk` на месте, возвращает публичную
/// запись вклада. `cs_hash` — стабильный (delta-независимый) хеш схемы;
/// `prior` — все предыдущие вклады (для transcript). `rng` — OS-энтропия.
pub fn contribute<R: RngCore + CryptoRng>(
    pk: &mut ProvingKey<Bn254>,
    prior: &[Contribution],
    cs_hash: &[u8; 64],
    name: impl Into<String>,
    rng: &mut R,
) -> Contribution {
    let s = Fr::rand(rng);
    let s_inv = s.inverse().expect("s != 0 with overwhelming probability");

    let g1_s = G1Projective::rand(rng).into_affine();
    let g1_sx = mul_g1(g1_s, s);

    let transcript = transcript_for(cs_hash, prior, &g1_s, &g1_sx);
    let g2_sp = hash_to_g2(&transcript);
    let g2_spx = mul_g2(g2_sp, s);

    // delta *= s (G1 и G2); L,H *= s⁻¹.
    pk.delta_g1 = mul_g1(pk.delta_g1, s);
    pk.vk.delta_g2 = mul_g2(pk.vk.delta_g2, s);
    for p in pk.l_query.iter_mut() {
        *p = mul_g1(*p, s_inv);
    }
    for p in pk.h_query.iter_mut() {
        *p = mul_g1(*p, s_inv);
    }

    Contribution {
        g1_s,
        g1_sx,
        g2_spx,
        delta_after: pk.delta_g1,
        name: name.into(),
    }
}

/// High-level: внести вклад в `state` (мутирует pk + добавляет запись).
/// Используется WASM-биндингом и тестами.
pub fn contribute_state<R: RngCore + CryptoRng>(
    state: &mut CeremonyState,
    name: impl Into<String>,
    rng: &mut R,
) -> Contribution {
    let c = contribute(&mut state.pk, &state.contributions, &state.cs_hash, name, rng);
    state.contributions.push(c.clone());
    c
}

// ──────────────────────────────────────────────────────────────────────────
// Verify
// ──────────────────────────────────────────────────────────────────────────

/// Серверная проверка: `new` — валидное продолжение `current` РОВНО на один
/// вклад (история не переписана, цепочка от `initial` верна).
pub fn verify_extension(
    initial: &CeremonyState,
    current: &CeremonyState,
    new: &CeremonyState,
) -> VerifyOutcome {
    if new.cs_hash != initial.cs_hash {
        return VerifyOutcome::UnchangedSectionTampered("cs_hash");
    }
    if new.contributions.len() != current.contributions.len() + 1 {
        return VerifyOutcome::NotAnExtension;
    }
    // Префикс должен совпадать — нельзя выкинуть чужие вклады.
    if new.contributions[..current.contributions.len()] != current.contributions[..] {
        return VerifyOutcome::NotAnExtension;
    }
    verify_chain(&initial.pk, &new.pk, &new.contributions, &new.cs_hash)
}

/// Проверить всю цепочку вкладов: `initial` — исходные параметры (setup,
/// delta-база), `current` — параметры после всех вкладов, `contributions` — в
/// порядке применения.
pub fn verify_chain(
    initial: &ProvingKey<Bn254>,
    current: &ProvingKey<Bn254>,
    contributions: &[Contribution],
    cs_hash: &[u8; 64],
) -> VerifyOutcome {
    // Неизменяемые секции (setup их не трогает) должны совпадать с initial.
    if current.vk.alpha_g1 != initial.vk.alpha_g1
        || current.vk.beta_g2 != initial.vk.beta_g2
        || current.vk.gamma_g2 != initial.vk.gamma_g2
    {
        return VerifyOutcome::UnchangedSectionTampered("vk alpha/beta/gamma");
    }
    if current.vk.gamma_abc_g1 != initial.vk.gamma_abc_g1 {
        return VerifyOutcome::UnchangedSectionTampered("IC");
    }
    if current.a_query != initial.a_query
        || current.b_g1_query != initial.b_g1_query
        || current.b_g2_query != initial.b_g2_query
    {
        return VerifyOutcome::UnchangedSectionTampered("A/B queries");
    }
    // beta_g1 delta-независим (используется прувером для C) — тоже неизменен.
    if current.beta_g1 != initial.beta_g1 {
        return VerifyOutcome::UnchangedSectionTampered("beta_g1");
    }

    // Цепочка delta: начинаем с initial delta (G1).
    let mut cur_delta = initial.delta_g1;
    for (i, c) in contributions.iter().enumerate() {
        let transcript = transcript_for(cs_hash, &contributions[..i], &c.g1_s, &c.g1_sx);
        let g2_sp = hash_to_g2(&transcript);

        // PoK: e(g1_s, g2_spx) == e(g1_sx, g2_sp).
        if !same_ratio(c.g1_s, c.g1_sx, g2_sp, c.g2_spx) {
            return VerifyOutcome::BadPok(i);
        }
        // Delta умножена на тот же s: e(curDelta, g2_spx) == e(deltaAfter, g2_sp).
        if !same_ratio(cur_delta, c.delta_after, g2_sp, c.g2_spx) {
            return VerifyOutcome::BadDeltaChain(i);
        }
        cur_delta = c.delta_after;
    }

    // Финальная delta_g1 совпадает с накопленной.
    if current.delta_g1 != cur_delta {
        return VerifyOutcome::FinalDeltaMismatch;
    }
    // delta G1/G2 согласованы: e(G1g, delta_g2) == e(delta_g1, G2g).
    if !same_ratio(
        G1Affine::generator(),
        current.delta_g1,
        G2Affine::generator(),
        current.vk.delta_g2,
    ) {
        return VerifyOutcome::DeltaG1G2Inconsistent;
    }

    // L,H корректно поделены на delta-ratio (случайная линейная комбинация).
    if !check_query_scale(&initial.l_query, &current.l_query, initial, current) {
        return VerifyOutcome::LQueryBadScale;
    }
    if !check_query_scale(&initial.h_query, &current.h_query, initial, current) {
        return VerifyOutcome::HQueryBadScale;
    }

    VerifyOutcome::Ok
}

/// L/H после вкладов = (delta_init / delta_cur) · L/H_init. Проверяем свёрткой
/// со случайными (Fiat-Shamir) коэффициентами одним pairing'ом:
/// `e(Σrᵢ·cur[i], delta_cur_g2) == e(Σrᵢ·init[i], delta_init_g2)`.
fn check_query_scale(
    init_q: &[G1Affine],
    cur_q: &[G1Affine],
    initial: &ProvingKey<Bn254>,
    current: &ProvingKey<Bn254>,
) -> bool {
    if init_q.len() != cur_q.len() {
        return false;
    }
    if init_q.is_empty() {
        return true;
    }
    let coeffs = fiat_shamir_coeffs(cur_q);
    let r_init = G1Projective::msm(init_q, &coeffs).expect("msm").into_affine();
    let r_cur = G1Projective::msm(cur_q, &coeffs).expect("msm").into_affine();
    // e(r_cur, delta_cur_g2) == e(r_init, delta_init_g2)
    Bn254::pairing(r_cur, current.vk.delta_g2) == Bn254::pairing(r_init, initial.vk.delta_g2)
}

// ──────────────────────────────────────────────────────────────────────────
// Хелперы
// ──────────────────────────────────────────────────────────────────────────

/// Стабильный (delta-независимый) хеш схемы — привязывает transcript к
/// конкретному circuit. Берём delta-неизменяемые части pk.
pub fn cs_hash(pk: &ProvingKey<Bn254>) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"tidex6-cs-hash-v1");
    update_hasher(&mut h, &pk.vk.alpha_g1);
    update_hasher(&mut h, &pk.vk.beta_g2);
    update_hasher(&mut h, &pk.vk.gamma_g2);
    for ic in &pk.vk.gamma_abc_g1 {
        update_hasher(&mut h, ic);
    }
    for a in &pk.a_query {
        update_hasher(&mut h, a);
    }
    for b in &pk.b_g2_query {
        update_hasher(&mut h, b);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    out
}

/// transcript вклада: cs_hash ‖ (все предыдущие pubkey) ‖ g1_s ‖ g1_sx.
fn transcript_for(
    cs_hash: &[u8; 64],
    prior: &[Contribution],
    g1_s: &G1Affine,
    g1_sx: &G1Affine,
) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(cs_hash);
    for c in prior {
        update_hasher(&mut h, &c.g1_s);
        update_hasher(&mut h, &c.g1_sx);
        update_hasher(&mut h, &c.g2_spx);
        update_hasher(&mut h, &c.delta_after);
    }
    update_hasher(&mut h, g1_s);
    update_hasher(&mut h, g1_sx);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    out
}

/// Fiat-Shamir коэффициенты для свёртки L/H — из хеша самих (уже
/// зафиксированных) точек, чтобы вкладчик не мог подогнать под известные `r`.
fn fiat_shamir_coeffs(points: &[G1Affine]) -> Vec<Fr> {
    let mut seed = Sha512::new();
    seed.update(b"tidex6-query-fs-v1");
    for p in points {
        update_hasher(&mut seed, p);
    }
    let base = seed.finalize();
    (0..points.len())
        .map(|i| {
            let mut h = Sha512::new();
            h.update(base);
            h.update((i as u64).to_le_bytes());
            Fr::from_le_bytes_mod_order(&h.finalize())
        })
        .collect()
}

/// `hashToG2` — детерминированная точка G2 с НЕизвестным dlog из transcript
/// (try-and-increment: x из хеша, y=√(x³+b), очистка кофактора).
fn hash_to_g2(transcript: &[u8]) -> G2Affine {
    let b = ark_bn254::g2::Config::COEFF_B;
    let mut counter: u64 = 0;
    loop {
        let mut h = Sha512::new();
        h.update(b"tidex6-h2g2-v1");
        h.update(transcript);
        h.update(counter.to_le_bytes());
        let d = h.finalize();
        let c0 = Fq::from_le_bytes_mod_order(&d[0..32]);
        let c1 = Fq::from_le_bytes_mod_order(&d[32..64]);
        let x = Fq2::new(c0, c1);
        let rhs = x * x * x + b;
        if let Some(y) = rhs.sqrt() {
            let p = G2Affine::new_unchecked(x, y);
            let q = p.clear_cofactor();
            if !q.is_zero() {
                return q;
            }
        }
        counter += 1;
    }
}

/// sameRatio: `e(a1, b2) == e(a2, b1)`.
fn same_ratio(a1: G1Affine, a2: G1Affine, b1: G2Affine, b2: G2Affine) -> bool {
    Bn254::pairing(a1, b2) == Bn254::pairing(a2, b1)
}

fn mul_g1(p: G1Affine, s: Fr) -> G1Affine {
    p.mul_bigint(s.into_bigint()).into_affine()
}
fn mul_g2(p: G2Affine, s: Fr) -> G2Affine {
    p.mul_bigint(s.into_bigint()).into_affine()
}

fn update_hasher<T: CanonicalSerialize>(h: &mut Sha512, point: &T) {
    let mut buf = Vec::new();
    point.serialize_uncompressed(&mut buf).expect("serialize");
    h.update(&buf);
}
