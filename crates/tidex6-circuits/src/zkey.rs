//! Rust-native парсер snarkjs `.zkey` → arkworks `ProvingKey<Bn254>` (Путь A,
//! церемония). Читает финальный/промежуточный zkey из snarkjs без Node — чтобы
//! верификация вклада и извлечение VK жили целиком в Rust-стеке.
//!
//! Байт-layout повторяет проверенную логику ark-circom (crates.io), но целится
//! в наш arkworks 0.5 и добавляет robust-проверку точек (on-curve + subgroup),
//! возвращая ошибку вместо паники на кривом вкладе.
//!
//! Секции zkey (Groth16): 2=header+vk, 3=IC, 5=A, 6=B1, 7=B2, 8=C(l_query),
//! 9=H. Координаты Fq — в Montgomery-форме LE, поэтому `Fq::new_unchecked`
//! (интерпретирует биты как montgomery-репрезентацию, без домножения на R).

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{BigInt, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkeyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("deserialize: {0}")]
    Deserialize(#[from] ark_serialize::SerializationError),
    #[error("bad magic: {0:?}")]
    BadMagic([u8; 4]),
    #[error("missing section {0}")]
    MissingSection(u32),
    #[error("point not on curve / wrong subgroup in section {0}")]
    BadPoint(u32),
}

type Result<T> = std::result::Result<T, ZkeyError>;

struct Section {
    position: u64,
    #[allow(dead_code)]
    size: u64,
}

/// Прочитать snarkjs zkey в arkworks `ProvingKey<Bn254>`.
pub fn read_zkey_pk<R: Read + Seek>(reader: &mut R) -> Result<ProvingKey<Bn254>> {
    let sections = read_section_table(reader)?;
    let get = |id: u32| sections.get(&id).and_then(|v| v.first()).ok_or(ZkeyError::MissingSection(id));

    // ── Section 2: header + vk-точки ───────────────────────────────────
    reader.seek(SeekFrom::Start(get(2)?.position))?;
    let _n8q = read_u32(reader)?;
    skip(reader, 32)?; // q (Fq modulus)
    let _n8r = read_u32(reader)?;
    skip(reader, 32)?; // r (Fr modulus)
    let n_vars = read_u32(reader)? as usize;
    let n_public = read_u32(reader)? as usize;
    let domain_size = read_u32(reader)? as usize;

    let alpha_g1 = read_g1(reader, 2)?;
    let beta_g1 = read_g1(reader, 2)?;
    let beta_g2 = read_g2(reader, 2)?;
    let gamma_g2 = read_g2(reader, 2)?;
    let delta_g1 = read_g1(reader, 2)?;
    let delta_g2 = read_g2(reader, 2)?;

    // ── Section 3: IC (gamma_abc_g1) ───────────────────────────────────
    reader.seek(SeekFrom::Start(get(3)?.position))?;
    let ic = read_g1_vec(reader, n_public + 1, 3)?;

    // ── Query-секции ───────────────────────────────────────────────────
    reader.seek(SeekFrom::Start(get(5)?.position))?;
    let a_query = read_g1_vec(reader, n_vars, 5)?;
    reader.seek(SeekFrom::Start(get(6)?.position))?;
    let b_g1_query = read_g1_vec(reader, n_vars, 6)?;
    reader.seek(SeekFrom::Start(get(7)?.position))?;
    let b_g2_query = read_g2_vec(reader, n_vars, 7)?;
    reader.seek(SeekFrom::Start(get(8)?.position))?;
    let l_query = read_g1_vec(reader, n_vars - n_public - 1, 8)?;
    reader.seek(SeekFrom::Start(get(9)?.position))?;
    let h_query = read_g1_vec(reader, domain_size, 9)?;

    let vk = VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: ic,
    };

    Ok(ProvingKey::<Bn254> {
        vk,
        beta_g1,
        delta_g1,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    })
}

/// Достать только VerifyingKey (для on-chain верификатора) — дешевле, читает
/// лишь секции 2 и 3.
pub fn read_zkey_vk<R: Read + Seek>(reader: &mut R) -> Result<VerifyingKey<Bn254>> {
    let sections = read_section_table(reader)?;
    let get = |id: u32| sections.get(&id).and_then(|v| v.first()).ok_or(ZkeyError::MissingSection(id));

    reader.seek(SeekFrom::Start(get(2)?.position))?;
    let _n8q = read_u32(reader)?;
    skip(reader, 32)?;
    let _n8r = read_u32(reader)?;
    skip(reader, 32)?;
    let _n_vars = read_u32(reader)?;
    let n_public = read_u32(reader)? as usize;
    let _domain_size = read_u32(reader)?;

    let alpha_g1 = read_g1(reader, 2)?;
    let _beta_g1 = read_g1(reader, 2)?;
    let beta_g2 = read_g2(reader, 2)?;
    let gamma_g2 = read_g2(reader, 2)?;
    let _delta_g1 = read_g1(reader, 2)?;
    let delta_g2 = read_g2(reader, 2)?;

    reader.seek(SeekFrom::Start(get(3)?.position))?;
    let ic = read_g1_vec(reader, n_public + 1, 3)?;

    Ok(VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: ic,
    })
}

// ── Section table ──────────────────────────────────────────────────────

fn read_section_table<R: Read + Seek>(reader: &mut R) -> Result<HashMap<u32, Vec<Section>>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != b"zkey" {
        return Err(ZkeyError::BadMagic(magic));
    }
    let _version = read_u32(reader)?;
    let num_sections = read_u32(reader)?;

    let mut sections: HashMap<u32, Vec<Section>> = HashMap::new();
    for _ in 0..num_sections {
        let id = read_u32(reader)?;
        let size = read_u64(reader)?;
        let position = reader.stream_position()?;
        sections.entry(id).or_default().push(Section { position, size });
        reader.seek(SeekFrom::Current(size as i64))?;
    }
    Ok(sections)
}

// ── Точки: Fq в Montgomery LE через new_unchecked ──────────────────────

fn read_fq<R: Read>(reader: &mut R) -> Result<Fq> {
    let bi = BigInt::<4>::deserialize_uncompressed(reader)?;
    Ok(Fq::new_unchecked(bi))
}

fn read_g1<R: Read>(reader: &mut R, section: u32) -> Result<G1Affine> {
    let x = read_fq(reader)?;
    let y = read_fq(reader)?;
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZkeyError::BadPoint(section));
    }
    Ok(p)
}

fn read_g2<R: Read>(reader: &mut R, section: u32) -> Result<G2Affine> {
    let x = Fq2::new(read_fq(reader)?, read_fq(reader)?);
    let y = Fq2::new(read_fq(reader)?, read_fq(reader)?);
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::identity());
    }
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZkeyError::BadPoint(section));
    }
    Ok(p)
}

fn read_g1_vec<R: Read>(reader: &mut R, n: usize, section: u32) -> Result<Vec<G1Affine>> {
    (0..n).map(|_| read_g1(reader, section)).collect()
}

fn read_g2_vec<R: Read>(reader: &mut R, n: usize, section: u32) -> Result<Vec<G2Affine>> {
    (0..n).map(|_| read_g2(reader, section)).collect()
}

// ── LE-примитивы ───────────────────────────────────────────────────────

fn read_u32<R: Read>(reader: &mut R) -> Result<u32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn skip<R: Read>(reader: &mut R, n: usize) -> Result<()> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(())
}
