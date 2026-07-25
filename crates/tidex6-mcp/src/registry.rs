//! Resolving a wallet address into a published reader address (ADR-019).
//!
//! This is what lets an agent work from an ordinary wallet address: the sender
//! names `9pQr…`, and the lock to seal the envelope with is read off the chain.
//! Nothing is copied between people.
//!
//! Deliberately plain JSON-RPC over the HTTP client we already have rather than
//! the full Solana SDK. All that is needed is one `getAccountInfo` and a fixed
//! byte layout — pulling in anchor-client to parse 1216 bytes at a known offset
//! would add a large dependency tree to a process whose whole job is to be a
//! thin, auditable layer.

use base64::Engine;
use rmcp::ErrorData as McpError;
use solana_pubkey::Pubkey;

/// Registry program id (ADR-019).
pub const REGISTRY_PROGRAM_ID: &str = "D1dCoBuiRehhT24XTF8Dmhm9cFERpmfANLB1bb3aGxLJ";

/// PDA seed prefix, matching `ReaderEntry::SEED_PREFIX` in the program.
const SEED_PREFIX: &[u8] = b"reader";

/// Reader address length: ML-KEM-768 public key + X25519 view-tag key.
const READER_ADDRESS_LEN: usize = 1184 + 32;

/// Byte offsets inside `ReaderEntry`, in Anchor's borsh layout:
/// discriminator(8) ‖ owner(32) ‖ version(1) ‖ written_len(4) ‖ bump(1)
/// ‖ is_finalized(1) ‖ vec_len(4) ‖ data.
const OFF_OWNER: usize = 8;
const OFF_VERSION: usize = 40;
const OFF_WRITTEN_LEN: usize = 41;
const OFF_IS_FINALIZED: usize = 46;
const OFF_DATA: usize = 51;

/// What a wallet has published, if anything.
pub struct Resolved {
    pub version: u8,
    /// `mlkem_pk ‖ x25519_pk`, hex — what the signing page seals to.
    pub address_hex: String,
}

/// Why a wallet cannot be paid.
///
/// Separated from transport errors on purpose: "not registered" is a normal
/// answer that the agent should relay to the user with instructions, while a
/// broken RPC is a fault to report as such.
pub enum Lookup {
    Found(Resolved),
    NotRegistered,
    /// Registered but the key was never finished. Treated as unpayable rather
    /// than as an error: sealing to a half-written key produces a payment
    /// nobody can ever open.
    Incomplete,
}

/// Derive the registry entry address for a wallet.
pub fn entry_pda(wallet: &Pubkey) -> Result<Pubkey, McpError> {
    let program = REGISTRY_PROGRAM_ID
        .parse::<Pubkey>()
        .map_err(|e| McpError::internal_error(format!("registry program id: {e}"), None))?;
    let (pda, _) = Pubkey::find_program_address(&[SEED_PREFIX, wallet.as_ref()], &program);
    Ok(pda)
}

/// Read what `wallet` has published.
pub async fn lookup(
    http: &reqwest::Client,
    rpc_url: &str,
    wallet: &Pubkey,
) -> Result<Lookup, McpError> {
    let pda = entry_pda(wallet)?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [pda.to_string(), { "encoding": "base64" }],
    });

    let response =
        http.post(rpc_url).json(&body).send().await.map_err(|e| {
            McpError::internal_error(format!("cannot reach the Solana RPC: {e}"), None)
        })?;

    let payload: serde_json::Value = response
        .json()
        .await
        .map_err(|e| McpError::internal_error(format!("RPC returned no JSON: {e}"), None))?;

    if let Some(error) = payload.get("error") {
        return Err(McpError::internal_error(
            format!("RPC error while reading the registry: {error}"),
            None,
        ));
    }

    let value = payload.pointer("/result/value");
    let Some(value) = value else {
        return Err(McpError::internal_error(
            "RPC response has no result.value".to_string(),
            None,
        ));
    };
    if value.is_null() {
        return Ok(Lookup::NotRegistered);
    }

    let encoded = value
        .pointer("/data/0")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            McpError::internal_error("registry account has no base64 data".to_string(), None)
        })?;

    let data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| McpError::internal_error(format!("registry data is not base64: {e}"), None))?;

    parse_entry(&data, wallet)
}

/// Parse a `ReaderEntry` at the known offsets.
fn parse_entry(data: &[u8], wallet: &Pubkey) -> Result<Lookup, McpError> {
    if data.len() < OFF_DATA + READER_ADDRESS_LEN {
        return Err(McpError::internal_error(
            format!(
                "registry entry is {} bytes, expected at least {}",
                data.len(),
                OFF_DATA + READER_ADDRESS_LEN
            ),
            None,
        ));
    }

    // The PDA is derived from the wallet, so a mismatch means the account is
    // not what it claims to be. Sealing an envelope to a key found there would
    // be reckless, so this is an error rather than "not registered".
    let owner = &data[OFF_OWNER..OFF_OWNER + 32];
    if owner != wallet.as_ref() {
        return Err(McpError::internal_error(
            "registry entry does not belong to the wallet it was derived from".to_string(),
            None,
        ));
    }

    let is_finalized = data[OFF_IS_FINALIZED] != 0;
    let written_len = u32::from_le_bytes([
        data[OFF_WRITTEN_LEN],
        data[OFF_WRITTEN_LEN + 1],
        data[OFF_WRITTEN_LEN + 2],
        data[OFF_WRITTEN_LEN + 3],
    ]) as usize;

    if !is_finalized || written_len != READER_ADDRESS_LEN {
        return Ok(Lookup::Incomplete);
    }

    Ok(Lookup::Found(Resolved {
        version: data[OFF_VERSION],
        address_hex: hex_encode(&data[OFF_DATA..OFF_DATA + READER_ADDRESS_LEN]),
    }))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_bytes(owner: &Pubkey, version: u8, written: u32, finalized: bool) -> Vec<u8> {
        let mut data = vec![0u8; OFF_DATA + READER_ADDRESS_LEN];
        data[OFF_OWNER..OFF_OWNER + 32].copy_from_slice(owner.as_ref());
        data[OFF_VERSION] = version;
        data[OFF_WRITTEN_LEN..OFF_WRITTEN_LEN + 4].copy_from_slice(&written.to_le_bytes());
        data[OFF_IS_FINALIZED] = u8::from(finalized);
        for (i, slot) in data[OFF_DATA..].iter_mut().enumerate() {
            *slot = (i % 251) as u8;
        }
        data
    }

    #[test]
    fn parses_a_finished_entry() {
        let wallet = Pubkey::new_unique();
        let data = entry_bytes(&wallet, 2, READER_ADDRESS_LEN as u32, true);

        match parse_entry(&data, &wallet).expect("parse") {
            Lookup::Found(r) => {
                assert_eq!(r.version, 2);
                assert_eq!(r.address_hex.len(), READER_ADDRESS_LEN * 2);
            }
            _ => panic!("expected a finished entry"),
        }
    }

    #[test]
    fn half_written_entry_is_unpayable_not_an_error() {
        let wallet = Pubkey::new_unique();
        let data = entry_bytes(&wallet, 2, 900, false);
        assert!(matches!(
            parse_entry(&data, &wallet).expect("parse"),
            Lookup::Incomplete
        ));
    }

    #[test]
    fn finalized_flag_without_full_length_is_still_unpayable() {
        // Defensive: a future program bug could set the flag early. Trusting it
        // alone would mean sealing to a key padded with zeroes.
        let wallet = Pubkey::new_unique();
        let data = entry_bytes(&wallet, 2, 900, true);
        assert!(matches!(
            parse_entry(&data, &wallet).expect("parse"),
            Lookup::Incomplete
        ));
    }

    #[test]
    fn foreign_owner_is_refused() {
        let wallet = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let data = entry_bytes(&other, 2, READER_ADDRESS_LEN as u32, true);
        assert!(parse_entry(&data, &wallet).is_err());
    }

    #[test]
    fn truncated_account_is_refused() {
        let wallet = Pubkey::new_unique();
        assert!(parse_entry(&[0u8; 40], &wallet).is_err());
    }

    #[test]
    fn pda_is_wallet_specific() {
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        assert_eq!(entry_pda(&a).unwrap(), entry_pda(&a).unwrap());
        assert_ne!(entry_pda(&a).unwrap(), entry_pda(&b).unwrap());
    }
}
