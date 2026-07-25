//! Reader registry — look up who can be paid, publish that you can (ADR-019).
//!
//! Lookup takes a wallet address and returns the reader address that wallet has
//! published, so a sender needs nothing but the recipient's ordinary wallet
//! address. It requires no keypair and no signature: the registry is a public
//! account and reading the chain is unauthenticated by construction.
//!
//! Publishing is the other direction and needs the wallet, so this module only
//! builds the unsigned instruction recipes — the browser assembles them, Phantom
//! signs, and the reader's secret never appears anywhere near this code.

use anchor_client::Instruction;
use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use anyhow::{Context, Result, anyhow};
use solana_rpc_client::rpc_client::RpcClient;

use tidex6_core::envelope::ReaderAddress;
use tidex6_registry::{MAX_CHUNK_LEN, READER_ADDRESS_LEN, ReaderEntry};

use crate::deposit::{IxRecipe, ix_to_recipe};

/// What the registry knows about one wallet.
///
/// Deliberately not `Debug`: the whole struct is public data, but dumping a
/// 1216-byte key into a log line is noise that also makes it easy to paste the
/// wrong thing somewhere. Print `wallet` and `version` if you need a trace.
#[derive(Clone)]
pub struct RegisteredReader {
    /// The wallet that published this entry.
    pub wallet: Pubkey,
    /// Identity version from the signed phrase (ADR-018). A sender can compare
    /// it against what they saw earlier and notice that the recipient rotated.
    pub version: u8,
    /// The published address: what a sender seals an envelope to.
    pub address: ReaderAddress,
}

/// Derive the registry entry address for a wallet.
///
/// Deterministic and offline — no network call, no account needs to exist.
pub fn entry_pda(wallet: &Pubkey) -> Pubkey {
    let (pda, _) = Pubkey::find_program_address(
        &[ReaderEntry::SEED_PREFIX, wallet.as_ref()],
        &tidex6_registry::ID,
    );
    pda
}

/// Look up a wallet's published reader address.
///
/// `Ok(None)` means the wallet has not registered, or registered and never
/// finished writing — either way it cannot be paid yet, and that is a normal
/// answer rather than an error. An unfinished entry is deliberately treated as
/// absent: a partially written key would seal envelopes nobody can open.
pub fn lookup(rpc: &RpcClient, wallet: &Pubkey) -> Result<Option<RegisteredReader>> {
    let pda = entry_pda(wallet);

    let account = match rpc.get_account(&pda) {
        Ok(account) => account,
        // A missing account surfaces as an RPC error rather than an empty
        // result, so "not registered" arrives here and is not a failure.
        Err(_) => return Ok(None),
    };

    if account.data.is_empty() {
        return Ok(None);
    }

    let entry = ReaderEntry::try_deserialize(&mut account.data.as_slice())
        .context("registry entry does not deserialise — wrong program version?")?;

    if !entry.is_finalized {
        return Ok(None);
    }

    if entry.owner != *wallet {
        // The PDA is derived from the wallet, so this cannot happen against an
        // honest program. If it ever does, something is deeply wrong and
        // sealing an envelope to that key would be reckless.
        return Err(anyhow!(
            "registry entry at {pda} claims owner {} but was derived from {wallet}",
            entry.owner
        ));
    }

    let address = ReaderAddress::from_bytes(&entry.data)
        .map_err(|e| anyhow!("published reader address is malformed: {e}"))?;

    Ok(Some(RegisteredReader {
        wallet: *wallet,
        version: entry.version,
        address,
    }))
}

/// Look up several wallets at once — a sender usually needs the recipient and
/// one or more auditors together.
///
/// Returns them in the order asked, so the caller can tell which lookup came
/// back empty and name the wallet that still has to register.
pub fn lookup_many(
    rpc: &RpcClient,
    wallets: &[Pubkey],
) -> Result<Vec<(Pubkey, Option<RegisteredReader>)>> {
    wallets
        .iter()
        .map(|w| lookup(rpc, w).map(|found| (*w, found)))
        .collect()
}

/// An unsigned registration plan: transactions to be signed by the registering
/// wallet, in order.
///
/// Order matters — the account must exist before anything is written into it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisterPlan {
    pub transactions: Vec<Vec<IxRecipe>>,
}

/// Build the instructions that publish `address` for `wallet`.
///
/// The wallet pays the rent (~0.0097 SOL, refundable when the entry is closed)
/// and signs. Nothing secret is involved: `address` is the public half of the
/// identity, and this function never sees the other half.
///
/// `version` is the identity version from the signed phrase, stored so senders
/// can notice a rotation.
pub fn build_register_plan(
    wallet: Pubkey,
    address: &ReaderAddress,
    version: u8,
) -> Result<RegisterPlan> {
    let bytes = address.to_bytes();
    if bytes.len() != READER_ADDRESS_LEN {
        return Err(anyhow!(
            "reader address is {} bytes, registry expects exactly {READER_ADDRESS_LEN}",
            bytes.len()
        ));
    }

    let entry = entry_pda(&wallet);

    let init = Instruction {
        program_id: tidex6_registry::ID,
        accounts: tidex6_registry::accounts::InitReader {
            wallet,
            entry,
            system_program: anchor_client::anchor_lang::system_program::ID,
        }
        .to_account_metas(None),
        data: tidex6_registry::instruction::InitReader { version }.data(),
    };

    // One transaction per chunk: the account allocation and the first write
    // could share a transaction, but keeping them separate means a failed write
    // can be retried on its own without re-running the allocation.
    let mut transactions = vec![vec![ix_to_recipe(&init)]];

    for (index, chunk) in bytes.chunks(MAX_CHUNK_LEN).enumerate() {
        let offset = (index * MAX_CHUNK_LEN) as u32;
        let write = Instruction {
            program_id: tidex6_registry::ID,
            accounts: tidex6_registry::accounts::WriteReaderChunk { wallet, entry }
                .to_account_metas(None),
            data: tidex6_registry::instruction::WriteReaderChunk {
                offset,
                chunk: chunk.to_vec(),
            }
            .data(),
        };
        transactions.push(vec![ix_to_recipe(&write)]);
    }

    Ok(RegisterPlan { transactions })
}

/// Build the instruction that closes a wallet's entry and refunds its rent.
///
/// After this the wallet is unfindable and cannot be paid until it registers
/// again. Together with [`build_register_plan`] this is how a rotated identity
/// replaces an old one.
pub fn build_close_plan(wallet: Pubkey) -> RegisterPlan {
    let close = Instruction {
        program_id: tidex6_registry::ID,
        accounts: tidex6_registry::accounts::CloseReader {
            wallet,
            entry: entry_pda(&wallet),
        }
        .to_account_metas(None),
        data: tidex6_registry::instruction::CloseReader {}.data(),
    };
    RegisterPlan {
        transactions: vec![vec![ix_to_recipe(&close)]],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_pda_is_deterministic_and_wallet_specific() {
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();

        assert_eq!(entry_pda(&a), entry_pda(&a));
        assert_ne!(entry_pda(&a), entry_pda(&b));
    }

    #[test]
    fn register_plan_covers_the_whole_address_in_order() {
        let wallet = Pubkey::new_unique();
        let (pk, sk) = tidex6_core::pqc::keygen();
        let address = ReaderAddress::from_secret(pk, &sk);

        let plan = build_register_plan(wallet, &address, 2).expect("plan");

        // One allocation plus the chunks needed for 1216 bytes at 900 per call.
        let expected_chunks = READER_ADDRESS_LEN.div_ceil(MAX_CHUNK_LEN);
        assert_eq!(plan.transactions.len(), 1 + expected_chunks);

        // Every transaction targets the registry and carries exactly one
        // instruction — a failed write must be retryable alone.
        for tx in &plan.transactions {
            assert_eq!(tx.len(), 1);
            assert_eq!(tx[0].program_id, tidex6_registry::ID.to_string());
        }
    }

    #[test]
    fn close_plan_is_a_single_instruction() {
        let plan = build_close_plan(Pubkey::new_unique());
        assert_eq!(plan.transactions.len(), 1);
        assert_eq!(plan.transactions[0].len(), 1);
    }
}
