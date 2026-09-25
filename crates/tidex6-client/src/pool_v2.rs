//! Solana pool v2 (ADR-022): the program holds the tokens and files every
//! leaf from the amount it charged; a note is spent only with its owner's key;
//! a funder takes an uncollected payment back after its window.
//!
//! The same note format as the EVM v2 pools (`crate::evm::v2`): the sender
//! passes the note's core, the envelope carries `rho ‖ aux` in the recipient
//! slot and the amount in token base units, and a payment with a window carries
//! the funder's own copy (slot kind 2) so the refund is rebuilt from the chain.
//!
//! Where the EVM pool puts envelopes into logs, this program keeps one memo
//! account per leaf, PDA `[b"memo", leaf]`. Those accounts are also the pool's
//! leaf list: every client rebuilds the tree from them, in `leaf_index` order.

use anchor_client::Instruction;
use anchor_client::anchor_lang::prelude::{AccountMeta, Pubkey};
use anchor_client::anchor_lang::{
    AccountDeserialize, Discriminator, InstructionData, ToAccountMetas, system_program,
};
use anyhow::{Context, Result, bail};
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::ProvingKey;
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_keypair::Keypair;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};
use solana_transaction::Transaction;
use tidex6_confidential::note_v2;
use tidex6_confidential::withdraw_v2::{self, WithdrawV2Witness};
use tidex6_core::envelope::{self, FunderView, ReaderAddress};
use tidex6_core::types::Secret;
use tidex6_pool_v2::{DepositArgs, MemoAccount, NullifierRecord, OwnerKey, PoolState};

use crate::confidential::LocalIdentity;
use crate::evm::note::{build_tree, fr_to_word};

/// SPL Token program (the pool holds classic SPL tokens).
pub const TOKEN_PROGRAM: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// Associated Token Account program.
pub const ATA_PROGRAM: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// USDC on Solana devnet (Circle's test mint, faucet.circle.com).
pub const DEVNET_USDC: Pubkey =
    Pubkey::from_str_const("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");

/// The USDC mint of the v2 pool on a cluster; `None` — no v2 pool there yet.
pub fn usdc_mint(is_mainnet: bool) -> Option<Pubkey> {
    (!is_mainnet).then_some(DEVNET_USDC)
}

/// Envelope bytes per `append_memo` transaction: under the 1232-byte limit
/// with the signature, three accounts and the Anchor framing.
const MEMO_CHUNK_LEN: usize = 800;

/// The pool v2 program.
pub fn program_id() -> Pubkey {
    tidex6_pool_v2::ID
}

pub fn pool_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[PoolState::POOL_SEED_PREFIX, mint.as_ref()], &program_id()).0
}

pub fn vault_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[PoolState::VAULT_SEED_PREFIX, mint.as_ref()],
        &program_id(),
    )
    .0
}

pub fn memo_pda(leaf: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[MemoAccount::SEED_PREFIX, leaf], &program_id()).0
}

pub fn nullifier_pda(nullifier: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[NullifierRecord::SEED_PREFIX, nullifier], &program_id()).0
}

pub fn owner_key_pda(wallet: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[OwnerKey::SEED_PREFIX, wallet.as_ref()], &program_id()).0
}

/// Associated token account of `owner` for `mint` (SPL Token).
pub fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), TOKEN_PROGRAM.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    )
    .0
}

/// `create_associated_token_account_idempotent`: a no-op when it exists.
fn create_ata_ix(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    Instruction {
        program_id: ATA_PROGRAM,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata(owner, mint), false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM, false),
        ],
        data: vec![1],
    }
}

fn fr(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

fn send(rpc: &RpcClient, signer: &Keypair, ixs: &[Instruction]) -> Result<String> {
    use solana_keypair::Signer;
    let blockhash = rpc.get_latest_blockhash().context("fetch a blockhash")?;
    let tx = Transaction::new_signed_with_payer(ixs, Some(&signer.pubkey()), &[signer], blockhash);
    Ok(rpc
        .send_and_confirm_transaction(&tx)
        .context("transaction not confirmed")?
        .to_string())
}

// ── owner keys ───────────────────────────────────────────────────────────

/// The owner key `wallet` published, or `None`.
pub fn lookup_owner_key(rpc: &RpcClient, wallet: &Pubkey) -> Result<Option<[u8; 32]>> {
    let Ok(account) = rpc.get_account(&owner_key_pda(wallet)) else {
        return Ok(None);
    };
    let entry = OwnerKey::try_deserialize(&mut account.data.as_slice())
        .context("owner-key account does not deserialise")?;
    Ok((entry.owner_pk != [0u8; 32]).then_some(entry.owner_pk))
}

/// The instruction that publishes (or replaces) `wallet`'s owner key.
pub fn publish_owner_key_ix(wallet: Pubkey, owner_pk: [u8; 32]) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: tidex6_pool_v2::accounts::PublishOwnerKey {
            owner_key: owner_key_pda(&wallet),
            wallet,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: tidex6_pool_v2::instruction::PublishOwnerKey { owner_pk }.data(),
    }
}

/// Publish our owner key; `None` — the same key is already there.
pub fn publish_owner_key(
    rpc: &RpcClient,
    signer: &Keypair,
    owner_pk: [u8; 32],
) -> Result<Option<String>> {
    use solana_keypair::Signer;
    let wallet = signer.pubkey();
    if lookup_owner_key(rpc, &wallet)? == Some(owner_pk) {
        return Ok(None);
    }
    send(rpc, signer, &[publish_owner_key_ix(wallet, owner_pk)]).map(Some)
}

// ── the pool ─────────────────────────────────────────────────────────────

/// What a client needs of the pool state.
#[derive(Debug, Clone, Copy)]
pub struct PoolInfo {
    pub treasury_owner_pk: [u8; 32],
    pub fee_floor: u64,
    pub next_leaf_index: u64,
}

impl PoolInfo {
    /// The fee on `amount`: 1% rounded up, at least the floor.
    pub fn fee_for(&self, amount: u64) -> u64 {
        tidex6_confidential::transfer_v2::fee_for(amount, self.fee_floor)
    }
}

pub fn pool_info(rpc: &RpcClient, mint: &Pubkey) -> Result<PoolInfo> {
    let account = rpc
        .get_account(&pool_pda(mint))
        .with_context(|| format!("no v2 pool for mint {mint}"))?;
    let body = account
        .data
        .get(PoolState::DISCRIMINATOR.len()..)
        .context("pool account too short")?;
    let state: &PoolState = bytemuck::try_from_bytes(
        body.get(..std::mem::size_of::<PoolState>())
            .context("pool account too short")?,
    )
    .map_err(|e| anyhow::anyhow!("pool account layout: {e}"))?;
    Ok(PoolInfo {
        treasury_owner_pk: state.treasury_owner_pk,
        fee_floor: state.fee_floor,
        next_leaf_index: state.next_leaf_index,
    })
}

// ── paying ───────────────────────────────────────────────────────────────

/// A payment to seal and send.
pub struct PaymentV2<'a> {
    pub mint: Pubkey,
    /// The recipient's reader address (their envelope) and owner key (who spends).
    pub reader: &'a ReaderAddress,
    pub owner_pk: [u8; 32],
    pub auditors: &'a [ReaderAddress],
    /// Base units the recipient gets; the fee goes on top.
    pub amount: u64,
    pub memo: &'a str,
    /// Seconds until the funder may take it back; 0 — never.
    pub refund_window: u64,
    /// Our own reader address, for the funder copy (needed when the window is on).
    pub funder: Option<&'a ReaderAddress>,
    /// The treasury's reader address: the fee note's envelope.
    pub treasury: &'a ReaderAddress,
}

/// What a payment left on chain.
#[derive(Debug)]
pub struct PaidV2 {
    pub transactions: Vec<String>,
    pub leaf_hex: String,
    pub amount: u64,
    pub fee: u64,
}

fn random_field() -> Result<[u8; 32]> {
    Ok(*Secret::random().context("randomness")?.as_bytes())
}

/// Pay into the pool: one `deposit` (payment + fee note, tokens moved), then
/// the two envelopes written in chunks.
pub fn pay(rpc: &RpcClient, signer: &Keypair, p: &PaymentV2) -> Result<PaidV2> {
    use solana_keypair::Signer;
    if p.amount == 0 {
        bail!("the amount must be greater than zero");
    }
    if p.refund_window > 0 && p.funder.is_none() {
        bail!("a refundable payment needs the sender's own reader address");
    }
    let payer = signer.pubkey();
    let info = pool_info(rpc, &p.mint)?;
    let fee = info.fee_for(p.amount);

    let rho = random_field()?;
    let aux = [0u8; 32];
    let core = note_v2::core(fr(&p.owner_pk), fr(&rho), fr(&aux));
    let mut env = envelope::build(
        p.reader,
        &rho,
        &aux,
        p.amount,
        p.memo.as_bytes(),
        p.auditors,
    )
    .context("seal the envelope")?;
    if let (Some(funder), true) = (p.funder, p.refund_window > 0) {
        let copy = FunderView {
            owner_pk: p.owner_pk,
            rho,
            aux,
            amount: p.amount,
        };
        envelope::add_funder_slot(&mut env, funder, &copy).context("seal the funder copy")?;
    }
    let fee_rho = random_field()?;
    let fee_env = envelope::build(p.treasury, &fee_rho, &aux, fee, b"fee", &[])
        .context("seal the fee envelope")?;

    // The program rebuilds both leaves and refuses a mismatch; `refund_after`
    // is absolute, so it is fixed here from the cluster clock.
    let refund_after = if p.refund_window == 0 {
        0i64
    } else {
        let slot = rpc.get_slot().context("slot")?;
        rpc.get_block_time(slot).context("cluster time")? + p.refund_window as i64
    };
    let refund = if refund_after == 0 {
        Fr::from(0u64)
    } else {
        note_v2::refund_tag(
            note_v2::refund_addr_solana(&payer.to_bytes()),
            refund_after as u64,
        )
    };
    let leaf = fr_to_word(note_v2::leaf(note_v2::body(core, p.amount), refund));
    let fee_core = note_v2::core(fr(&info.treasury_owner_pk), fr(&fee_rho), fr(&aux));
    let fee_leaf = fr_to_word(note_v2::leaf(note_v2::body(fee_core, fee), Fr::from(0u64)));

    let deposit = Instruction {
        program_id: program_id(),
        accounts: tidex6_pool_v2::accounts::Deposit {
            pool: pool_pda(&p.mint),
            mint: p.mint,
            vault: vault_pda(&p.mint),
            depositor_token: ata(&payer, &p.mint),
            memo: memo_pda(&leaf),
            fee_memo: memo_pda(&fee_leaf),
            payer,
            token_program: TOKEN_PROGRAM,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: tidex6_pool_v2::instruction::Deposit {
            args: DepositArgs {
                core: fr_to_word(core),
                amount: p.amount,
                refund_after,
                leaf,
                fee_rho,
                fee_leaf,
                memo_total_len: env.len() as u32,
                fee_memo_total_len: fee_env.len() as u32,
                memo_chunk: Vec::new(),
            },
        }
        .data(),
    };
    let mut transactions = vec![send(rpc, signer, &[deposit])?];
    transactions.extend(write_memo(rpc, signer, &leaf, &env)?);
    transactions.extend(write_memo(rpc, signer, &fee_leaf, &fee_env)?);
    Ok(PaidV2 {
        transactions,
        leaf_hex: hex::encode(leaf),
        amount: p.amount,
        fee,
    })
}

/// The `append_memo` instructions that write `data` into the memo of `leaf`.
pub fn append_memo_ixs(depositor: Pubkey, leaf: &[u8; 32], data: &[u8]) -> Vec<Instruction> {
    data.chunks(MEMO_CHUNK_LEN)
        .enumerate()
        .map(|(i, chunk)| Instruction {
            program_id: program_id(),
            accounts: tidex6_pool_v2::accounts::AppendMemo {
                memo: memo_pda(leaf),
                depositor,
            }
            .to_account_metas(None),
            data: tidex6_pool_v2::instruction::AppendMemo {
                leaf: *leaf,
                offset: (i * MEMO_CHUNK_LEN) as u32,
                chunk: chunk.to_vec(),
            }
            .data(),
        })
        .collect()
}

fn write_memo(
    rpc: &RpcClient,
    signer: &Keypair,
    leaf: &[u8; 32],
    data: &[u8],
) -> Result<Vec<String>> {
    use solana_keypair::Signer;
    append_memo_ixs(signer.pubkey(), leaf, data)
        .iter()
        .map(|ix| send(rpc, signer, std::slice::from_ref(ix)))
        .collect()
}

// ── reading the pool ─────────────────────────────────────────────────────

/// One leaf of the pool, from its memo account.
#[derive(Clone)]
pub struct LeafMemo {
    pub leaf_index: u64,
    pub leaf: [u8; 32],
    pub depositor: Pubkey,
    pub refund_after: i64,
    /// Deposits record their public amount; forwarded notes record 0.
    pub amount: u64,
    /// The envelope once fully written; `None` while chunks are missing.
    pub envelope: Option<Vec<u8>>,
}

/// Every leaf of the pool of `mint`, in leaf order. A gap is an error: a
/// tree rebuilt around it has a root the pool never had.
pub fn leaves(rpc: &RpcClient, mint: &Pubkey) -> Result<Vec<LeafMemo>> {
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::Memcmp(Memcmp::new_base58_encoded(0, MemoAccount::DISCRIMINATOR)),
            // `mint` is the first field after the discriminator.
            RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
                MemoAccount::DISCRIMINATOR.len(),
                mint.as_ref(),
            )),
        ]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            ..RpcAccountInfoConfig::default()
        },
        ..RpcProgramAccountsConfig::default()
    };
    let accounts = rpc
        .get_program_ui_accounts_with_config(&program_id(), config)
        .context("read the pool's memo accounts")?;
    let expected = pool_info(rpc, mint)?.next_leaf_index;
    let mut out: Vec<LeafMemo> = accounts
        .into_iter()
        .filter_map(|(_, account)| {
            let data = account.data.decode()?;
            MemoAccount::try_deserialize(&mut data.as_slice()).ok()
        })
        .map(|m| LeafMemo {
            leaf_index: m.leaf_index,
            leaf: m.leaf,
            depositor: m.depositor,
            refund_after: m.refund_after,
            amount: m.amount,
            envelope: m.is_finalized.then_some(m.data),
        })
        .collect();
    out.sort_by_key(|l| l.leaf_index);
    // Every position of this pool's tree, each exactly once.
    if out.len() as u64 != expected
        || out
            .iter()
            .enumerate()
            .any(|(i, l)| l.leaf_index != i as u64)
    {
        bail!(
            "the pool has {expected} leaves but {} memo accounts in order were found",
            out.len()
        );
    }
    Ok(out)
}

/// One of our notes.
pub struct OpenNoteSol {
    pub leaf_index: u64,
    pub rho: Fr,
    pub aux: Fr,
    pub amount: u64,
    pub memo: String,
    pub refund: Fr,
    pub nullifier: [u8; 32],
}

impl std::fmt::Debug for OpenNoteSol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenNoteSol")
            .field("leaf_index", &self.leaf_index)
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

fn refund_of(l: &LeafMemo) -> Fr {
    if l.refund_after == 0 {
        Fr::from(0u64)
    } else {
        note_v2::refund_tag(
            note_v2::refund_addr_solana(&l.depositor.to_bytes()),
            l.refund_after as u64,
        )
    }
}

/// Our notes: opened with the reader secret and checked against the leaf the
/// program filed under our owner key. Second field — already spent.
pub fn my_notes(
    rpc: &RpcClient,
    leaves: &[LeafMemo],
    identity: &LocalIdentity,
) -> Result<Vec<(OpenNoteSol, bool)>> {
    let owner_pk = &identity
        .owner_pk_v2()
        .context("this identity has no spending key; v2 notes need one")?;
    let reader_secret = identity.reader_secret();
    let mut out = Vec::new();
    for l in leaves {
        let Some(env) = &l.envelope else { continue };
        let Ok(Some(view)) = envelope::open_as_recipient(env, reader_secret) else {
            continue;
        };
        let (rho, aux, refund) = (fr(&view.secret), fr(&view.nullifier), refund_of(l));
        let core = note_v2::core(fr(owner_pk), rho, aux);
        let leaf = note_v2::leaf(note_v2::body(core, view.denomination), refund);
        if fr_to_word(leaf) != l.leaf {
            continue;
        }
        let nullifier = fr_to_word(note_v2::nullifier(rho, l.leaf_index));
        let is_spent = rpc.get_account(&nullifier_pda(&nullifier)).is_ok();
        out.push((
            OpenNoteSol {
                leaf_index: l.leaf_index,
                rho,
                aux,
                amount: view.denomination,
                memo: String::from_utf8_lossy(&view.memo).into_owned(),
                refund,
                nullifier,
            },
            is_spent,
        ));
    }
    Ok(out)
}

/// Withdraw one of our notes to our own wallet, signed and paid by it.
pub fn withdraw(
    rpc: &RpcClient,
    signer: &Keypair,
    mint: &Pubkey,
    proving_key: &ProvingKey<Bn254>,
    leaves: &[LeafMemo],
    note: &OpenNoteSol,
    identity: &LocalIdentity,
) -> Result<String> {
    use solana_keypair::Signer;
    let spending_key = identity
        .spending_key()
        .context("this identity has no spending key; v2 notes need one")?;
    let wallet = signer.pubkey();
    let tree = build_tree(&leaves.iter().map(|l| l.leaf).collect::<Vec<_>>())?;
    let path = tree
        .proof(note.leaf_index)
        .with_context(|| format!("leaf {}: merkle path", note.leaf_index))?;
    let root = tree.root().to_bytes();
    let witness = WithdrawV2Witness {
        sk_spend: fr(spending_key),
        rho: note.rho,
        aux: note.aux,
        amount: note.amount,
        refund: note.refund,
        path_siblings: std::array::from_fn(|i| fr(path.siblings[i].as_bytes())),
        path_indices: std::array::from_fn(|i| (note.leaf_index >> i) & 1 == 1),
        merkle_root: fr(&root),
        recipient: wallet.to_bytes(),
        relayer: wallet.to_bytes(),
        relayer_fee: 0,
    };
    let mut rng = rand::thread_rng();
    let (proof, _) = crate::confidential::prover_runtime::without_tracing(|| {
        withdraw_v2::prove_ceremony(proving_key, &witness, &mut rng)
    })
    .map_err(|e| anyhow::anyhow!("leaf {}: prove: {e}", note.leaf_index))?;
    let bytes = tidex6_circuits::solana_bytes::groth16_to_solana_bytes(&proof, &proving_key.vk)
        .map_err(|e| anyhow::anyhow!("proof bytes: {e:?}"))?;

    let token = ata(&wallet, mint);
    let ix = Instruction {
        program_id: program_id(),
        accounts: tidex6_pool_v2::accounts::Withdraw {
            pool: pool_pda(mint),
            mint: *mint,
            vault: vault_pda(mint),
            nullifier: nullifier_pda(&note.nullifier),
            recipient: wallet,
            recipient_token: token,
            relayer: wallet,
            relayer_token: token,
            payer: wallet,
            token_program: TOKEN_PROGRAM,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: tidex6_pool_v2::instruction::Withdraw {
            proof_a: bytes.proof_a,
            proof_b: bytes.proof_b,
            proof_c: bytes.proof_c,
            merkle_root: root,
            nullifier: note.nullifier,
            amount: note.amount,
            relayer_fee: 0,
        }
        .data(),
    };
    // Groth16 verification needs more compute than the default budget.
    let budget =
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(400_000);
    let budget = Instruction {
        program_id: budget.program_id,
        accounts: Vec::new(),
        data: budget.data,
    };
    send(
        rpc,
        signer,
        &[budget, create_ata_ix(&wallet, &wallet, mint), ix],
    )
}

// ── refunds ──────────────────────────────────────────────────────────────

/// Our own payment that can come back after its window.
pub struct RefundableSol {
    pub leaf_index: u64,
    pub leaf: [u8; 32],
    pub copy: FunderView,
    pub refund_after: i64,
    pub nullifier: [u8; 32],
}

impl std::fmt::Debug for RefundableSol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefundableSol")
            .field("leaf_index", &self.leaf_index)
            .field("amount", &self.copy.amount)
            .field("refund_after", &self.refund_after)
            .finish_non_exhaustive()
    }
}

/// Payments funded by `me` that carry our funder copy; second field — spent.
pub fn my_refunds(
    rpc: &RpcClient,
    leaves: &[LeafMemo],
    identity: &LocalIdentity,
    me: &Pubkey,
) -> Result<Vec<(RefundableSol, bool)>> {
    let reader_secret = identity.reader_secret();
    let mut out = Vec::new();
    for l in leaves {
        if l.refund_after == 0 || l.depositor != *me {
            continue;
        }
        let Some(env) = &l.envelope else { continue };
        let Ok(Some(copy)) = envelope::open_as_funder(env, reader_secret) else {
            continue;
        };
        let core = note_v2::core(fr(&copy.owner_pk), fr(&copy.rho), fr(&copy.aux));
        let leaf = note_v2::leaf(note_v2::body(core, copy.amount), refund_of(l));
        if fr_to_word(leaf) != l.leaf {
            continue;
        }
        let nullifier = fr_to_word(note_v2::nullifier(fr(&copy.rho), l.leaf_index));
        let is_spent = rpc.get_account(&nullifier_pda(&nullifier)).is_ok();
        out.push((
            RefundableSol {
                leaf_index: l.leaf_index,
                leaf: l.leaf,
                copy,
                refund_after: l.refund_after,
                nullifier,
            },
            is_spent,
        ));
    }
    Ok(out)
}

/// Take a payment back after its window. The program recognises the funder
/// by the signer, so it must be the wallet that paid.
pub fn refund(
    rpc: &RpcClient,
    signer: &Keypair,
    mint: &Pubkey,
    r: &RefundableSol,
) -> Result<String> {
    use solana_keypair::Signer;
    let depositor = signer.pubkey();
    let ix = Instruction {
        program_id: program_id(),
        accounts: tidex6_pool_v2::accounts::Refund {
            pool: pool_pda(mint),
            mint: *mint,
            vault: vault_pda(mint),
            depositor_token: ata(&depositor, mint),
            memo: memo_pda(&r.leaf),
            nullifier: nullifier_pda(&r.nullifier),
            depositor,
            token_program: TOKEN_PROGRAM,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: tidex6_pool_v2::instruction::Refund {
            leaf: r.leaf,
            owner_pk: r.copy.owner_pk,
            rho: r.copy.rho,
            aux: r.copy.aux,
            nullifier: r.nullifier,
        }
        .data(),
    };
    send(rpc, signer, &[ix])
}
