#![allow(unexpected_cfgs)]
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-confidential-amounts — песочница confidential transfers с
//! реальным SOL.
//!
//! **НЕ часть tidex6 MVP.** Отдельная программа с отдельным
//! program ID `6r8JfoXYtNKw36ZiFjWLdSJHGMpgTQUwDnqyWskKbqdP`.
//! Цель — увидеть на живом mainnet как работает перевод с
//! **скрытой суммой** через Pedersen commitments, прежде чем
//! принимать решение интегрировать это в основной верификатор.
//!
//! # Модель
//!
//! - **Vault PDA** `[b"conf-vault"]` — общий пул SOL всех депозитов.
//!   Owned нашей программой → можем свободно двигать лампорты.
//! - **ConfidentialAccount PDA** `[b"conf-account", owner]` — хранит
//!   только 64-байтный commitment. Сумма **не хранится**.
//! - **Deposit**: перевод SOL → vault, обновление commitment.
//!   amount открыт (SOL public).
//! - **Transfer**: только commitment math на двух аккаунтах; vault
//!   не трогается. Amount ПРЯЧЕТСЯ.
//! - **Withdraw**: SOL из vault → owner + commitment update.
//!   amount снова открыт (SOL идёт публичному получателю).
//!
//! # Что скрывается, что нет
//!
//! | Операция  | Amount виден снаружи? |
//! | ---       | ---                   |
//! | Deposit   | ДА — входящий SOL     |
//! | Transfer  | **НЕТ**               |
//! | Withdraw  | ДА — исходящий SOL    |
//!
//! Суть скрытия именно в шаге transfer: сколько между аккаунтами
//! перетекло — наблюдатель не видит.
//!
//! # Безопасность
//!
//! TOY. Программа **верит клиенту**:
//! - нет range proof — можно «передать отрицательный amount»;
//! - нет binding между заявленным amount при withdraw и фактическим
//!   balance commitment'а — withdraw'нуть можно сколько угодно
//!   пока в vault что-то есть.
//!
//! Песочница для своих двух кошельков, не публичная. В реальный
//! tidex6 эту схему можно затащить только добавив обе проверки
//! через Groth16/Bulletproofs.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_lang::solana_program::system_instruction;
use solana_bn254::prelude::*;

declare_id!("6r8JfoXYtNKw36ZiFjWLdSJHGMpgTQUwDnqyWskKbqdP");

/// Uncompressed G1 BN254 — 32 байта X || 32 байта Y, big-endian.
/// Формат `sol_alt_bn128_addition` syscall, без конверсий.
pub const G1_UNCOMPRESSED_LEN: usize = 64;

#[program]
pub mod tidex6_confidential_amounts {
    use super::*;

    /// Создать общий vault — один на программу.
    pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
        ctx.accounts.vault.bump = ctx.bumps.vault;
        msg!("conf-vault-init:{}", ctx.accounts.vault.key());
        Ok(())
    }

    /// Создать confidential-аккаунт для текущего signer'а.
    /// `initial_commitment` — `Com(0, r)` вычисленный клиентом.
    /// Программа просто сохраняет; корректность на совести клиента.
    pub fn init_account(
        ctx: Context<InitAccount>,
        initial_commitment: [u8; G1_UNCOMPRESSED_LEN],
    ) -> Result<()> {
        let account = &mut ctx.accounts.account;
        account.owner = ctx.accounts.owner.key();
        account.commitment = initial_commitment;
        account.bump = ctx.bumps.account;

        msg!(
            "conf-init-account:{}:{}",
            account.owner,
            hex_short(&initial_commitment)
        );
        Ok(())
    }

    /// Deposit `amount_lamports` SOL в vault. Одновременно
    /// гомоморфно обновляет commitment аккаунта: прибавляет
    /// `delta_commitment` (клиент считает `Com(amount, r)` со
    /// свежим blinding).
    ///
    /// `amount_lamports` **публичен** — deposit и так раскрывает
    /// amount: lamports летят на vault через system transfer.
    /// Настоящее скрытие в `transfer`.
    pub fn deposit(
        ctx: Context<Deposit>,
        amount_lamports: u64,
        delta_commitment: [u8; G1_UNCOMPRESSED_LEN],
    ) -> Result<()> {
        require!(
            ctx.accounts.account.owner == ctx.accounts.owner.key(),
            ConfidentialError::NotAccountOwner
        );
        require!(amount_lamports > 0, ConfidentialError::ZeroAmount);
        require!(
            !delta_commitment.iter().all(|&b| b == 0),
            ConfidentialError::InvalidG1Point
        );

        invoke(
            &system_instruction::transfer(
                &ctx.accounts.owner.key(),
                &ctx.accounts.vault.key(),
                amount_lamports,
            ),
            &[
                ctx.accounts.owner.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        let account = &mut ctx.accounts.account;
        account.commitment = g1_add(&account.commitment, &delta_commitment)?;

        msg!(
            "conf-deposit:{}:{}:{}",
            ctx.accounts.owner.key(),
            amount_lamports,
            hex_short(&account.commitment)
        );
        Ok(())
    }

    /// Приватный перевод. Клиент вычисляет `transfer_commitment =
    /// Com(amount, r_transfer)`. Программа вычитает его из
    /// sender-commitment и прибавляет к receiver-commitment.
    /// **SOL не двигается** — поэтому наблюдатель не видит amount.
    pub fn transfer(
        ctx: Context<Transfer>,
        transfer_commitment: [u8; G1_UNCOMPRESSED_LEN],
    ) -> Result<()> {
        require!(
            ctx.accounts.from.owner == ctx.accounts.sender.key(),
            ConfidentialError::NotAccountOwner
        );
        require!(
            !transfer_commitment.iter().all(|&b| b == 0),
            ConfidentialError::InvalidG1Point
        );

        let negated = g1_negate(&transfer_commitment)?;

        let from = &mut ctx.accounts.from;
        from.commitment = g1_add(&from.commitment, &negated)?;

        let to = &mut ctx.accounts.to;
        to.commitment = g1_add(&to.commitment, &transfer_commitment)?;

        msg!(
            "conf-transfer:{}:{}:{}:{}",
            ctx.accounts.sender.key(),
            ctx.accounts.to_owner.key(),
            hex_short(&from.commitment),
            hex_short(&to.commitment),
        );
        Ok(())
    }

    /// Withdraw `amount_lamports` из vault на `owner`. Одновременно
    /// обновляет commitment через `new_commitment` (клиент считает
    /// `Com(balance - amount, new_blinding)`).
    ///
    /// **Trust-based**: программа не проверяет соответствие
    /// `new_commitment` остатку. В продакшене здесь ZK proof знания
    /// amount + blinding обязателен.
    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount_lamports: u64,
        new_commitment: [u8; G1_UNCOMPRESSED_LEN],
    ) -> Result<()> {
        require!(
            ctx.accounts.account.owner == ctx.accounts.owner.key(),
            ConfidentialError::NotAccountOwner
        );
        require!(amount_lamports > 0, ConfidentialError::ZeroAmount);

        let vault_info = ctx.accounts.vault.to_account_info();
        require!(
            vault_info.lamports() >= amount_lamports,
            ConfidentialError::VaultInsufficient
        );

        // Vault owned нашей программой → можем дёргать лампорты
        // напрямую без system_program::transfer.
        **vault_info.try_borrow_mut_lamports()? -= amount_lamports;
        **ctx.accounts.owner.to_account_info().try_borrow_mut_lamports()? += amount_lamports;

        let account = &mut ctx.accounts.account;
        account.commitment = new_commitment;

        msg!(
            "conf-withdraw:{}:{}:{}",
            account.owner,
            amount_lamports,
            hex_short(&account.commitment)
        );
        Ok(())
    }

    /// Закрыть confidential-account — вернуть rent владельцу.
    pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
        require!(
            ctx.accounts.account.owner == ctx.accounts.owner.key(),
            ConfidentialError::NotAccountOwner
        );
        msg!("conf-close-account:{}", ctx.accounts.owner.key());
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────

#[account]
pub struct ConfidentialVault {
    pub bump: u8,
}

impl ConfidentialVault {
    pub const LEN: usize = 8 + 1;
}

#[account]
pub struct ConfidentialAccount {
    pub owner: Pubkey,
    pub commitment: [u8; G1_UNCOMPRESSED_LEN],
    pub bump: u8,
}

impl ConfidentialAccount {
    pub const LEN: usize = 8 + 32 + G1_UNCOMPRESSED_LEN + 1;
}

// ─────────────────────────────────────────────────────────────
// Instruction contexts
// ─────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(
        init,
        payer = payer,
        space = ConfidentialVault::LEN,
        seeds = [b"conf-vault"],
        bump
    )]
    pub vault: Account<'info, ConfidentialVault>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitAccount<'info> {
    #[account(
        init,
        payer = owner,
        space = ConfidentialAccount::LEN,
        seeds = [b"conf-account", owner.key().as_ref()],
        bump
    )]
    pub account: Account<'info, ConfidentialAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"conf-account", owner.key().as_ref()],
        bump = account.bump
    )]
    pub account: Account<'info, ConfidentialAccount>,

    #[account(
        mut,
        seeds = [b"conf-vault"],
        bump = vault.bump
    )]
    pub vault: Account<'info, ConfidentialVault>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(
        mut,
        seeds = [b"conf-account", sender.key().as_ref()],
        bump = from.bump
    )]
    pub from: Account<'info, ConfidentialAccount>,

    #[account(
        mut,
        seeds = [b"conf-account", to_owner.key().as_ref()],
        bump = to.bump
    )]
    pub to: Account<'info, ConfidentialAccount>,

    pub sender: Signer<'info>,

    /// CHECK: используется только как seed для `to` PDA; подпись не нужна.
    pub to_owner: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"conf-account", owner.key().as_ref()],
        bump = account.bump
    )]
    pub account: Account<'info, ConfidentialAccount>,

    #[account(
        mut,
        seeds = [b"conf-vault"],
        bump = vault.bump
    )]
    pub vault: Account<'info, ConfidentialVault>,

    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(
        mut,
        close = owner,
        seeds = [b"conf-account", owner.key().as_ref()],
        bump = account.bump
    )]
    pub account: Account<'info, ConfidentialAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,
}

// ─────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────

#[error_code]
pub enum ConfidentialError {
    #[msg("alt_bn128 point addition syscall failed")]
    Bn128AddFailed,
    #[msg("invalid uncompressed G1 point encoding")]
    InvalidG1Point,
    #[msg("signer is not the owner of this confidential account")]
    NotAccountOwner,
    #[msg("amount must be strictly positive")]
    ZeroAmount,
    #[msg("vault does not hold enough lamports for this withdrawal")]
    VaultInsufficient,
}

// ─────────────────────────────────────────────────────────────
// G1 arithmetic helpers
// ─────────────────────────────────────────────────────────────

fn g1_add(
    a: &[u8; G1_UNCOMPRESSED_LEN],
    b: &[u8; G1_UNCOMPRESSED_LEN],
) -> Result<[u8; G1_UNCOMPRESSED_LEN]> {
    let mut input = [0u8; 2 * G1_UNCOMPRESSED_LEN];
    input[..G1_UNCOMPRESSED_LEN].copy_from_slice(a);
    input[G1_UNCOMPRESSED_LEN..].copy_from_slice(b);

    let result = alt_bn128_addition(&input)
        .map_err(|_| error!(ConfidentialError::Bn128AddFailed))?;

    result
        .as_slice()
        .try_into()
        .map_err(|_| error!(ConfidentialError::InvalidG1Point))
}

/// Negate G1 point: `(x, y) → (x, p - y)` где p — BN254 base field.
fn g1_negate(
    point: &[u8; G1_UNCOMPRESSED_LEN],
) -> Result<[u8; G1_UNCOMPRESSED_LEN]> {
    const BN254_BASE_FIELD_MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];

    let mut negated = *point;
    let y = &mut negated[32..];

    if y.iter().all(|&b| b == 0) {
        return Ok(negated);
    }

    let mut borrow: i16 = 0;
    let mut out = [0u8; 32];
    for i in (0..32).rev() {
        let diff = BN254_BASE_FIELD_MODULUS_BE[i] as i16 - y[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    y.copy_from_slice(&out);
    Ok(negated)
}

fn hex_short(bytes: &[u8; G1_UNCOMPRESSED_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
