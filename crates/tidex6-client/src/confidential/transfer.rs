//! Перевод оператору — единственное место локального режима, где ключ
//! действительно подписывает.
//!
//! Инструкции собираются руками, а не через `spl-token`: нам нужны ровно две —
//! создать счёт получателя, если его нет, и перевести. Тащить ради этого весь
//! крейт со всеми его версиями значит платить за то, чем не пользуешься.

use anchor_client::anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};
use solana_keypair::Keypair;
use solana_rpc_client::rpc_client::RpcClient;

/// SPL Token, классический (не Token-2022): настоящие USDC и USDT живут здесь.
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Associated Token Account.
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// SPL Memo — им перевод привязывается к депозиту.
const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// У USDC и USDT шесть знаков после запятой.
const DECIMALS: u8 = 6;

/// Перевести оператору `amount_micro` и привязать перевод к депозиту.
///
/// # Почему в перевод кладётся memo
///
/// Подпись перевода становится публичной, и без привязки её мог бы предъявить
/// кто угодно как оплату **своего** депозита. Memo равен commitment: подпись
/// годится ровно для того депозита, ради которого сделана, и ни для какого
/// другого.
///
/// # Возвращает
/// * подпись транзакции в base58
pub fn pay_operator(
    signer: &Keypair,
    operator: &str,
    mint: &str,
    amount_micro: u64,
    commitment_hex: &str,
    rpc_url: &str,
) -> Result<String> {
    use anchor_client::Signer as _;
    // Всё через anchor_client, как и остальной SDK: отдельные solana-*
    // зависимости дали бы вторые версии тех же типов и шанс разъехаться.
    use anchor_client::anchor_lang::prelude::AccountMeta;
    use anchor_client::anchor_lang::solana_program::instruction::Instruction;
    use solana_transaction::Transaction;

    let rpc = RpcClient::new(rpc_url.to_string());
    let payer = signer.pubkey();
    let operator: Pubkey = operator.parse().context("operator address")?;
    let mint: Pubkey = mint.parse().context("mint")?;
    let token_program: Pubkey = TOKEN_PROGRAM.parse().expect("константа");
    let ata_program: Pubkey = ATA_PROGRAM.parse().expect("константа");
    let memo_program: Pubkey = MEMO_PROGRAM.parse().expect("константа");

    let source = associated_token_address(&payer, &mint, &token_program, &ata_program);
    let destination = associated_token_address(&operator, &mint, &token_program, &ata_program);

    // `create_idempotent` (код 1): если счёт оператора уже есть — ничего не
    // делает. Обычный `create` в этом случае отменил бы всю транзакцию.
    let create_destination = Instruction {
        program_id: ata_program,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(operator, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(anchor_client::anchor_lang::system_program::ID, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data: vec![1],
    };

    // `TransferChecked` (код 12): проверяет минт и знаки после запятой на
    // стороне программы. Обычный `Transfer` этого не делает, и ошибка в
    // множителе прошла бы молча.
    let mut data = vec![12u8];
    data.extend_from_slice(&amount_micro.to_le_bytes());
    data.push(DECIMALS);
    let transfer = Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(payer, true),
        ],
        data,
    };

    let memo = Instruction {
        program_id: memo_program,
        accounts: vec![],
        data: commitment_hex.as_bytes().to_vec(),
    };

    let blockhash = rpc
        .get_latest_blockhash()
        .context("fetch a fresh blockhash")?;
    let tx = Transaction::new_signed_with_payer(
        &[create_destination, transfer, memo],
        Some(&payer),
        &[signer],
        blockhash,
    );

    let signature = rpc
        .send_and_confirm_transaction(&tx)
        .context("the transfer to the operator was not confirmed")?;
    Ok(signature.to_string())
}

/// Адрес связанного токен-счёта: PDA от `[owner, token_program, mint]`.
fn associated_token_address(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    ata_program: &Pubkey,
) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        ata_program,
    )
    .0
}
