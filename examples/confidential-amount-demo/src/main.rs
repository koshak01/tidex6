//! CLI для confidential-amount-demo.
//!
//! ```text
//! cd-demo init alice
//! cd-demo init bob
//! cd-demo deposit alice 100
//! cd-demo deposit bob 10
//! cd-demo transfer alice bob 30
//! cd-demo balance alice
//! cd-demo state           # показывает всё что видно наблюдателю
//! ```

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use tidex6_confidential_amount_demo::state::DemoState;

#[derive(Parser, Debug)]
#[command(name = "cd-demo", about = "Confidential amount demo — Pedersen commitments playground")]
struct Cli {
    /// Где хранить JSON-состояние. По умолчанию `./cd-demo-state.json`
    /// в текущей директории.
    #[arg(long, global = true)]
    state: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Создать новый аккаунт с нулевым балансом.
    Init { name: String },

    /// Пополнить аккаунт на `amount`. В реальной системе amount
    /// здесь раскрывается (он пришёл из публичного источника).
    Deposit { name: String, amount: u64 },

    /// Приватно перевести `amount` от `from` к `to`. Наблюдатель
    /// видит только смену двух commitment'ов.
    Transfer {
        from: String,
        to: String,
        amount: u64,
    },

    /// Показать баланс конкретного аккаунта с точки зрения его
    /// владельца (с расшифровкой).
    Balance { name: String },

    /// Показать всё состояние так как его видит **наблюдатель**:
    /// только публичные commitment'ы, без балансов.
    State,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let state_path = cli
        .state
        .unwrap_or_else(|| PathBuf::from("./cd-demo-state.json"));

    let mut state = DemoState::load(&state_path)?;

    match cli.command {
        Command::Init { name } => {
            state.open_account(&name)?;
            state.save(&state_path)?;
            println!("Opened account `{name}` with zero balance.");
            print_public_state(&state);
        }

        Command::Deposit { name, amount } => {
            state.deposit(&name, amount)?;
            state.save(&state_path)?;
            println!("Deposited {amount} into `{name}`.");
            print_public_state(&state);
        }

        Command::Transfer { from, to, amount } => {
            state.transfer(&from, &to, amount)?;
            state.save(&state_path)?;
            println!(
                "Confidential transfer: {from} → {to} ({amount} units, hidden from observers)."
            );
            println!();
            print_public_state(&state);
        }

        Command::Balance { name } => {
            let entry = state
                .accounts
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("unknown account `{name}`"))?;
            let ok = state.verify_owner_view(&name)?;
            println!("Account: {name}");
            println!("  public commitment : {}", entry.public_commitment_hex);
            println!("  private balance   : {}", entry.private_balance);
            println!(
                "  consistency check : {}",
                if ok {
                    "OK — commitment matches balance · blinding"
                } else {
                    "FAIL — state file tampered"
                }
            );
        }

        Command::State => {
            print_public_state(&state);
        }
    }

    Ok(())
}

/// Напечатать только то, что было бы видно наблюдателю на chain.
/// Никаких приватных балансов и blinding factor'ов.
fn print_public_state(state: &DemoState) {
    println!();
    println!("┌──── What an outside observer sees ──────────────────────────┐");
    if state.accounts.is_empty() {
        println!("  (no accounts yet)");
    } else {
        for (name, entry) in &state.accounts {
            println!(
                "  {:10} → commitment {}…",
                name,
                &entry.public_commitment_hex[..24]
            );
        }
    }
    println!("└─────────────────────────────────────────────────────────────┘");
    println!("  Nothing above reveals actual balances.");
    println!("  Use `cd-demo balance <name>` to decrypt your own account.");
    println!();
}
