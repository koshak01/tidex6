//! Create a pool v2 for one mint: `init_pool_v2 <rpc> <authority-keypair.json> <mint> <treasury_pk_hex> <fee_floor>`.
//! Run once per mint by the program's upgrade authority.

use anyhow::{Context, Result, bail};
use solana_keypair::read_keypair_file;
use solana_rpc_client::rpc_client::RpcClient;
use tidex6_client::pool_v2;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        bail!("usage: init_pool_v2 <rpc> <authority-keypair.json> <mint> <treasury_pk_hex> <fee_floor>");
    }
    let rpc = RpcClient::new(args[1].clone());
    let authority = read_keypair_file(&args[2]).map_err(|e| anyhow::anyhow!("read keypair: {e}"))?;
    let mint = args[3].parse().context("mint")?;
    let treasury: [u8; 32] = hex::decode(&args[4])
        .context("treasury hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("treasury key must be 32 bytes"))?;
    let fee_floor: u64 = args[5].parse().context("fee floor")?;
    let sig = pool_v2::init_pool(&rpc, &authority, &mint, treasury, fee_floor)?;
    println!("init_pool ok: {sig}");
    Ok(())
}
