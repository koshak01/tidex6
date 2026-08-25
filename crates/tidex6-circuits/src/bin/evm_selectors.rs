use sha3::{Digest, Keccak256};
fn main() {
    for sig in [
        "deposit(uint256,bytes)",
        "approve(address,uint256)",
        "balanceOf(address)",
        "allowance(address,address)",
        "denomination()",
        "currentRoot()",
        "mint(address,uint256)",
        "decimals()",
        "Deposit(uint256,uint256,uint256,address,bytes)",
    ] {
        let mut h = Keccak256::new();
        h.update(sig.as_bytes());
        let d = h.finalize();
        println!("{:<52} 0x{}", sig, hex::encode(&d[..4]));
        if sig.contains('(') && sig.chars().next().unwrap().is_uppercase() {
            println!("{:<52} topic0 0x{}", "", hex::encode(&d[..]));
        }
    }
}
