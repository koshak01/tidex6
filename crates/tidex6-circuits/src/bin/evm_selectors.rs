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
        "publishReader(uint8,bytes)",
        "readerOf(address)",
        "revokeReader()",
        "isKnownRoot(uint256)",
        "NotAFieldElement()",
        "CommitmentAlreadyUsed()",
        "RootNotRecent()",
        "NullifierAlreadySpent()",
        "InvalidProof()",
        "FeeExceedsDenomination()",
        "TransferFailed()",
        "nullifierSpent(uint256)",
        "withdraw(uint256[2],uint256[2][2],uint256[2],uint256,uint256,address,address,uint256)",
        "nextLeafIndex()",
        "ReaderRevoked(address)",
        "isRegistered(address)",
        "matchesPublished(address,bytes)",
        "ReaderPublished(address,uint8,bytes)",
        "Deposit(uint256,uint256,uint256,address,bytes)",
        // hidden-amount pool (Tidex6HiddenPool) and its two verifiers
        "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[8])",
        "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[4])",
        "deposit(uint256,uint256,bytes)",
        "withdraw(uint256[2],uint256[2][2],uint256[2],uint256,uint256,address,address,uint256,uint256)",
        "transferNote(uint256[2],uint256[2][2],uint256[2],uint256,uint256,uint256,uint256,bytes,bytes)",
        "Deposit(uint256,uint256,uint256,address,uint256,bytes)",
        "NoteCreated(uint256,uint256,uint256,bytes)",
        "NoteSpent(uint256)",
        "Withdrawal(uint256,address,address,uint256,uint256)",
        "AmountOutOfRange()",
        "FeeExceedsAmount()",
        "SameCommitment()",
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
