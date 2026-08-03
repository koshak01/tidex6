// tidex6_private_transfer — Aleo/Leo MVP for the tidex6 privacy contour.
//
// Maps Solana tidex6 concepts:
//   note / commitment  → private Token record
//   spend / nullifier  → consuming a record as function input (once)
//   amount privacy     → amount is private on the record
//   link privacy       → owner is private; public chain does not show who↔whom
//
// NOT in this MVP: auditor/view key, relayer fee payer, ML-KEM memo, CT Token-2022.

program tidex6_private_transfer.aleo {
    // Private value unit (UTXO-style). Owner alone can spend.
    record Token {
        // Who may consume this record.
        owner: address,
        // Private amount (hidden on chain).
        amount: u64,
    }

    // Mint a private note to `receiver` for `amount`.
    // Offline / demo: caller is trusted to mint. Mainnet product would gate this.
    fn mint_private(
        public receiver: address,
        public amount: u64,
    ) -> Token {
        assert(amount > 0u64);
        return Token {
            owner: receiver,
            amount: amount,
        };
    }

    // Move the full note to a new owner (1:1 transfer).
    // Consuming `token` nullifies it — a second spend of the same record fails
    // at the protocol layer (double-spend protection).
    fn transfer_full(
        token: Token,
        private new_owner: address,
    ) -> Token {
        assert(token.amount > 0u64);
        return Token {
            owner: new_owner,
            amount: token.amount,
        };
    }

    // Split-transfer: send `amount` to `receiver`, keep change for sender.
    // Fails if amount is zero or exceeds balance (checked arithmetic).
    fn transfer_private(
        token: Token,
        private receiver: address,
        private amount: u64,
    ) -> (Token, Token) {
        assert(amount > 0u64);
        let change: u64 = token.amount - amount;
        let remaining: Token = Token {
            owner: token.owner,
            amount: change,
        };
        let transferred: Token = Token {
            owner: receiver,
            amount: amount,
        };
        return (remaining, transferred);
    }

    @noupgrade
    constructor() {}
}
