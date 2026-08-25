// Частный перевод ценности на Aleo (эскиз для гранта).
//
// Соответствие Solana tidex6:
//   нота / обязательство     → запись Token
//   трата / нуллификатор     → запись на входе функции съедается один раз
//   скрытая сумма            → amount в записи, не на публичной ленте
//   скрытая связь кто-кому   → owner в записи
//   слот аудитора            → отдельная запись AuditSlip (только смотреть, не тратить Token)
//
// Не в этом эскизе: ретранслятор, шифрование ML-KEM, Token-2022.

program tidex6_private_transfer.aleo {
    // Ценность, которую можно потратить. Тратит только owner.
    record Token {
        owner: address,
        amount: u64,
    }

    // Выписка для аудитора: видит сумму, но это НЕ Token.
    // Потратить чужой Token через AuditSlip нельзя — отдельный тип записи.
    record AuditSlip {
        owner: address,
        amount: u64,
    }

    // Выпустить частную ноту (для демо; в проде выпуск ограничивают).
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

    // Передать всю ноту другому владельцу.
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

    // Частичный перевод: получателю amount, сдача владельцу.
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

    // Выборочное раскрытие: владелец Token выдаёт аудитору AuditSlip
    // с той же суммой. Token возвращается владельцу (право траты сохраняется).
    // Аудитор получает только «выписку», не возможность потратить Token.
    fn issue_audit_slip(
        token: Token,
        private auditor: address,
    ) -> (Token, AuditSlip) {
        assert(token.amount > 0u64);
        let kept: Token = Token {
            owner: token.owner,
            amount: token.amount,
        };
        let slip: AuditSlip = AuditSlip {
            owner: auditor,
            amount: token.amount,
        };
        return (kept, slip);
    }

    @noupgrade
    constructor() {}
}
