//! Payment quoting — the arithmetic an agent is allowed to do on its own.
//!
//! Quoting touches no key and sends nothing. It exists so the agent can tell
//! the user what a payment will cost *before* anyone signs anything, and so the
//! numbers the user approves are the numbers that get executed.
//!
//! Amounts are in micro-units (1e6), matching the stablecoin decimals and the
//! integer arithmetic the pool service uses. Nothing here is floating point:
//! a rounding drift between the quote and the sealed note would be a payment
//! the recipient cannot claim.

/// Fee policy (ADR-016): a percentage the sender pays on top, with a floor so
/// small payments still cover the cost of moving them.
#[derive(Debug, Clone, Copy)]
pub struct FeePolicy {
    /// Basis points. 100 = 1%.
    pub bps: u32,
    /// Minimum fee in micro-units, applied when the percentage falls below it.
    pub floor_micro: u64,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            bps: 100,
            floor_micro: 100_000,
        }
    }
}

/// What the user is asked to approve. Every number the agent shows comes from
/// here, so there is one place where the arithmetic can be wrong.
#[derive(Debug, Clone, Copy)]
pub struct Quote {
    pub amount_micro: u64,
    pub fee_micro: u64,
    pub total_micro: u64,
}

impl Quote {
    /// Compute the quote for `amount_micro` under `policy`.
    ///
    /// Checked arithmetic throughout: a silent wrap here would be a wrong
    /// number shown to a human who is about to sign it.
    pub fn compute(amount_micro: u64, policy: FeePolicy) -> Option<Self> {
        let proportional = (amount_micro as u128)
            .checked_mul(policy.bps as u128)?
            .checked_div(10_000)?;
        let proportional = u64::try_from(proportional).ok()?;

        let fee = proportional.max(policy.floor_micro);
        let total = amount_micro.checked_add(fee)?;

        Some(Self {
            amount_micro,
            fee_micro: fee,
            total_micro: total,
        })
    }
}

/// Render micro-units as a decimal string, trailing zeros trimmed.
pub fn micro_to_decimal(micro: u64) -> String {
    let whole = micro / 1_000_000;
    let frac = micro % 1_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let s = format!("{whole}.{frac:06}");
    s.trim_end_matches('0').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_applies_to_small_payments() {
        // 1% of 1.0 is 0.01, below the 0.1 floor — the floor wins.
        let q = Quote::compute(1_000_000, FeePolicy::default()).expect("fits");
        assert_eq!(q.fee_micro, 100_000);
        assert_eq!(q.total_micro, 1_100_000);
    }

    #[test]
    fn percentage_applies_to_large_payments() {
        // 1% of 100.0 is 1.0, above the floor.
        let q = Quote::compute(100_000_000, FeePolicy::default()).expect("fits");
        assert_eq!(q.fee_micro, 1_000_000);
        assert_eq!(q.total_micro, 101_000_000);
    }

    #[test]
    fn overflow_is_reported_not_wrapped() {
        assert!(Quote::compute(u64::MAX, FeePolicy::default()).is_none());
    }

    #[test]
    fn decimal_rendering_trims() {
        assert_eq!(micro_to_decimal(1_000_000), "1");
        assert_eq!(micro_to_decimal(1_100_000), "1.1");
        assert_eq!(micro_to_decimal(100_000), "0.1");
    }
}
