# ADR-006: No proc macros in MVP — builder pattern instead

**Status:** Accepted
**Date:** 2026-04-09

## Context

The original project vision included a set of procedural macros that would let an integrator add privacy to their Anchor program with a single annotation:

```rust
#[privacy_program]
pub mod my_program {
    #[private_deposit]
    pub fn contribute(ctx: Context<Contribute>, amount: u64) -> Result<()> {
        // ...
    }
}
```

The macros were supposed to:
- Parse the integrator's Anchor `#[program]` module
- Detect functions tagged `#[private_deposit]` and `#[private_withdraw]`
- Auto-generate PDA structures (PoolState, MerkleRoot history, NullifierPDA, Vault)
- Auto-generate CPI calls into `tidex6-verifier`
- Auto-generate IDL extensions so client tooling knows about the new accounts
- Handle edge cases on function signatures, account contexts, lifetimes

This is a serious mini-compiler. Realistic estimate: **2–3 weeks** of full-time work for one developer with proc-macro experience. For a developer new to `syn` / `quote` / `proc-macro2`, longer.

The MVP timeline is 32 days for one developer. Two to three weeks on macros alone is an **architectural rewrite** of the work plan.

## Decision

Cut proc macros from the MVP entirely. Replace with a **builder pattern** API exposed by `tidex6-client`:

```rust
use tidex6::PrivatePool;

let pool = PrivatePool::new(&ctx)
    .denomination(LAMPORTS_PER_SOL)
    .with_auditor(auditor_pubkey)
    .build()?;

pool.deposit(&signer, secret, nullifier)?;
pool.withdraw(proof, recipient)?;
```

The integrator writes ~5 lines of Rust to wire tidex6 into their program instead of ~2 lines of macro annotations. The resulting program is verbose but understandable, debuggable, and IDE-friendly.

Macros are designed in v0.2 architecture as **ergonomic sugar on top of the proven builder API**, not as a replacement for it. They will be implemented after the MVP ships, on top of code that already works.

## Consequences

**Positive:**
- Saves ~10 days in the MVP timeline. This is the biggest single time saving from the review pass.
- Builder pattern code is debuggable like normal Rust. No hidden generated code. IDE autocompletion works. Compile errors point at the integrator's source line, not at a macro invocation.
- Tests are normal unit tests against normal functions, not test harnesses for macro expansion.
- Macros built later sit on top of a stable, tested API. They become incremental enhancement, not architectural foundation.
- Easier to understand for a new contributor reviewing the SDK.

**Negative:**
- The pitch line "add privacy in 2 lines of code" becomes "add privacy in 5 lines of code". Slightly less magical, but still credible.
- Some verbosity in integrator code that macros would have hidden — explicit builder calls, explicit account context wiring.
- We carry one extra design item into v0.2: build the macros that the original brief promised.

**Neutral:**
- Builder pattern is a well-understood Rust idiom. Every Rust developer can read it without learning a new syntax.
- The macro work is not lost — when it lands in v0.2, it will be a cleaner implementation because it sits on top of an API that has already shipped and seen real integrator usage.

## Related

- [ADR-005](ADR-005-non-upgradeable-verifier.md) — the verifier is locked, but the SDK remains mutable
- [PROJECT_BRIEF.md §8](../PROJECT_BRIEF.md) — Developer Experience section showing builder code
- [ROADMAP.md "Next — v0.2"](../ROADMAP.md) — ergonomic macros listed as v0.2 deliverable
