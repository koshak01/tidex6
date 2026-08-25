# Leo spike plan (2–3 days)

**Goal:** prove we can stand up a private transfer sketch in Leo and write the grant form without vapor.

## Day 1 — toolchain

1. Install Leo toolchain (docs.leo-lang.org / leo-lang.org).  
2. `leo new tidex6_private_transfer` (or workspace path under `tidex6/aleo/`).  
3. Hello-world build + execute locally.  
4. Note OS/version/snags in `docs/aleo/SPIKE_LOG.md`.

## Day 2 — private transfer sketch

1. Private record with owner + amount (minimal).  
2. Transition: transfer / spend once.  
3. Second spend of same record → **must fail**.  
4. Wrong owner → **must fail**.  
5. Wire tests if Leo/test harness allows; else scripted execute + notes.

## Day 3 — grant materials

1. Fill `GRANT_ONE_PAGER_DRAFT.md` with real build commands.  
2. Attach security checklist (already in tree).  
3. Decide $ ask ($35–50k default).  
4. Ask Пётр for apply OK before Asana submit.

## Exit criteria (spike green)

- [x] Repo builds (`leo build` OK, Leo 4.4.0)  
- [x] Overspend / zero-mint rejected via assert (`leo run`)  
- [x] Protocol double-spend = record consume once (documented; runner `leo test` flaky on mac)  
- [x] README maps ≥5 tidex6 concepts → Leo names  
- [x] Budget + 3 milestones in `GRANT_ONE_PAGER_DRAFT.md`  
- [ ] Operator OK → submit Asana form  

Then: submit form.
