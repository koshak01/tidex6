# tidex6 — Website Style Guide

This document describes the visual design system for `tidex6.com`.
Feed this file to a design AI (Claude Desktop, v0, etc.) to generate
the TypeScript/HTML/CSS components for each page.

---

## Brand Identity

**Name:** tidex6
**Slogan:** I grant access, not permission.
**Subtitle:** The Rust-native privacy framework for Solana.
**Logo:** bowler hat in Solana gradient (purple → magenta → green).
  - Dark background variant: `brand/logo-dark.png`
  - Light/mono variant: `brand/logo-mono.png`
**Domain:** tidex6.com

---

## Color Palette

Dark theme inspired by Solana's official site (solana.com) and
Phantom wallet. NOT the Polymarket navy — this is a Solana-native
project and must feel like the Solana ecosystem.

### Backgrounds
| Token | Hex | Usage |
|---|---|---|
| `--bg-primary` | `#0A0A0A` | Main page background |
| `--bg-secondary` | `#111111` | Cards, elevated surfaces |
| `--bg-tertiary` | `#1A1A1A` | Inputs, code blocks |
| `--bg-hero` | `linear-gradient(135deg, #0A0A0A 0%, #1A0B2E 50%, #0A0A0A 100%)` | Hero section — subtle purple glow |

### Accent Colors (Solana Gradient)
| Token | Hex | Usage |
|---|---|---|
| `--color-primary` | `#9945FF` | Primary purple (Solana brand) |
| `--color-secondary` | `#14F195` | Green accent (Solana brand) |
| `--color-gradient` | `linear-gradient(90deg, #9945FF, #DC1FFF, #14F195)` | Buttons, borders, highlights |
| `--color-primary-hover` | `#B066FF` | Button hover state |
| `--color-primary-muted` | `rgba(153, 69, 255, 0.15)` | Badges, subtle backgrounds |

### Text
| Token | Hex | Usage |
|---|---|---|
| `--text-primary` | `#FFFFFF` | Headings, body text |
| `--text-secondary` | `#A3A3A3` | Descriptions, secondary info |
| `--text-tertiary` | `#666666` | Muted labels, footnotes |
| `--text-link` | `#9945FF` | Links (purple) |
| `--text-success` | `#14F195` | Success states, confirmed |
| `--text-error` | `#FF4C4C` | Errors, warnings |

### Borders
| Token | Hex | Usage |
|---|---|---|
| `--border-subtle` | `#1F1F1F` | Card borders, dividers |
| `--border-default` | `#2A2A2A` | Input borders |
| `--border-focus` | `#9945FF` | Focus rings |
| `--border-gradient` | `linear-gradient(90deg, #9945FF, #14F195)` | Special highlights |

---

## Typography

| Element | Font | Weight | Size |
|---|---|---|---|
| H1 (hero) | Inter | 700 (bold) | 56px / 3.5rem |
| H2 (section) | Inter | 600 (semibold) | 36px / 2.25rem |
| H3 (card title) | Inter | 600 | 24px / 1.5rem |
| Body | Inter | 400 (regular) | 16px / 1rem |
| Body small | Inter | 400 | 14px / 0.875rem |
| Code / mono | JetBrains Mono | 400 | 14px / 0.875rem |
| Button | Inter | 600 | 16px / 1rem |
| Nav link | Inter | 500 | 15px / 0.9375rem |

Line height: 1.5 for body, 1.2 for headings.
Letter spacing: -0.02em for headings, normal for body.

Import: `@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400&display=swap');`

---

## Layout

- **Max width:** 1200px centered
- **Grid:** 12-column with 24px gap
- **Section padding:** 120px vertical (desktop), 60px (mobile)
- **Card padding:** 32px
- **Border radius:** 12px for cards, 8px for inputs/buttons, 999px for pills
- **Header height:** 72px, fixed, backdrop-blur

---

## Components

### Button — Primary
```
Background: var(--color-gradient)
Text: #FFFFFF, 600 weight
Padding: 12px 28px
Border-radius: 8px
Hover: brightness(1.1) + slight scale(1.02)
Transition: all 0.2s ease
```

### Button — Secondary (outline)
```
Background: transparent
Border: 1px solid var(--border-default)
Text: var(--text-primary)
Hover: border-color var(--color-primary), text var(--color-primary)
```

### Card
```
Background: var(--bg-secondary)
Border: 1px solid var(--border-subtle)
Border-radius: 12px
Padding: 32px
Hover: border-color var(--border-default), subtle box-shadow
Transition: all 0.2s ease
```

### Navigation Header
```
Background: rgba(10, 10, 10, 0.8)
Backdrop-filter: blur(12px)
Border-bottom: 1px solid var(--border-subtle)
Height: 72px
Position: fixed, z-index: 100
```

### Code Block
```
Background: var(--bg-tertiary)
Border: 1px solid var(--border-subtle)
Border-radius: 8px
Padding: 24px
Font: JetBrains Mono, 14px
Color: var(--text-primary)
Syntax highlighting: Solana purple for keywords, green for strings
```

### Wallet Connect Button
```
Background: var(--color-gradient)
Icon: Phantom/wallet icon on the left
Text: "Connect Wallet"
Border-radius: 8px
When connected: show truncated address + green dot
```

---

## Site Structure

**NO landing page. NO full-screen hero.** This is a normal website
with a fixed top navigation menu. Clicking a menu item takes you
to that page. Clean, professional, like a real product — not a
hackathon one-pager.

### Navigation (fixed header, every page)

```
[Logo tidex6]   Home   How it Works   Use Cases   Developers   Roadmap   [Connect Wallet]
```

- Logo is the bowler hat (small, ~32px) + "tidex6" text next to it
- Menu items are regular links to separate pages (or anchor sections on one long page — designer decides)
- [Connect Wallet] button is always on the right, gradient style
- Mobile: hamburger menu

### 1. Home (compact, not a landing page)

Top area (NOT full-screen hero — just a section):
- Logo (80px, centered or left-aligned)
- H1: "I grant access, not permission." (normal heading size, not 56px billboard)
- One line subtitle: "The Rust-native privacy framework for Solana."
- Two buttons inline: [Connect Wallet] (gradient) + [View on GitHub] (outline)

Below — **three feature cards** in a row:
- "ZK Privacy" — shield icon — "Groth16 proofs hide the sender-receiver link."
- "Selective Disclosure" — key icon — "Share a viewing key with your accountant — and only them."
- "Non-upgradeable" — lock icon — "Verifier program locked after deploy. No backdoors."

Below — **live stats bar** (compact, one line):
- Program ID (truncated, clickable to Solscan)
- Network: Mainnet
- Verified ✓
- Powered by Helius RPC

### 2. How it Works
Three large steps, vertically stacked, with illustrations:
- Step 1: DEPOSIT — "Lena sends SOL into the shielded pool. On-chain: only a commitment hash."
- Step 2: TRANSFER NOTE — "The note file travels offchain. Signal, email, QR — any channel."
- Step 3: WITHDRAW — "The recipient presents a ZK proof and claims the SOL. No link to the sender."

Below: side-by-side comparison panel:
- Left: "What Solscan sees" — hash, tx signature, ???
- Right: "What the accountant sees" — date, sender name, amount, memo

### 3. Use Cases
Grid of 6 clickable cards. Each card:
- Icon (emoji or SVG)
- Title (2-3 words)
- On click: expands to show 2-3 sentence description

Cards:
1. **Family Support** — "Send monthly support across borders. No flags, no questions."
2. **Journalist Protection** — "A source funds an investigation. The donation is private."
3. **Freelancer Privacy** — "Invoice clients without broadcasting your rates to competitors."
4. **Payroll** — "Pay a remote team in 12 countries. Each sees only their own salary."
5. **Donor Anonymity** — "Support causes without exposing yourself to retaliation."
6. **Tax Compliance** — "Share a viewing key with your accountant at year-end. Full audit trail."

### 4. Developers
Two code blocks side by side:
- Left: SDK (Rust)
  ```rust
  let pool = PrivatePool::connect(Cluster::Mainnet, Denomination::OneSol)?;
  let (sig, note, _) = pool.deposit(&wallet).send()?;
  let sig = pool.withdraw(&wallet).note(note).to(recipient).send()?;
  ```
- Right: CLI (bash)
  ```bash
  tidex6 keygen
  tidex6 deposit --amount 0.1
  tidex6 withdraw --note parents.note --to <pubkey>
  ```

Below: four link buttons:
[GitHub] [SDK Reference] [Security Policy] [Solscan Program]

### 5. Roadmap
Horizontal timeline with three milestones:
- **MVP (April 2026)** ✅ — Shielded pool, ZK withdraw, CLI, SDK, mainnet deploy
- **v0.2 (Q3 2026)** — Viewing keys (ElGamal), shielded memos, audit, web UI v2
- **v0.3 (Q4 2026)** — Confidential amounts (Token-2022 CT), shared anonymity pool

### 6. Footer
Dark, minimal:
- Left: Logo + "I grant access, not permission."
- Center: Program ID (clickable to Solscan), Security.txt status
- Right: GitHub, Solscan, License
- Bottom line: "Powered by Helius RPC | Colosseum Frontier 2026 | Built with Claude Code"

---

## Interactive Elements

### Wallet Connect (Phantom/Backpack)
- Uses `@solana/wallet-adapter-react` + `@solana/wallet-adapter-phantom`
- Header shows: [Connect Wallet] → after connect: [Cs9F...8n6 ●]
- Balance displayed next to address

### Deposit Form (on Home page or separate)
```
┌────────────────────────────────────┐
│  Deposit to Shielded Pool          │
│                                    │
│  Amount: [0.1 SOL ▼]              │
│  (dropdown: 0.1 / 0.5 / 1 / 10)  │
│                                    │
│  [Deposit]                         │
│                                    │
│  After deposit:                    │
│  ✓ Note saved — download below    │
│  [Download .note file]             │
└────────────────────────────────────┘
```

### Withdraw Form
```
┌────────────────────────────────────┐
│  Withdraw from Shielded Pool       │
│                                    │
│  Note: [Upload .note file]         │
│  Recipient: [paste pubkey]         │
│                                    │
│  [Withdraw]                        │
│                                    │
│  After withdraw:                   │
│  ✓ 0.1 SOL received               │
│  Tx: 2iHTqeVM... (link to Solscan)│
└────────────────────────────────────┘
```

---

## Responsive Breakpoints

| Breakpoint | Width | Layout |
|---|---|---|
| Desktop | > 1024px | Full grid, side-by-side panels |
| Tablet | 768–1024px | 2-column cards, stacked panels |
| Mobile | < 768px | Single column, hamburger menu |

---

## Animations

- **Cards:** subtle fade-in on scroll into view (0.3s, no bounce)
- **Buttons:** scale(1.02) on hover (0.2s)
- **No hero animations.** Page loads instantly, no theatrical reveals.
- **No excessive motion.** Respect `prefers-reduced-motion`.
- Keep it professional. This is infrastructure, not a game.

---

## Reference Sites (for visual inspiration)

1. **solana.com** — dark theme, gradients, clean sections
2. **phantom.app** — wallet-native feel, purple accent
3. **jup.ag** — trading UI, dark theme, Solana-native
4. **helius.dev** — developer-focused, clean docs

---

## What NOT to do

- No light theme. Dark only.
- No generic stock photos. Use icons, code blocks, and diagrams.
- No cookie banners, popups, or newsletter forms.
- No "Web3" buzzwords (metaverse, NFT, DeFi yield).
- No competitor mentions.
- No Russian language anywhere.
- No emojis in headings (use SVG icons instead).
