# tidex6 brand assets

This directory contains the official tidex6 logo and brand assets.

## Logo

The tidex6 mark is a round bowler hat — a quiet symbol of
discretion and selective disclosure. The gradient runs diagonally
at 60 degrees from Solana purple (`#9945FF`) through magenta
(`#DC1FFF`) to Solana green (`#14F195`), signalling that tidex6 is
Solana-native without reproducing the Solana Foundation trademark.

The hat is intentionally featureless: no face, no figure, no eyes.
Privacy is not about hiding — it is about choosing who sees what.

## Files

| File | Background | Use case |
|---|---|---|
| `logo-dark.png` | Dark (`#0A0A0A`) | Hero logo, gradient fill. GitHub social preview, dark-mode site, presentations, Colosseum submission. |
| `logo-mono.png` | White (`#FFFFFF`) | Monochrome fill in Solana purple (`#9945FF`). README in light mode, documentation, stickers, print, favicons, embeds in third-party documents. |
| `logo-variants-study.png` | Comparison sheet | Reference only. Shows the gradient-on-dark, gradient-on-white, and monochrome-purple variants side by side. Not for direct use. |

The repository README uses a `<picture>` element to automatically
serve `logo-dark.png` to visitors with dark mode enabled and
`logo-mono.png` to visitors with light mode enabled.

## Planned additional variants

- `logo-light.png` — the full gradient hat on a pure white
  background, for use cases that want the gradient on light
  surfaces (landing page hero, pitch deck title slide).
- `logo.svg` — vector-native version for infinite scaling. The
  current PNGs are raster; an SVG trace would be ideal before
  launch.

## Colour tokens

```text
solana-purple : #9945FF
solana-magenta: #DC1FFF
solana-green  : #14F195
charcoal      : #0A0A0A   (hero background)
white         : #FFFFFF   (light background)
```

## Trademark notice

The tidex6 hat mark is an original design for this project and may
be used under the same dual MIT/Apache-2.0 licence as the rest of
the repository. The Solana name, logo, and signature stripes are
trademarks of the Solana Foundation and are **not** reproduced in
the tidex6 mark — only the colour palette is inspired by the
Solana ecosystem, which is permitted by their brand guidelines.
