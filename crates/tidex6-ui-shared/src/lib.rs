//! Shared web chrome for the tidex6 properties.
//!
//! Contains the brand assets, the partial Tera templates (head,
//! header, footer) and the foundation CSS (tokens, base, footer)
//! that every tidex6 web property — `tidex6.com`, `relayer.tidex6.com`,
//! and any future microservice with a UI — shares verbatim.
//!
//! The asset tree under `assets/` is **embedded at compile time** via
//! `include_dir!`. There is no runtime filesystem dependency — the
//! consumer binary ships with the bytes baked in, and an Axum
//! handler can stream them with `Bytes::from_static`.
//!
//! # Layout
//!
//! ```text
//! assets/
//! ├── css/
//! │   ├── tokens.css        — design tokens (colors, spacing, fonts)
//! │   ├── base.css          — body/typography/reset
//! │   └── footer.css        — footer-* component styles
//! ├── images/
//! │   ├── logo-mono.png     — bowler-hat brand mark
//! │   └── partners/
//! │       ├── solana.svg
//! │       ├── helius.svg
//! │       ├── claude.svg
//! │       └── rust.svg
//! └── templates/
//!     └── partials/
//!         ├── head.html     — favicons, fonts, design-system CSS
//!         ├── header.html   — nav bar with brand mark
//!         └── footer.html   — slogan + tech-stack row
//! ```
//!
//! # Usage
//!
//! For an Axum server:
//!
//! ```ignore
//! use tidex6_ui_shared::ASSETS;
//!
//! async fn shared_static(Path(rel): Path<String>) -> impl IntoResponse {
//!     match ASSETS.get_file(&rel) {
//!         Some(file) => (
//!             [(header::CONTENT_TYPE, mime_for(&rel))],
//!             file.contents().to_vec(),
//!         ).into_response(),
//!         None => StatusCode::NOT_FOUND.into_response(),
//!     }
//! }
//! ```
//!
//! For a Tera renderer:
//!
//! ```ignore
//! tera.add_raw_template(
//!     "partials/footer.html",
//!     tidex6_ui_shared::FOOTER_HTML,
//! )?;
//! ```

use include_dir::{Dir, include_dir};

/// Compile-time embedded asset tree. Walk it the same way as a
/// filesystem `Dir` (see `include_dir` crate docs). Path keys inside
/// are *relative* — `css/tokens.css`, `images/logo-mono.png`, etc.
pub static ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/assets");

/// Footer partial. The only chrome partial that is identical across
/// every tidex6 property — the same slogan, same tech-stack row,
/// same Solscan/GitHub links. Header and `<head>` differ per-site
/// (different nav, different page-specific CSS imports) and live in
/// each consumer's own `templates/partials/` directory.
pub const FOOTER_HTML: &str = include_str!("../assets/templates/partials/footer.html");

/// Convenience constants for the foundation CSS. Consumers can
/// concatenate these into a single bundled stylesheet, or serve each
/// at its own path — both work.
pub const TOKENS_CSS: &str = include_str!("../assets/css/tokens.css");
pub const BASE_CSS: &str = include_str!("../assets/css/base.css");
pub const FOOTER_CSS: &str = include_str!("../assets/css/footer.css");
