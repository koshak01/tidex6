//! MCP Apps UI for the trusted-setup ceremony (SEP-1865 / `ui://`).
//!
//! The card is a launch pad: it never embeds the wallet page (sandbox cannot
//! reach browser extensions). Correlation nonce is **ceremony-only** — never
//! reuse for payments (see task 483).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use uuid::Uuid;

/// Resource URI bound to the `ceremony` tool via `_meta["ui/resourceUri"]`.
pub const CEREMONY_UI_URI: &str = "ui://tidex6/ceremony";

/// MIME type required by MCP Apps for interactive HTML.
pub const CEREMONY_UI_MIME: &str = "text/html;profile=mcp-app";

const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
pub struct CeremonySession {
    pub created_at: Instant,
    pub status: SessionStatus,
    pub wallet: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Pending,
    Done,
    Expired,
}

fn store() -> &'static Mutex<HashMap<String, CeremonySession>> {
    static STORE: OnceLock<Mutex<HashMap<String, CeremonySession>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Create a pending session; returns unguessable nonce (UUID).
pub fn create_session() -> String {
    let nonce = Uuid::new_v4().to_string();
    if let Ok(mut g) = store().lock() {
        g.retain(|_, s| s.created_at.elapsed() < SESSION_TTL);
        g.insert(
            nonce.clone(),
            CeremonySession {
                created_at: Instant::now(),
                status: SessionStatus::Pending,
                wallet: None,
            },
        );
    }
    nonce
}

/// Mark session complete after a real on-chain contribution (web calls this).
///
/// Ignores unknown / expired nonces quietly — the card will simply keep
/// polling until TTL.
pub fn complete_session(nonce: &str, wallet: impl Into<String>) {
    let nonce = nonce.trim();
    if nonce.is_empty() {
        return;
    }
    let Ok(mut g) = store().lock() else {
        return;
    };
    if let Some(s) = g.get_mut(nonce) {
        if s.created_at.elapsed() >= SESSION_TTL {
            s.status = SessionStatus::Expired;
            return;
        }
        s.status = SessionStatus::Done;
        s.wallet = Some(wallet.into());
    }
}

/// Read session status; lazy-expire.
pub fn session_status(nonce: &str) -> Option<CeremonySession> {
    let nonce = nonce.trim();
    if nonce.is_empty() {
        return None;
    }
    let Ok(mut g) = store().lock() else {
        return None;
    };
    let Some(s) = g.get_mut(nonce) else {
        return None;
    };
    if s.status == SessionStatus::Pending && s.created_at.elapsed() >= SESSION_TTL {
        s.status = SessionStatus::Expired;
    }
    Some(s.clone())
}

/// Self-contained HTML card (no external origins). Meaning-first copy (canon §5).
pub fn ceremony_card_html(contributions: usize, wallets: usize, url: &str, nonce: &str) -> String {
    // Escape for HTML attribute / text.
    let url_esc = html_escape(url);
    let nonce_esc = html_escape(nonce);
    let link = if nonce.is_empty() {
        url_esc.clone()
    } else {
        format!(
            "{base}{sep}s={nonce}",
            base = url_esc,
            sep = if url.contains('?') { "&" } else { "?" },
            nonce = nonce_esc
        )
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>tidex6 ceremony</title>
<style>
  :root {{ font-family: system-ui, sans-serif; color: #e8e6e3; background: #0d0d0c; }}
  body {{ margin: 0; padding: 14px; }}
  .card {{
    border: 1px solid #2a2a28; border-radius: 12px; padding: 14px 16px;
    background: #141412; max-width: 360px;
  }}
  h1 {{ font-size: 15px; margin: 0 0 8px; font-weight: 600; letter-spacing: -0.01em; }}
  .nums {{ display: flex; gap: 16px; margin: 10px 0 8px; }}
  .nums div {{ flex: 1; }}
  .nums b {{ display: block; font-size: 22px; font-variant-numeric: tabular-nums; }}
  .nums span {{ font-size: 11px; color: #8a8680; }}
  p {{ margin: 0 0 10px; font-size: 12.5px; line-height: 1.45; color: #b5b1a9; }}
  a.btn {{
    display: inline-block; padding: 8px 14px; border-radius: 8px;
    background: #14F195; color: #0a0a09; font-weight: 600; font-size: 13px;
    text-decoration: none;
  }}
  a.sec {{ display: inline-block; margin-left: 10px; font-size: 12px; color: #8a8680; }}
  #st {{ margin-top: 10px; font-size: 12px; color: #14F195; min-height: 1.2em; }}
</style>
</head>
<body>
  <div class="card">
    <h1>Trusted-setup ceremony</h1>
    <div class="nums">
      <div><b id="c">{contributions}</b><span>contributions</span></div>
      <div><b id="w">{wallets}</b><span>distinct wallets</span></div>
    </div>
    <p>Safety is 1-of-N: one honest wallet is enough. Repeats from the same wallet do not strengthen the guarantee.</p>
    <p><b>$0</b> · no deposit · signature only names the contribution.</p>
    <a class="btn" id="go" href="{link}" target="_blank" rel="noopener">Contribute</a>
    <a class="sec" href="{url_esc}transcript/" target="_blank" rel="noopener">Transcript</a>
    <div id="st"></div>
  </div>
  <script>
  (function () {{
    var nonce = {nonce_json};
    var statusEl = document.getElementById('st');
    var go = document.getElementById('go');
    // Prefer host openLink when available (MCP Apps); keep href for degradation.
    go.addEventListener('click', function (e) {{
      try {{
        if (window.openai && typeof window.openai.openExternal === 'function') {{
          e.preventDefault();
          window.openai.openExternal({{ href: go.href }});
          return;
        }}
      }} catch (_) {{}}
      try {{
        if (window.parent && window.parent !== window) {{
          window.parent.postMessage({{ jsonrpc: '2.0', method: 'ui/open-link', params: {{ url: go.href }} }}, '*');
        }}
      }} catch (_) {{}}
    }});
    if (!nonce) return;
    var started = Date.now();
    var interval = 4000;
    function tick() {{
      if (Date.now() - started > 10 * 60 * 1000) {{
        statusEl.textContent = 'Session window closed — open the link again if needed.';
        return;
      }}
      if (Date.now() - started > 2 * 60 * 1000) interval = 12000;
      try {{
        // Hosts that implement callServerTool (MCP Apps) can poll status.
        if (window.mcpApp && typeof window.mcpApp.callServerTool === 'function') {{
          window.mcpApp.callServerTool('ceremony_status', {{ nonce: nonce }}).then(function (r) {{
            var st = (r && r.structuredContent) || r || {{}};
            if (st.status === 'done') {{
              statusEl.textContent = 'Accepted' + (st.wallet ? (' · ' + st.wallet) : '');
              return;
            }}
            if (st.status === 'expired') {{
              statusEl.textContent = 'Session expired.';
              return;
            }}
            setTimeout(tick, interval);
          }}).catch(function () {{ setTimeout(tick, interval); }});
          return;
        }}
      }} catch (_) {{}}
      setTimeout(tick, interval);
    }}
    setTimeout(tick, interval);
  }})();
  </script>
</body>
</html>
"##,
        contributions = contributions,
        wallets = wallets,
        link = link,
        url_esc = url_esc,
        nonce_json = serde_json::to_string(nonce).unwrap_or_else(|_| "\"\"".into()),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
