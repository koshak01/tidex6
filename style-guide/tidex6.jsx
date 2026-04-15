import { useState, useEffect, useRef } from "react";

// ─── CSS Variables & Global Styles ───────────────────────────────────
const GLOBAL_CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400&display=swap');

:root {
  --bg-primary: #0A0A0A;
  --bg-secondary: #111111;
  --bg-tertiary: #1A1A1A;
  --color-primary: #9945FF;
  --color-secondary: #14F195;
  --color-gradient: linear-gradient(90deg, #9945FF, #DC1FFF, #14F195);
  --color-primary-hover: #B066FF;
  --color-primary-muted: rgba(153, 69, 255, 0.15);
  --text-primary: #FFFFFF;
  --text-secondary: #A3A3A3;
  --text-tertiary: #666666;
  --text-link: #9945FF;
  --text-success: #14F195;
  --text-error: #FF4C4C;
  --border-subtle: #1F1F1F;
  --border-default: #2A2A2A;
  --border-focus: #9945FF;
}

*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

html {
  scroll-behavior: smooth;
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: 'Inter', sans-serif;
  font-size: 16px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

body { background: var(--bg-primary); }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

::selection {
  background: rgba(153, 69, 255, 0.4);
  color: #fff;
}

::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }

@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(24px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}
@keyframes gradientShift {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
@keyframes heroGradient {
  0%   { background-position: 0% 50%; }
  50%  { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
@keyframes slideInLeft {
  from { opacity: 0; transform: translateX(-30px); }
  to { opacity: 1; transform: translateX(0); }
}
@keyframes slideInRight {
  from { opacity: 0; transform: translateX(30px); }
  to { opacity: 1; transform: translateX(0); }
}
`;

// ─── Icons (inline SVG) ──────────────────────────────────────────────
const Icons = {
  shield: (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="url(#grad)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <defs><linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#9945FF"/><stop offset="100%" stopColor="#14F195"/></linearGradient></defs>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  key: (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="url(#grad2)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <defs><linearGradient id="grad2" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#9945FF"/><stop offset="100%" stopColor="#14F195"/></linearGradient></defs>
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
    </svg>
  ),
  lock: (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="url(#grad3)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <defs><linearGradient id="grad3" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#9945FF"/><stop offset="100%" stopColor="#14F195"/></linearGradient></defs>
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  ),
  github: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  ),
  external: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  ),
  menu: (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
  ),
  close: (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
  ),
  wallet: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12V7H5a2 2 0 0 1 0-4h14v4"/><path d="M3 5v14a2 2 0 0 0 2 2h16v-5"/><path d="M18 12a1 1 0 1 0 2 0 1 1 0 0 0-2 0z"/>
    </svg>
  ),
  check: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#14F195" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
  ),
  arrow_down: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M6 9l6 6 6-6"/></svg>
  ),
  copy: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
  ),
  deposit: (
    <svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="23" stroke="url(#gd1)" strokeWidth="1.5" strokeDasharray="4 3"/><defs><linearGradient id="gd1" x1="0" y1="0" x2="48" y2="48"><stop stopColor="#9945FF"/><stop offset="1" stopColor="#14F195"/></linearGradient></defs><path d="M24 14v20M17 27l7 7 7-7" stroke="url(#gd1)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
  ),
  transfer: (
    <svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="23" stroke="url(#gd2)" strokeWidth="1.5" strokeDasharray="4 3"/><defs><linearGradient id="gd2" x1="0" y1="0" x2="48" y2="48"><stop stopColor="#9945FF"/><stop offset="1" stopColor="#14F195"/></linearGradient></defs><path d="M14 20h20M30 16l4 4-4 4M34 28H14M18 24l-4 4 4 4" stroke="url(#gd2)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
  ),
  withdraw: (
    <svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="23" stroke="url(#gd3)" strokeWidth="1.5" strokeDasharray="4 3"/><defs><linearGradient id="gd3" x1="0" y1="0" x2="48" y2="48"><stop stopColor="#9945FF"/><stop offset="1" stopColor="#14F195"/></linearGradient></defs><path d="M24 34V14M17 21l7-7 7 7" stroke="url(#gd3)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
  ),
};

// ─── Bowler Hat Logo SVG ─────────────────────────────────────────────
function Logo({ size = 40 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none">
      <defs>
        <linearGradient id="hat-grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#9945FF"/>
          <stop offset="50%" stopColor="#DC1FFF"/>
          <stop offset="100%" stopColor="#14F195"/>
        </linearGradient>
      </defs>
      {/* brim */}
      <ellipse cx="50" cy="72" rx="44" ry="10" fill="url(#hat-grad)"/>
      {/* dome */}
      <path d="M25 72 C25 72 25 30 50 30 C75 30 75 72 75 72" fill="url(#hat-grad)"/>
      {/* band */}
      <rect x="25" y="62" width="50" height="6" rx="2" fill="#0A0A0A" opacity="0.4"/>
    </svg>
  );
}

// ─── Intersection Observer Hook ──────────────────────────────────────
function useInView(threshold = 0.15) {
  const ref = useRef(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setVisible(true); obs.disconnect(); } }, { threshold });
    obs.observe(el);
    return () => obs.disconnect();
  }, [threshold]);
  return [ref, visible];
}

// ─── Animated Counter ────────────────────────────────────────────────
function Counter({ end, suffix = "", prefix = "" }) {
  const [ref, visible] = useInView(0.3);
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!visible) return;
    let start = 0;
    const dur = 1800;
    const step = (ts) => {
      if (!start) start = ts;
      const p = Math.min((ts - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(eased * end));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [visible, end]);
  return <span ref={ref}>{prefix}{val.toLocaleString()}{suffix}</span>;
}

// ─── Section Wrapper ─────────────────────────────────────────────────
function Section({ id, children, style = {}, className = "" }) {
  const [ref, visible] = useInView(0.08);
  return (
    <section
      ref={ref}
      id={id}
      className={className}
      style={{
        maxWidth: 1200,
        margin: "0 auto",
        padding: "100px 24px",
        opacity: visible ? 1 : 0,
        transform: visible ? "translateY(0)" : "translateY(20px)",
        transition: "opacity 0.6s ease-out, transform 0.6s ease-out",
        ...style,
      }}
    >
      {children}
    </section>
  );
}

// ─── Use Case Card ───────────────────────────────────────────────────
const USE_CASES = [
  { icon: "🌍", title: "Family Support", desc: "Send monthly support across borders. No flags, no questions." },
  { icon: "📰", title: "Journalist Protection", desc: "A source funds an investigation. The donation is private." },
  { icon: "💼", title: "Freelancer Privacy", desc: "Invoice clients without broadcasting your rates to competitors." },
  { icon: "💸", title: "Payroll", desc: "Pay a remote team in 12 countries. Each sees only their own salary." },
  { icon: "🤝", title: "Donor Anonymity", desc: "Support causes without exposing yourself to retaliation." },
  { icon: "📊", title: "Tax Compliance", desc: "Share a viewing key with your accountant at year-end. Full audit trail." },
];

function UseCaseCard({ icon, title, desc, delay }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      onClick={() => setOpen(!open)}
      style={{
        background: "var(--bg-secondary)",
        border: `1px solid ${open ? "rgba(153,69,255,0.4)" : "var(--border-subtle)"}`,
        borderRadius: 12,
        padding: 28,
        cursor: "pointer",
        transition: "all 0.25s ease",
        animationDelay: `${delay}ms`,
      }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--border-default)"; e.currentTarget.style.transform = "translateY(-2px)"; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = open ? "rgba(153,69,255,0.4)" : "var(--border-subtle)"; e.currentTarget.style.transform = "translateY(0)"; }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: open ? 12 : 0 }}>
        <span style={{ fontSize: 24 }}>{icon}</span>
        <span style={{ fontWeight: 600, fontSize: 17, flex: 1 }}>{title}</span>
        <span style={{ transform: open ? "rotate(180deg)" : "rotate(0)", transition: "transform 0.2s", color: "var(--text-tertiary)" }}>{Icons.arrow_down}</span>
      </div>
      {open && (
        <p style={{ color: "var(--text-secondary)", fontSize: 14, lineHeight: 1.6, animation: "fadeIn 0.3s ease" }}>{desc}</p>
      )}
    </div>
  );
}

// ─── Code Block ──────────────────────────────────────────────────────
function CodeBlock({ title, lang, code }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const highlight = (src) => {
    if (lang === "rust") {
      return src
        .replace(/(\/\/.+)/g, '<span style="color:#666">$1</span>')
        .replace(/\b(let|fn|use|pub|mut|impl|struct|enum|match|if|else|return|async|await)\b/g, '<span style="color:#9945FF">$1</span>')
        .replace(/"([^"]*)"/g, '<span style="color:#14F195">"$1"</span>')
        .replace(/\b(PrivatePool|Cluster|Denomination|Mainnet|OneSol)\b/g, '<span style="color:#DC1FFF">$1</span>')
        .replace(/(\.\w+)\(/g, '<span style="color:#B066FF">$1</span>(')
        .replace(/(\?|&amp;)/g, '<span style="color:#9945FF">$1</span>');
    }
    return src
      .replace(/(#.+)/g, '<span style="color:#666">$1</span>')
      .replace(/\b(tidex6)\b/g, '<span style="color:#9945FF">$1</span>')
      .replace(/(--\w+)/g, '<span style="color:#14F195">$1</span>')
      .replace(/(&lt;\w+&gt;)/g, '<span style="color:#DC1FFF">$1</span>');
  };

  const escaped = code.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

  return (
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        background: "#161616", borderRadius: "8px 8px 0 0",
        border: "1px solid var(--border-subtle)", borderBottom: "none",
        padding: "10px 16px",
      }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-secondary)" }}>{title}</span>
        <button onClick={handleCopy} style={{
          background: "none", border: "none", color: "var(--text-tertiary)",
          cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontSize: 12,
        }}>
          {copied ? Icons.check : Icons.copy}
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      </div>
      <pre style={{
        background: "var(--bg-tertiary)",
        border: "1px solid var(--border-subtle)",
        borderRadius: "0 0 8px 8px",
        padding: 20,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 13,
        lineHeight: 1.7,
        overflowX: "auto",
        margin: 0,
      }}>
        <code dangerouslySetInnerHTML={{ __html: highlight(escaped) }} />
      </pre>
    </div>
  );
}

// ─── Timeline Milestone ──────────────────────────────────────────────
function Milestone({ label, date, items, done, isLast }) {
  return (
    <div style={{ flex: 1, position: "relative", textAlign: "center", padding: "0 12px" }}>
      {/* connector line */}
      {!isLast && (
        <div style={{
          position: "absolute", top: 12, left: "calc(50% + 16px)", right: "-50%",
          height: 2, background: done ? "var(--color-gradient)" : "var(--border-default)",
          zIndex: 0,
        }} />
      )}
      {/* dot */}
      <div style={{
        width: 24, height: 24, borderRadius: "50%",
        background: done ? "var(--color-gradient)" : "var(--bg-tertiary)",
        border: done ? "none" : "2px solid var(--border-default)",
        margin: "0 auto 16px", position: "relative", zIndex: 1,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        {done && <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
      </div>
      <div style={{
        background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)",
        borderRadius: 12, padding: 20, textAlign: "left",
      }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: done ? "var(--text-success)" : "var(--color-primary)", marginBottom: 4 }}>{label}</div>
        <div style={{ fontSize: 12, color: "var(--text-tertiary)", marginBottom: 10 }}>{date}</div>
        {items.map((it, i) => (
          <div key={i} style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, display: "flex", gap: 6, alignItems: "flex-start" }}>
            <span style={{ color: done ? "var(--text-success)" : "var(--text-tertiary)", flexShrink: 0 }}>
              {done ? "✓" : "○"}
            </span>
            {it}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main App ────────────────────────────────────────────────────────
export default function Tidex6() {
  const [mobileMenu, setMobileMenu] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [walletConnected, setWalletConnected] = useState(false);

  useEffect(() => {
    const s = document.createElement("style");
    s.textContent = GLOBAL_CSS;
    document.head.appendChild(s);
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", handleScroll);
    return () => { document.head.removeChild(s); window.removeEventListener("scroll", handleScroll); };
  }, []);

  const NAV = [
    { label: "How it Works", href: "#how" },
    { label: "Use Cases", href: "#cases" },
    { label: "Developers", href: "#dev" },
    { label: "Roadmap", href: "#roadmap" },
  ];

  const PROGRAM_ID = "TDx6...Prv1m";
  const PROGRAM_ID_FULL = "TDx6wZs1F9bfK4E8VnPrv1m";

  return (
    <div style={{ background: "var(--bg-primary)", minHeight: "100vh", color: "var(--text-primary)" }}>

      {/* ═══ HEADER ═══ */}
      <header style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, height: 72,
        background: scrolled ? "rgba(10,10,10,0.85)" : "rgba(10,10,10,0.6)",
        backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
        borderBottom: `1px solid ${scrolled ? "var(--border-subtle)" : "transparent"}`,
        transition: "all 0.3s ease",
      }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", height: "100%", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 24px" }}>
          {/* Logo */}
          <a href="#" style={{ display: "flex", alignItems: "center", gap: 10, textDecoration: "none", color: "var(--text-primary)" }}>
            <Logo size={36} />
            <span style={{ fontWeight: 700, fontSize: 20, letterSpacing: "-0.02em" }}>tidex6</span>
          </a>

          {/* Desktop Nav */}
          <nav style={{ display: "flex", alignItems: "center", gap: 32 }} className="desktop-nav">
            {NAV.map(n => (
              <a key={n.href} href={n.href} style={{
                color: "var(--text-secondary)", textDecoration: "none", fontSize: 15, fontWeight: 500,
                transition: "color 0.2s",
              }}
              onMouseEnter={e => e.target.style.color = "#fff"}
              onMouseLeave={e => e.target.style.color = "var(--text-secondary)"}
              >{n.label}</a>
            ))}
          </nav>

          {/* Wallet Button */}
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button
              onClick={() => setWalletConnected(!walletConnected)}
              style={{
                background: walletConnected ? "var(--bg-secondary)" : "var(--color-gradient)",
                backgroundSize: "200% 200%",
                color: "#fff", border: walletConnected ? "1px solid var(--border-default)" : "none",
                borderRadius: 8, padding: "9px 20px", fontSize: 14, fontWeight: 600,
                cursor: "pointer", display: "flex", alignItems: "center", gap: 8,
                fontFamily: "'Inter', sans-serif", transition: "all 0.2s ease",
              }}
              onMouseEnter={e => { if (!walletConnected) e.currentTarget.style.filter = "brightness(1.1)"; }}
              onMouseLeave={e => { e.currentTarget.style.filter = "none"; }}
            >
              {walletConnected ? (
                <>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>Cs9F...8n6</span>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--text-success)", display: "inline-block" }} />
                </>
              ) : (
                <>{Icons.wallet}<span>Connect Wallet</span></>
              )}
            </button>

            {/* Mobile toggle */}
            <button onClick={() => setMobileMenu(!mobileMenu)} style={{
              background: "none", border: "none", color: "#fff", cursor: "pointer",
              display: "none", padding: 4,
            }} className="mobile-toggle">
              {mobileMenu ? Icons.close : Icons.menu}
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileMenu && (
          <div style={{
            position: "absolute", top: 72, left: 0, right: 0,
            background: "rgba(10,10,10,0.95)", backdropFilter: "blur(12px)",
            borderBottom: "1px solid var(--border-subtle)", padding: "16px 24px",
          }}>
            {NAV.map(n => (
              <a key={n.href} href={n.href} onClick={() => setMobileMenu(false)} style={{
                display: "block", color: "var(--text-secondary)", textDecoration: "none",
                fontSize: 16, padding: "12px 0", borderBottom: "1px solid var(--border-subtle)",
              }}>{n.label}</a>
            ))}
          </div>
        )}
      </header>

      {/* Responsive CSS */}
      <style>{`
        .desktop-nav { display: flex !important; }
        .mobile-toggle { display: none !important; }
        @media (max-width: 768px) {
          .desktop-nav { display: none !important; }
          .mobile-toggle { display: block !important; }
        }
      `}</style>

      {/* ═══ HERO ═══ */}
      <div style={{
        background: "linear-gradient(135deg, #0A0A0A 0%, #1A0B2E 40%, #0F0520 60%, #0A0A0A 100%)",
        paddingTop: 72, position: "relative", overflow: "hidden",
      }}>
        {/* Glow orbs */}
        <div style={{
          position: "absolute", top: "20%", left: "30%", width: 500, height: 500,
          background: "radial-gradient(circle, rgba(153,69,255,0.12) 0%, transparent 70%)",
          borderRadius: "50%", pointerEvents: "none",
        }} />
        <div style={{
          position: "absolute", top: "40%", right: "20%", width: 400, height: 400,
          background: "radial-gradient(circle, rgba(20,241,149,0.06) 0%, transparent 70%)",
          borderRadius: "50%", pointerEvents: "none",
        }} />

        <div style={{
          maxWidth: 1200, margin: "0 auto", padding: "120px 24px 100px",
          textAlign: "center", position: "relative", zIndex: 1,
        }}>
          <div style={{ animation: "fadeInUp 0.6s ease-out both", animationDelay: "0.1s" }}>
            <Logo size={80} />
          </div>
          <h1 style={{
            fontSize: "clamp(32px, 5vw, 56px)", fontWeight: 700, lineHeight: 1.15,
            letterSpacing: "-0.03em", margin: "32px auto 20px", maxWidth: 700,
            animation: "fadeInUp 0.6s ease-out both", animationDelay: "0.25s",
          }}>
            I grant access,{" "}
            <span style={{
              background: "linear-gradient(90deg, #9945FF, #DC1FFF, #14F195, #DC1FFF, #9945FF)",
              backgroundSize: "300% 100%",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
              animation: "heroGradient 6s ease infinite",
            }}>not permission.</span>
          </h1>
          <p style={{
            fontSize: "clamp(16px, 2vw, 20px)", color: "var(--text-secondary)",
            maxWidth: 520, margin: "0 auto 40px", lineHeight: 1.6,
            animation: "fadeInUp 0.6s ease-out both", animationDelay: "0.4s",
          }}>
            The Rust-native privacy framework for Solana.
          </p>
          <div style={{
            display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap",
            animation: "fadeInUp 0.6s ease-out both", animationDelay: "0.55s",
          }}>
            <button
              onClick={() => setWalletConnected(true)}
              style={{
                background: "var(--color-gradient)", backgroundSize: "200% 200%",
                color: "#fff", border: "none", borderRadius: 8,
                padding: "14px 32px", fontSize: 16, fontWeight: 600,
                cursor: "pointer", fontFamily: "'Inter', sans-serif",
                transition: "all 0.2s ease",
              }}
              onMouseEnter={e => { e.currentTarget.style.filter = "brightness(1.12)"; e.currentTarget.style.transform = "scale(1.02)"; }}
              onMouseLeave={e => { e.currentTarget.style.filter = "none"; e.currentTarget.style.transform = "scale(1)"; }}
            >Connect Wallet</button>
            <a href="https://github.com" target="_blank" rel="noopener noreferrer" style={{
              background: "transparent", color: "var(--text-primary)",
              border: "1px solid var(--border-default)", borderRadius: 8,
              padding: "14px 32px", fontSize: 16, fontWeight: 600,
              cursor: "pointer", textDecoration: "none", display: "inline-flex",
              alignItems: "center", gap: 8, fontFamily: "'Inter', sans-serif",
              transition: "all 0.2s ease",
            }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--color-primary)"; e.currentTarget.style.color = "var(--color-primary)"; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = "var(--border-default)"; e.currentTarget.style.color = "var(--text-primary)"; }}
            >{Icons.github} View on GitHub</a>
          </div>
        </div>
      </div>

      {/* ═══ FEATURES ═══ */}
      <Section id="features">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 24 }}>
          {[
            { icon: Icons.shield, title: "ZK Privacy", desc: "Groth16 proofs hide the sender-receiver link." },
            { icon: Icons.key, title: "Selective Disclosure", desc: "Share a viewing key with your accountant — and only them." },
            { icon: Icons.lock, title: "Non-upgradeable", desc: "Verifier program locked after deploy. No backdoors." },
          ].map((f, i) => (
            <div key={i} style={{
              background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)",
              borderRadius: 12, padding: 32, transition: "all 0.25s ease",
              animation: "fadeInUp 0.5s ease-out both",
              animationDelay: `${i * 0.12}s`,
            }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--border-default)"; e.currentTarget.style.boxShadow = "0 4px 24px rgba(153,69,255,0.06)"; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = "var(--border-subtle)"; e.currentTarget.style.boxShadow = "none"; }}
            >
              <div style={{ marginBottom: 16 }}>{f.icon}</div>
              <h3 style={{ fontSize: 20, fontWeight: 600, marginBottom: 8, letterSpacing: "-0.01em" }}>{f.title}</h3>
              <p style={{ color: "var(--text-secondary)", fontSize: 15, lineHeight: 1.6 }}>{f.desc}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* ═══ STATS BAR ═══ */}
      <div style={{
        borderTop: "1px solid var(--border-subtle)",
        borderBottom: "1px solid var(--border-subtle)",
        background: "var(--bg-secondary)",
      }}>
        <div style={{
          maxWidth: 1200, margin: "0 auto", padding: "28px 24px",
          display: "flex", flexWrap: "wrap", justifyContent: "center",
          gap: "24px 48px",
        }}>
          {[
            { label: "Program ID", value: PROGRAM_ID, mono: true, link: true },
            { label: "Network", value: "Mainnet" },
            { label: "Security.txt", value: "Verified", green: true },
            { label: "Powered by", value: "Helius RPC" },
          ].map((s, i) => (
            <div key={i} style={{ textAlign: "center", minWidth: 120 }}>
              <div style={{ fontSize: 11, fontWeight: 500, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6 }}>{s.label}</div>
              <div style={{
                fontSize: 14, fontWeight: 600,
                fontFamily: s.mono ? "'JetBrains Mono', monospace" : "'Inter', sans-serif",
                color: s.green ? "var(--text-success)" : "var(--text-primary)",
                cursor: s.link ? "pointer" : "default",
                display: "flex", alignItems: "center", gap: 4, justifyContent: "center",
              }}>
                {s.green && <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--text-success)", display: "inline-block" }} />}
                {s.value}
                {s.link && <span style={{ color: "var(--text-tertiary)" }}>{Icons.copy}</span>}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ═══ HOW IT WORKS ═══ */}
      <Section id="how">
        <h2 style={{ fontSize: "clamp(28px, 4vw, 36px)", fontWeight: 600, letterSpacing: "-0.02em", marginBottom: 64, textAlign: "center" }}>
          How it Works
        </h2>
        <div style={{ display: "flex", flexDirection: "column", gap: 48, maxWidth: 800, margin: "0 auto" }}>
          {[
            { step: "01", icon: Icons.deposit, title: "DEPOSIT", desc: "Lena sends SOL into the shielded pool. On-chain: only a commitment hash." },
            { step: "02", icon: Icons.transfer, title: "TRANSFER NOTE", desc: "The note file travels offchain. Signal, email, QR — any channel." },
            { step: "03", icon: Icons.withdraw, title: "WITHDRAW", desc: "The recipient presents a ZK proof and claims the SOL. No link to the sender." },
          ].map((s, i) => (
            <div key={i} style={{
              display: "flex", gap: 32, alignItems: "flex-start",
              animation: `${i % 2 === 0 ? "slideInLeft" : "slideInRight"} 0.5s ease-out both`,
            }}>
              <div style={{ flexShrink: 0 }}>{s.icon}</div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--color-primary)", letterSpacing: "0.1em", marginBottom: 6 }}>STEP {s.step}</div>
                <h3 style={{ fontSize: 22, fontWeight: 600, marginBottom: 8, letterSpacing: "-0.01em" }}>{s.title}</h3>
                <p style={{ color: "var(--text-secondary)", fontSize: 15, lineHeight: 1.6 }}>{s.desc}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Comparison Panel */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 24, marginTop: 80 }}>
          <div style={{
            background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)",
            borderRadius: 12, padding: 28, position: "relative", overflow: "hidden",
          }}>
            <div style={{
              position: "absolute", top: 0, left: 0, right: 0, height: 3,
              background: "var(--text-error)", opacity: 0.6,
            }} />
            <h4 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-tertiary)", letterSpacing: "0.06em", marginBottom: 20, textTransform: "uppercase" }}>What Solscan sees</h4>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, lineHeight: 2, color: "var(--text-secondary)" }}>
              <div>Hash: <span style={{ color: "var(--text-tertiary)" }}>7Fk2...Xe9p</span></div>
              <div>Tx: <span style={{ color: "var(--text-tertiary)" }}>2iHT...qeVM</span></div>
              <div>Sender: <span style={{ color: "var(--text-tertiary)" }}>???</span></div>
              <div>Amount: <span style={{ color: "var(--text-tertiary)" }}>???</span></div>
              <div>Recipient: <span style={{ color: "var(--text-tertiary)" }}>???</span></div>
            </div>
          </div>
          <div style={{
            background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)",
            borderRadius: 12, padding: 28, position: "relative", overflow: "hidden",
          }}>
            <div style={{
              position: "absolute", top: 0, left: 0, right: 0, height: 3,
              background: "var(--text-success)", opacity: 0.6,
            }} />
            <h4 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-tertiary)", letterSpacing: "0.06em", marginBottom: 20, textTransform: "uppercase" }}>What the accountant sees</h4>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, lineHeight: 2, color: "var(--text-secondary)" }}>
              <div>Date: <span style={{ color: "#fff" }}>2026-04-10</span></div>
              <div>Sender: <span style={{ color: "#fff" }}>Lena K.</span></div>
              <div>Amount: <span style={{ color: "var(--text-success)" }}>1.0 SOL</span></div>
              <div>Memo: <span style={{ color: "#fff" }}>April rent</span></div>
              <div>Status: <span style={{ color: "var(--text-success)" }}>Confirmed</span></div>
            </div>
          </div>
        </div>
      </Section>

      {/* ═══ USE CASES ═══ */}
      <Section id="cases">
        <h2 style={{ fontSize: "clamp(28px, 4vw, 36px)", fontWeight: 600, letterSpacing: "-0.02em", marginBottom: 48, textAlign: "center" }}>
          Use Cases
        </h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 16, maxWidth: 900, margin: "0 auto" }}>
          {USE_CASES.map((c, i) => (
            <UseCaseCard key={i} {...c} delay={i * 80} />
          ))}
        </div>
      </Section>

      {/* ═══ DEVELOPERS ═══ */}
      <Section id="dev">
        <h2 style={{ fontSize: "clamp(28px, 4vw, 36px)", fontWeight: 600, letterSpacing: "-0.02em", marginBottom: 48, textAlign: "center" }}>
          Developers
        </h2>
        <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
          <CodeBlock
            title="SDK — Rust"
            lang="rust"
            code={`let pool = PrivatePool::connect(
    Cluster::Mainnet,
    Denomination::OneSol,
)?;

let (sig, note, _) = pool
    .deposit(&wallet)
    .send()?;

let sig = pool
    .withdraw(&wallet)
    .note(note)
    .to(recipient)
    .send()?;`}
          />
          <CodeBlock
            title="CLI — bash"
            lang="bash"
            code={`# Generate keypair
tidex6 keygen

# Deposit into shielded pool
tidex6 deposit --amount 0.1

# Withdraw to recipient
tidex6 withdraw \\
  --note parents.note \\
  --to <pubkey>`}
          />
        </div>

        {/* Dev Links */}
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 40, justifyContent: "center" }}>
          {[
            { label: "GitHub", href: "#" },
            { label: "SDK Reference", href: "#" },
            { label: "Security Policy", href: "#" },
            { label: "Solscan Program", href: "#" },
          ].map((l, i) => (
            <a key={i} href={l.href} style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              color: "var(--text-primary)", textDecoration: "none",
              border: "1px solid var(--border-default)", borderRadius: 8,
              padding: "10px 20px", fontSize: 14, fontWeight: 500,
              transition: "all 0.2s ease",
            }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--color-primary)"; e.currentTarget.style.color = "var(--color-primary)"; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = "var(--border-default)"; e.currentTarget.style.color = "var(--text-primary)"; }}
            >{l.label} {Icons.external}</a>
          ))}
        </div>
      </Section>

      {/* ═══ ROADMAP ═══ */}
      <Section id="roadmap">
        <h2 style={{ fontSize: "clamp(28px, 4vw, 36px)", fontWeight: 600, letterSpacing: "-0.02em", marginBottom: 64, textAlign: "center" }}>
          Roadmap
        </h2>
        <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
          <Milestone
            label="MVP"
            date="April 2026"
            done={true}
            items={["Shielded pool", "ZK withdraw", "CLI & SDK", "Mainnet deploy"]}
          />
          <Milestone
            label="v0.2"
            date="Q3 2026"
            done={false}
            items={["Viewing keys (ElGamal)", "Shielded memos", "Audit", "Web UI v2"]}
          />
          <Milestone
            label="v0.3"
            date="Q4 2026"
            done={false}
            isLast={true}
            items={["Confidential amounts", "Token-2022 CT", "Shared anonymity pool"]}
          />
        </div>
      </Section>

      {/* ═══ FOOTER ═══ */}
      <footer style={{
        borderTop: "1px solid var(--border-subtle)",
        background: "var(--bg-secondary)",
      }}>
        <div style={{
          maxWidth: 1200, margin: "0 auto", padding: "48px 24px 32px",
        }}>
          <div style={{
            display: "flex", flexWrap: "wrap", justifyContent: "space-between",
            alignItems: "flex-start", gap: 32, marginBottom: 32,
          }}>
            {/* Left */}
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                <Logo size={28} />
                <span style={{ fontWeight: 700, fontSize: 18 }}>tidex6</span>
              </div>
              <p style={{ color: "var(--text-tertiary)", fontSize: 14, fontStyle: "italic" }}>I grant access, not permission.</p>
            </div>

            {/* Center */}
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 11, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Program ID</div>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: 13,
                color: "var(--text-secondary)", cursor: "pointer",
                display: "flex", alignItems: "center", gap: 6,
              }}>
                {PROGRAM_ID_FULL} {Icons.external}
              </div>
              <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 4, justifyContent: "center" }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--text-success)", display: "inline-block" }} />
                <span style={{ fontSize: 12, color: "var(--text-success)" }}>Security.txt Verified</span>
              </div>
            </div>

            {/* Right */}
            <div style={{ display: "flex", gap: 20 }}>
              {["GitHub", "Solscan", "License"].map(l => (
                <a key={l} href="#" style={{
                  color: "var(--text-tertiary)", textDecoration: "none", fontSize: 14,
                  transition: "color 0.2s",
                }}
                  onMouseEnter={e => e.target.style.color = "#fff"}
                  onMouseLeave={e => e.target.style.color = "var(--text-tertiary)"}
                >{l}</a>
              ))}
            </div>
          </div>

          {/* Bottom bar */}
          <div style={{
            borderTop: "1px solid var(--border-subtle)", paddingTop: 20,
            display: "flex", flexWrap: "wrap", justifyContent: "center",
            alignItems: "center", gap: 20, fontSize: 12, color: "var(--text-tertiary)",
          }}>
            <a href="https://helius.dev" target="_blank" rel="noopener noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              color: "var(--text-tertiary)", textDecoration: "none", transition: "color 0.2s",
            }}
              onMouseEnter={e => e.currentTarget.style.color = "#FF8C00"}
              onMouseLeave={e => e.currentTarget.style.color = "var(--text-tertiary)"}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="5" fill="currentColor"/>
                {[0,45,90,135,180,225,270,315].map(a => (
                  <line key={a} x1="12" y1="2" x2="12" y2="5"
                    stroke="currentColor" strokeWidth="2" strokeLinecap="round"
                    transform={`rotate(${a} 12 12)`}/>
                ))}
              </svg>
              Helius RPC
            </a>
            <span style={{ opacity: 0.2 }}>|</span>
            <a href="https://claude.ai" target="_blank" rel="noopener noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              color: "var(--text-tertiary)", textDecoration: "none", transition: "color 0.2s",
            }}
              onMouseEnter={e => e.currentTarget.style.color = "#D4A574"}
              onMouseLeave={e => e.currentTarget.style.color = "var(--text-tertiary)"}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M16.1 2.96l-4.44 14.6L7.76 5.52a.5.5 0 0 0-.94-.02L3.7 13.76a.5.5 0 0 0 .46.74h4.18M16.1 2.96a.5.5 0 0 1 .96.08l3.22 12.48a.5.5 0 0 1-.48.62h-4.12"/>
              </svg>
              Claude
            </a>
            <span style={{ opacity: 0.2 }}>|</span>
            <a href="https://docs.anthropic.com/en/docs/claude-code" target="_blank" rel="noopener noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              color: "var(--text-tertiary)", textDecoration: "none", transition: "color 0.2s",
            }}
              onMouseEnter={e => e.currentTarget.style.color = "#D4A574"}
              onMouseLeave={e => e.currentTarget.style.color = "var(--text-tertiary)"}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="4 17 10 11 4 5"/>
                <line x1="12" y1="19" x2="20" y2="19"/>
              </svg>
              Claude Code
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
