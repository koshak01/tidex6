/**
 * tidex6.com — vanilla JS
 * =======================
 * No frameworks. No build step. Just works.
 */

/* ── Mobile menu ──────────────────────────────────── */

function toggleMobileMenu() {
    const nav = document.getElementById('mobile-nav');
    nav.classList.toggle('open');
}

function closeMobileMenu() {
    const nav = document.getElementById('mobile-nav');
    nav.classList.remove('open');
}

/* ── Wallet connect (Phantom adapter) ─────────────── */

async function connectWallet() {
    const btn = document.getElementById('wallet-btn');

    if (window.solana && window.solana.isPhantom) {
        try {
            const resp = await window.solana.connect();
            const pubkey = resp.publicKey.toString();
            const short = pubkey.slice(0, 4) + '...' + pubkey.slice(-4);

            // Clear existing content and build new elements safely
            btn.textContent = '';
            const dot = document.createElement('span');
            dot.className = 'dot';
            btn.appendChild(dot);
            btn.appendChild(document.createTextNode(' ' + short));
            btn.classList.add('connected');
        } catch (err) {
            console.error('Wallet connect failed:', err);
        }
    } else {
        window.open('https://phantom.app/', '_blank');
    }
}

/* ── Code copy button ─────────────────────────────── */

function copyCode(el) {
    const pre = el.closest('.code-block').querySelector('pre');
    const text = pre.innerText;
    navigator.clipboard.writeText(text).then(function() {
        el.textContent = 'Copied!';
        setTimeout(function() { el.textContent = 'Copy'; }, 2000);
    });
}

/* ── Smooth scroll for nav links ──────────────────── */

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('a[href^="/#"]').forEach(function(link) {
        link.addEventListener('click', function(e) {
            const href = link.getAttribute('href').replace('/', '');
            const target = document.querySelector(href);
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                closeMobileMenu();
            }
        });
    });
});
