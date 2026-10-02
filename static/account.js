// Your settings on every page: theme, accent, language, formats, and the account menu (top right).
// Loaded in <head>, after i18n.js, so the theme and language are right before the page draws.
(() => {
  const DEFAULTS = {theme: 'dark', accent: 'teal', lang: '', time_format: '24h', temp_unit: 'C', default_range: 'live', start_page: 'overview'};
  const CACHE = 'gaugery.prefs';   // only look-and-feel is remembered in the browser, never your name or email
  const root = document.documentElement;
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  let cached = {};
  try { cached = JSON.parse(localStorage.getItem(CACHE)) || {}; } catch { /* private window: defaults */ }

  const M = window.Gaugery = {me: null, prefs: {...DEFAULTS, ...cached}};
  const dark = matchMedia('(prefers-color-scheme: light)');

  function applyLook(p) {
    root.dataset.theme = p.theme === 'system' ? (dark.matches ? 'light' : 'dark') : p.theme;
    root.dataset.accent = p.accent;
    window.dispatchEvent(new CustomEvent('gaugery:theme'));
  }
  dark.addEventListener('change', () => { if (M.prefs.theme === 'system') applyLook(M.prefs); });
  applyLook(M.prefs);
  I18N.setLang(M.prefs.lang);

  // ---------- formats that follow your settings ----------
  const pad2 = n => String(n).padStart(2, '0');
  M.fmtClock = (t, secs = true) => {
    const d = new Date(t * 1000), s = secs ? ':' + pad2(d.getSeconds()) : '';
    if (M.prefs.time_format === '12h') {
      const h = d.getHours() % 12 || 12;
      return `${h}:${pad2(d.getMinutes())}${s} ${d.getHours() < 12 ? 'AM' : 'PM'}`;
    }
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}${s}`;
  };
  M.temp = c => (c == null ? null : M.prefs.temp_unit === 'F' ? c * 9 / 5 + 32 : c);   // readings are °C
  M.tempUnit = () => (M.prefs.temp_unit === 'F' ? '°F' : '°C');
  M.fmtTemp = c => (c == null ? '–' : Math.round(M.temp(c)) + M.tempUnit());
  M.save = p => { try { localStorage.setItem(CACHE, JSON.stringify({theme: p.theme, accent: p.accent, lang: p.lang, time_format: p.time_format, temp_unit: p.temp_unit, default_range: p.default_range})); } catch { /* not saved */ } };

  // ---------- avatars ----------
  const PRESETS = [
    ['#35D0BA', '#0B3B35', 'rings'], ['#4FA8FF', '#0B2A4A', 'wave'], ['#A08CFF', '#2A1F5C', 'diamond'], ['#F5B942', '#4A3300', 'sun'],
    ['#FF6F91', '#4A0F22', 'bolt'], ['#A5D65C', '#253B0B', 'leaf'], ['#62E0E8', '#0B3A3D', 'grid'], ['#FF9955', '#4A2000', 'peak'],
    ['#D58CFF', '#3A1050', 'orbit'], ['#7FC4FF', '#0E2E4F', 'server'], ['#F7D774', '#453800', 'star'], ['#FFB3C7', '#4F1B2A', 'heart'],
  ];
  const SHAPES = {
    rings: '<circle cx="32" cy="32" r="14" fill="none" stroke="F" stroke-width="5"/><circle cx="32" cy="32" r="4" fill="F"/>',
    wave: '<path d="M10 36c6-8 10-8 16 0s10 8 16 0 10-8 12-4" fill="none" stroke="F" stroke-width="5" stroke-linecap="round"/>',
    diamond: '<path d="M32 12 50 32 32 52 14 32z" fill="F"/>',
    sun: '<circle cx="32" cy="32" r="10" fill="F"/><path d="M32 10v7M32 47v7M10 32h7M47 32h7M16.5 16.5l5 5M42.5 42.5l5 5M47.5 16.5l-5 5M21.5 42.5l-5 5" stroke="F" stroke-width="4" stroke-linecap="round"/>',
    bolt: '<path d="M36 10 18 36h12l-4 18 20-28H34z" fill="F"/>',
    leaf: '<path d="M16 46C16 24 30 14 50 14c0 22-12 34-34 32zM18 44 38 26" fill="F" stroke="B" stroke-width="3"/>',
    grid: '<g fill="F"><rect x="15" y="15" width="14" height="14" rx="3"/><rect x="35" y="15" width="14" height="14" rx="3"/><rect x="15" y="35" width="14" height="14" rx="3"/><rect x="35" y="35" width="14" height="14" rx="7"/></g>',
    peak: '<path d="M8 48 24 22l10 14 8-10 14 22z" fill="F"/>',
    orbit: '<ellipse cx="32" cy="32" rx="20" ry="9" fill="none" stroke="F" stroke-width="4" transform="rotate(-30 32 32)"/><circle cx="32" cy="32" r="7" fill="F"/>',
    server: '<g fill="F"><rect x="16" y="14" width="32" height="10" rx="3"/><rect x="16" y="27" width="32" height="10" rx="3"/><rect x="16" y="40" width="32" height="10" rx="3"/></g><g fill="B"><circle cx="22" cy="19" r="2"/><circle cx="22" cy="32" r="2"/><circle cx="22" cy="45" r="2"/></g>',
    star: '<path d="m32 11 6.2 13.6 14.8 1.7-11 10 3 14.7L32 43.6 19 51l3-14.7-11-10 14.8-1.7z" fill="F"/>',
    heart: '<path d="M32 50S12 38 12 25c0-7 5-11 10.5-11 4.3 0 7.4 2.5 9.5 6 2.1-3.5 5.2-6 9.5-6C47 14 52 18 52 25c0 13-20 25-20 25z" fill="F"/>',
  };
  M.presetSVG = i => {
    const [fg, bg, shape] = PRESETS[i - 1];
    return `<svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" fill="${bg}"/>${SHAPES[shape].replaceAll('"F"', `"${fg}"`).replaceAll('"B"', `"${bg}"`)}</svg>`;
  };
  M.presetCount = PRESETS.length;
  function initials(me) {
    const name = (me.display_name || me.user || '?').trim();
    const parts = name.split(/\s+/).filter(Boolean);
    return ((parts[0] || '?')[0] + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
  }
  function hue(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360; return h; }
  M.avatarHTML = (me, size = 30) => {
    const dims = `width:${size}px;height:${size}px;font-size:${Math.round(size * .4)}px`;
    const box = `class="avatar" style="${dims}"`;
    if (me.avatar === 'upload' && me.avatar_version) return `<span ${box}><img src="api/me/avatar?v=${me.avatar_version}" alt=""></span>`;
    const m = /^p(\d+)$/.exec(me.avatar || '');
    if (m && +m[1] >= 1 && +m[1] <= PRESETS.length) return `<span ${box}>${M.presetSVG(+m[1])}</span>`;
    return `<span class="avatar" style="${dims};background:hsl(${hue(me.user || '')} 45% 42%)">${esc(initials(me))}</span>`;
  };

  // ---------- the account menu (top right) ----------
  const ICON = {
    gear: '<circle cx="8" cy="8" r="2.2"/><path d="M8 1.8v1.6M8 12.6v1.6M1.8 8h1.6M12.6 8h1.6M3.6 3.6l1.1 1.1M11.3 11.3l1.1 1.1M3.6 12.4l1.1-1.1M11.3 4.7l1.1-1.1"/>',
    out: '<path d="M6 2.5H3.5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1H6M10.5 11 13.5 8l-3-3M13.5 8H6"/>',
    grid: '<rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/>',
  };
  const svg = d => `<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
  M.signOut = async () => {
    await fetch('api/logout', {method: 'POST'}).catch(() => {});
    location.href = 'login.html';
  };
  function renderAccount() {
    const host = document.getElementById('account');
    if (!host || !M.me) return;
    const me = M.me, name = me.display_name || me.user;
    host.innerHTML = `<button type="button" aria-haspopup="menu" aria-expanded="false" title="${esc(t('Your account'))}">${M.avatarHTML(me, 28)}<span class="nm">${esc(name)}</span></button>
      <div class="acct-menu" role="menu" hidden>
        <div class="who">${M.avatarHTML(me, 38)}<div><b>${esc(name)}</b><span>${esc(me.email || me.user)}</span></div></div>
        <a role="menuitem" href="./">${svg(ICON.grid)}${esc(t('All servers'))}</a>
        <a role="menuitem" href="settings.html">${svg(ICON.gear)}${esc(t('Settings'))}</a>
        <button role="menuitem" type="button" data-signout>${svg(ICON.out)}${esc(t('Sign out'))}</button>
      </div>`;
    const btn = host.querySelector('button'), menu = host.querySelector('.acct-menu');
    // Lives in <body>, not the header: the header's frosted-glass effect (backdrop-filter) makes it
    // its own layer, which would trap the menu underneath the page on narrow screens.
    document.querySelectorAll('body > .acct-menu').forEach(m => m.remove());
    document.body.appendChild(menu);
    const close = () => { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
    // just below the avatar, right-aligned with it, but always fully on screen
    const place = () => {
      const r = btn.getBoundingClientRect(), w = menu.offsetWidth, h = menu.offsetHeight;
      menu.style.left = Math.max(8, Math.min(r.right - w, innerWidth - w - 8)) + 'px';
      menu.style.top = Math.max(8, Math.min(r.bottom + 8, innerHeight - h - 8)) + 'px';
    };
    btn.onclick = () => {
      menu.hidden = !menu.hidden; btn.setAttribute('aria-expanded', String(!menu.hidden));
      if (!menu.hidden) { place(); menu.querySelector('a').focus({preventScroll: true}); }
    };
    addEventListener('resize', () => { if (!menu.hidden) place(); });
    addEventListener('scroll', () => { if (!menu.hidden) close(); }, {passive: true});
    menu.querySelector('[data-signout]').onclick = M.signOut;
    document.addEventListener('pointerdown', e => { if (!host.contains(e.target) && !menu.contains(e.target)) close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !menu.hidden) { close(); btn.focus(); } });
  }

  // ---------- load your settings from the hub ----------
  M.ready = fetch('api/me', {cache: 'no-store'}).then(r => (r.ok ? r.json() : null)).then(me => {
    if (!me) return null;
    const langBefore = I18N.lang;
    M.me = me;
    M.prefs = {...DEFAULTS, ...me.prefs};
    M.save(M.prefs);
    applyLook(M.prefs);
    I18N.setLang(M.prefs.lang);
    if (I18N.lang !== langBefore) { location.reload(); return me; }   // text was drawn in another language
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', renderAccount); else renderAccount();
    return me;
  }).catch(() => null);
  M.refresh = me => { M.me = me; M.prefs = {...DEFAULTS, ...me.prefs}; M.save(M.prefs); applyLook(M.prefs); renderAccount(); };
  document.addEventListener('DOMContentLoaded', () => I18N.apply());
})();
