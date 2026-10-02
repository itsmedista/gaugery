// The one gauge used across Gaugery (styles in gauge.css).
//   Gauge.html({id, label, sub, frac})  markup; frac (0..1) is the starting fill
//   Gauge.set(el, {frac, level, num, unit, sub, title})  update in place; the fill animates
//   Gauge.level(frac, [warn, crit])  'ok' | 'warn' | 'crit' for the fill color
const Gauge = (() => {
  const R = 46, CIRC = 2 * Math.PI * R, ARC = CIRC * .75;
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const dash = f => `${Math.max(.001, ARC * Math.min(1, Math.max(0, f || 0)))} ${CIRC}`;

  function html({id = '', label, sub = '', frac = 0, level = 'ok'}) {
    return `<div class="gauge" data-lvl="${level}"${id ? ` id="${esc(id)}"` : ''}>
      <svg viewBox="0 0 120 108" aria-hidden="true">
        <circle class="trk" cx="60" cy="58" r="${R}" stroke-dasharray="${ARC} ${CIRC}" transform="rotate(135 60 58)"/>
        <circle class="val" cx="60" cy="58" r="${R}" stroke-dasharray="${dash(frac)}" transform="rotate(135 60 58)"/>
        <text class="gv" x="60" y="61">–</text><text class="gu" x="60" y="77"></text>
      </svg>
      <div class="glabel">${esc(label)}</div>${sub === null ? '' : `<div class="gsub">${esc(sub)}</div>`}
    </div>`;
  }

  function set(el, {frac, level = 'ok', num = '–', unit = '', sub, title}) {
    el.dataset.lvl = level;
    el.querySelector('.val').setAttribute('stroke-dasharray', dash(frac));
    el.querySelector('.gv').textContent = num;
    el.querySelector('.gu').textContent = unit;
    const s = el.querySelector('.gsub'); if (s && sub !== undefined) s.textContent = sub;
    if (title) el.title = title;
  }

  const level = (f, th = [.7, .9]) => f >= th[1] ? 'crit' : f >= th[0] ? 'warn' : 'ok';
  return {html, set, level};
})();
