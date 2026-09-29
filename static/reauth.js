// Sensitive changes (servers, service checks, container actions, two-factor) need your password
// from the last 15 minutes. When the hub answers {"reauth": true}, ask for it here and repeat the
// request, so every page and button gets this without extra code.
(() => {
  const plainFetch = window.fetch.bind(window);
  const tr = (s, v) => (window.t ? window.t(s, v) : s);
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  let asking = null;  // one prompt at a time, shared by requests that need it together

  function ask() {
    if (asking) return asking;
    asking = new Promise(async resolve => {
      let totp = false;
      try { totp = (await (await plainFetch('api/auth-config')).json()).totp; } catch { /* ask for the password only */ }
      const d = document.createElement('dialog');
      d.innerHTML = `<form method="dialog">
        <h2>${esc(tr("Confirm it's you"))}</h2>
        <p class="hint">${esc(tr('Changes like this need your password from the last 15 minutes.'))}</p>
        <label for="ra-pw">${esc(tr('Password'))}</label>
        <input id="ra-pw" type="password" autocomplete="current-password" required>
        ${totp ? `<label for="ra-code">${esc(tr('Code from your authenticator app, or a recovery code'))}</label>
        <input id="ra-code" autocomplete="one-time-code" maxlength="12" required>` : ''}
        <p class="err" role="alert"></p>
        <div class="row"><button type="button" class="btn" data-cancel>${esc(tr('Cancel'))}</button><button class="btn primary">${esc(tr('Confirm'))}</button></div>
      </form>`;
      document.body.appendChild(d);
      const finish = ok => { d.close(); d.remove(); asking = null; resolve(ok); };
      d.querySelector('[data-cancel]').onclick = () => finish(false);
      d.addEventListener('cancel', e => { e.preventDefault(); finish(false); });
      d.querySelector('form').addEventListener('submit', async e => {
        e.preventDefault();
        const r = await plainFetch('api/reauth', {method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({password: d.querySelector('#ra-pw').value, code: d.querySelector('#ra-code')?.value || ''})});
        if (r.ok) return finish(true);
        d.querySelector('.err').textContent = tr((await r.json().catch(() => ({}))).detail || "That didn't work");
      });
      d.showModal();
      d.querySelector('#ra-pw').focus();
    });
    return asking;
  }

  window.fetch = async (input, init) => {
    const r = await plainFetch(input, init);
    if (r.status !== 403) return r;
    const j = await r.clone().json().catch(() => null);
    if (!j || !j.reauth) return r;
    return (await ask()) ? plainFetch(input, init) : r;
  };
})();
