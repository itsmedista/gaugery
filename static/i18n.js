// Interface translations. The English text is the key, so anything not translated shows in English.
//   t('Sign out')  ·  t('{n} of {total} up', {n, total})
//   <h2 data-i18n>Services</h2>                   the element's own text is translated
//   <input data-i18n-attr="placeholder,title">    those attributes are translated
(() => {
  const LANGS = {en: 'English', fr: 'Français', es: 'Español', de: 'Deutsch'};
  const LOCALES = {en: 'en-GB', fr: 'fr-FR', es: 'es-ES', de: 'de-DE'};
  const DICT = window.MONITORR_DICT || {};
  let lang = 'en';

  function setLang(l) {
    const browser = (navigator.language || 'en').slice(0, 2).toLowerCase();
    lang = LANGS[l] ? l : LANGS[browser] ? browser : 'en';
    document.documentElement.lang = lang;
  }

  function t(s, vars) {
    let out = (lang !== 'en' && DICT[lang] && DICT[lang][s]) || s;
    if (vars) out = out.replace(/\{(\w+)\}/g, (m, k) => (vars[k] ?? m));
    return out;
  }

  // Translate one element's own words, keeping icons and badges inside it.
  function translateText(el) {
    const node = [...el.childNodes].find(n => n.nodeType === 3 && n.nodeValue.trim());
    if (!el.dataset.i18n) el.dataset.i18n = (node ? node.nodeValue : el.textContent).trim();
    const text = t(el.dataset.i18n);
    if (node) node.nodeValue = node.nodeValue.replace(node.nodeValue.trim(), text);
    else el.textContent = text;
  }

  function apply(root = document) {
    root.querySelectorAll('[data-i18n]').forEach(translateText);
    root.querySelectorAll('[data-i18n-attr]').forEach(el => {
      for (const a of el.dataset.i18nAttr.split(',')) {
        const key = el.getAttribute('data-i18n-' + a) || el.getAttribute(a);
        if (!key) continue;
        el.setAttribute('data-i18n-' + a, key);
        el.setAttribute(a, t(key));
      }
    });
  }

  window.I18N = {LANGS, setLang, t, apply, get lang() { return lang; }, get locale() { return LOCALES[lang]; }};
  window.t = t;
  setLang('');
})();
