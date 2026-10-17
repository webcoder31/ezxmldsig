/*
 * Interface of the ezxmldsig demo.
 *
 * Every value that comes from the server or from a token is written with
 * textContent or as an attribute value: the page never builds markup from a
 * string. The tokens are created, analyzed and attacked by the PHP side
 * (demo/src/); this script only displays them.
 */
(function () {
  'use strict';

  /* ---------- Helpers ---------- */

  function $(id) {
    return document.getElementById(id);
  }

  /**
   * Creates an element. props: class, text, attrs (attributes), data
   * (dataset), on (event listeners). Children: nodes or strings (text).
   */
  function el(tag, props, children) {
    const node = document.createElement(tag);
    props = props || {};
    if (props.class) node.className = props.class;
    if (props.text !== undefined && props.text !== null) node.textContent = String(props.text);
    if (props.attrs) {
      Object.keys(props.attrs).forEach(function (name) {
        const value = props.attrs[name];
        if (value !== false && value !== null && value !== undefined) node.setAttribute(name, value === true ? '' : String(value));
      });
    }
    if (props.data) {
      Object.keys(props.data).forEach(function (name) { node.dataset[name] = props.data[name]; });
    }
    if (props.on) {
      Object.keys(props.on).forEach(function (name) { node.addEventListener(name, props.on[name]); });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined || child === false) return;
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
  }

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    return svg;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function chip(text, kind, iconName) {
    return el('span', { class: 'chip' + (kind ? ' chip-' + kind : '') }, [iconName ? icon(iconName) : null, text]);
  }

  function debounce(fn, delay) {
    let timer = null;
    return function () {
      const args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(null, args); }, delay);
    };
  }

  const reducedMotion = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : { matches: false };

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, reducedMotion.matches ? 0 : ms); });
  }

  function formatBytes(n) {
    return n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB';
  }

  function formatNumber(n) {
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  /** Decodes base64 holding UTF-8 text; NULL if it is not. */
  function decodeBase64Utf8(value) {
    try {
      const binary = atob(value.replace(/\s+/g, ''));
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (e) {
      return null;
    }
  }

  function base64Length(value) {
    const clean = value.replace(/\s+/g, '');
    const padding = (clean.match(/=+$/) || [''])[0].length;
    return Math.floor(clean.length * 3 / 4) - padding;
  }

  let toastTimer = null;
  function toast(message) {
    const node = $('toast');
    node.textContent = message;
    node.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { node.hidden = true; }, 2200);
  }

  function copyText(text, what) {
    function done() { toast(what + ' copied to the clipboard.'); }
    function fallback() {
      const area = el('textarea', { attrs: { readonly: true, 'aria-hidden': 'true' } });
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand('copy');
        done();
      } catch (e) {
        toast('Copy failed: select the text and copy it.');
      }
      document.body.removeChild(area);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  }

  async function api(path, body) {
    const init = body === undefined
      ? { method: 'GET' }
      : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    let response;
    try {
      response = await fetch(path, init);
    } catch (e) {
      throw new Error('The demo server does not answer. Is bin/demo still running?');
    }
    let payload = null;
    try {
      payload = await response.json();
    } catch (e) {
      throw new Error('Unexpected answer from the server (HTTP ' + response.status + ').');
    }
    if (!response.ok) throw new Error(payload && payload.error ? payload.error : 'HTTP ' + response.status);
    return payload;
  }

  /* ---------- State ---------- */

  const state = {
    config: null,
    token: null,          // { xml, encrypted, algorithms, data, edited }
    verified: null,       // { xml, result }
    fullValues: false,
    editing: false,
    tree: null,
    activeId: null,
    pinnedId: null,
    labResults: {}
  };

  /* ---------- Theme ---------- */

  const THEMES = ['auto', 'dark', 'light'];
  const THEME_LABELS = { auto: 'automatic', dark: 'dark', light: 'light' };
  const THEME_ICONS = { auto: 'auto', dark: 'moon', light: 'sun' };

  function readStoredTheme() {
    try {
      const value = localStorage.getItem('ezxmldsig-demo-theme');
      return THEMES.indexOf(value) >= 0 ? value : 'auto';
    } catch (e) {
      return 'auto';
    }
  }

  function applyTheme(theme) {
    if (theme === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    const button = $('theme-toggle');
    button.setAttribute('aria-label', 'Color theme: ' + THEME_LABELS[theme] + '. Change it.');
    button.title = 'Theme: ' + THEME_LABELS[theme];
    clear(button);
    button.appendChild(icon(THEME_ICONS[theme]));
  }

  function initTheme() {
    let theme = readStoredTheme();
    applyTheme(theme);
    $('theme-toggle').addEventListener('click', function () {
      theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
      applyTheme(theme);
      try { localStorage.setItem('ezxmldsig-demo-theme', theme); } catch (e) { /* not kept */ }
    });
  }

  /* ---------- Algorithms ---------- */

  function fillSelect(select, option) {
    const choices = state.config.algorithms[option];
    clear(select);
    Object.keys(choices).forEach(function (name) {
      select.appendChild(el('option', { text: choices[name], attrs: { value: name } }));
    });
  }

  function algorithmLabel(uri) {
    return state.config.uris[uri] || uri;
  }

  function readAlgorithms(prefix) {
    const algorithms = {};
    Object.keys(state.config.algorithms).forEach(function (option) {
      algorithms[option] = $(prefix + option).value;
    });
    return algorithms;
  }

  /* ---------- Data editor ---------- */

  let entryCounter = 0;

  function toEntries(data) {
    return Object.keys(data).map(function (key) {
      const value = data[key];
      return {
        id: ++entryCounter,
        key: key,
        value: typeof value === 'object' && value !== null ? '' : String(value),
        children: typeof value === 'object' && value !== null ? toEntries(value) : null
      };
    });
  }

  let entries = [];

  function entriesToData(list) {
    const data = {};
    list.forEach(function (entry) {
      data[entry.key] = entry.children ? entriesToData(entry.children) : entry.value;
    });
    return data;
  }

  function findEntry(list, id, parent) {
    for (let i = 0; i < list.length; i++) {
      if (list[i].id === id) return { list: list, index: i, entry: list[i], parent: parent || null };
      if (list[i].children) {
        const found = findEntry(list[i].children, id, list[i]);
        if (found) return found;
      }
    }
    return null;
  }

  const MAX_DEPTH = 4;

  function renderEntries(list, container, depth) {
    list.forEach(function (entry) {
      const keyInput = el('input', {
        attrs: { type: 'text', name: 'key-' + entry.id, value: entry.key, 'aria-label': 'Key', autocomplete: 'off', spellcheck: 'false' },
        on: { input: function () { entry.key = keyInput.value; onDataChange(); } }
      });
      const row = el('div', { class: 'data-row' + (entry.children ? ' is-group' : '') }, [
        el('div', { class: 'data-key' }, [keyInput])
      ]);
      if (!entry.children) {
        const valueInput = el('input', {
          attrs: { type: 'text', name: 'value-' + entry.id, value: entry.value, 'aria-label': 'Value of ' + (entry.key || 'this key'), autocomplete: 'off', spellcheck: 'false' },
          on: { input: function () { entry.value = valueInput.value; onDataChange(); } }
        });
        row.appendChild(el('div', { class: 'data-value' }, [valueInput]));
      }
      const addChild = el('button', {
        class: 'icon-btn',
        attrs: { type: 'button', 'aria-label': 'Add a nested value under ' + (entry.key || 'this key'), title: 'Add a nested value', disabled: depth >= MAX_DEPTH },
        on: {
          click: function () {
            if (!entry.children) entry.children = [];
            entry.children.push({ id: ++entryCounter, key: 'key' + (entry.children.length + 1), value: 'value', children: null });
            renderDataEditor();
            onDataChange();
          }
        }
      }, [icon('child')]);
      const remove = el('button', {
        class: 'icon-btn',
        attrs: { type: 'button', 'aria-label': 'Remove ' + (entry.key || 'this value'), title: 'Remove' },
        on: {
          click: function () {
            const found = findEntry(entries, entry.id);
            if (!found) return;
            found.list.splice(found.index, 1);
            if (found.parent && found.parent.children.length === 0) {
              found.parent.children = null;
              found.parent.value = 'value';
            }
            renderDataEditor();
            onDataChange();
          }
        }
      }, [icon('trash')]);
      row.appendChild(el('div', { class: 'data-actions' }, [addChild, remove]));
      container.appendChild(row);
      if (entry.children) {
        const children = el('div', { class: 'data-children' });
        renderEntries(entry.children, children, depth + 1);
        container.appendChild(children);
      }
    });
  }

  function renderDataEditor() {
    const container = $('data-editor');
    clear(container);
    renderEntries(entries, container, 1);
  }

  /* ---------- Issuer ---------- */

  function issuerInput() {
    return {
      data: entriesToData(entries),
      encrypt: $('encrypt').checked,
      algorithms: readAlgorithms('issuer-')
    };
  }

  function showIssuerError(message) {
    const box = $('issuer-error');
    box.textContent = message || '';
    box.hidden = !message;
  }

  const refreshIssuerCode = debounce(async function () {
    try {
      const result = await api('/api/issuer-code', issuerInput());
      renderPhp($('issuer-code'), result.code);
      showIssuerError(null);
    } catch (e) {
      showIssuerError(e.message);
    }
  }, 250);

  function onDataChange() {
    refreshIssuerCode();
  }

  function syncEncryptionSelect() {
    $('issuer-sessionKeyCipheringAlgorithm').disabled = !$('encrypt').checked;
  }

  async function createToken() {
    const button = $('create-token');
    const input = issuerInput();
    button.disabled = true;
    try {
      const result = await api('/api/issue', input);
      if (result.error) throw new Error(result.error);
      showIssuerError(null);
      renderPhp($('issuer-code'), result.code);
      setToken({ xml: result.xml, encrypted: result.encrypted, algorithms: input.algorithms, data: input.data, edited: false });
      resetVerification('New token: verify it with the receiver.');
      return true;
    } catch (e) {
      showIssuerError(e.message);
      return false;
    } finally {
      button.disabled = false;
    }
  }

  /* ---------- XML parsing (display only) ---------- */

  const TOKEN_RE = /(<\?[\s\S]*?\?>)|(<!--[\s\S]*?-->)|(<!DOCTYPE(?:[^[>]|\[[\s\S]*?\])*>)|(<!\[CDATA\[[\s\S]*?\]\]>)|(<\/[^<>]*>)|(<[^<>]*>)|([^<]+)|(<)/g;
  const ATTR_RE = /([^\s=/]+)\s*=\s*("([^"]*)"|'([^']*)')/g;

  function splitName(name) {
    const colon = name.indexOf(':');
    return colon > 0 ? { prefix: name.slice(0, colon), local: name.slice(colon + 1) } : { prefix: '', local: name };
  }

  /** Parses XML into a tree, tolerating errors: it is only displayed. */
  function parseXml(xml) {
    let counter = 0;
    const root = { type: 'root', children: [] };
    const stack = [root];
    let match;
    TOKEN_RE.lastIndex = 0;
    while ((match = TOKEN_RE.exec(xml)) !== null) {
      const parent = stack[stack.length - 1];
      if (match[1]) parent.children.push({ type: 'decl', raw: match[1] });
      else if (match[2]) parent.children.push({ type: 'comment', raw: match[2] });
      else if (match[3]) parent.children.push({ type: 'doctype', raw: match[3] });
      else if (match[4]) parent.children.push({ type: 'text', raw: match[4] });
      else if (match[5]) {
        const name = match[5].slice(2, -1).trim();
        for (let i = stack.length - 1; i > 0; i--) {
          if (stack[i].name === name) { stack.length = i; break; }
        }
      } else if (match[6]) {
        const body = match[6];
        const nameMatch = /^<([^\s/>]+)/.exec(body);
        if (!nameMatch) { parent.children.push({ type: 'text', raw: body }); continue; }
        const attrs = [];
        let attr;
        const attrSource = body.slice(nameMatch[0].length);
        ATTR_RE.lastIndex = 0;
        while ((attr = ATTR_RE.exec(attrSource)) !== null) {
          attrs.push({ name: attr[1], value: attr[3] !== undefined ? attr[3] : attr[4], quote: attr[3] !== undefined ? '"' : "'" });
        }
        const names = splitName(nameMatch[1]);
        const node = {
          type: 'element', id: 'n' + (++counter), name: nameMatch[1], prefix: names.prefix, local: names.local,
          attrs: attrs, children: [], selfClosing: /\/\s*>$/.test(body), parent: parent.type === 'element' ? parent : null
        };
        parent.children.push(node);
        if (!node.selfClosing) stack.push(node);
      } else {
        parent.children.push({ type: 'text', raw: match[7] || match[8] });
      }
    }
    return root;
  }

  function elementChildren(node) {
    return node.children.filter(function (child) { return child.type === 'element'; });
  }

  function textOf(node) {
    return node.children.filter(function (child) { return child.type === 'text'; }).map(function (child) { return child.raw; }).join('');
  }

  function ancestors(node) {
    const list = [];
    for (let parent = node.parent; parent; parent = parent.parent) list.push(parent);
    return list;
  }

  function hasAncestor(node, local) {
    return ancestors(node).some(function (a) { return a.local === local; });
  }

  /* ---------- Pretty lines ---------- */

  const VALUE_LIMIT = 44;

  /** Returns the segments of a text value, shortened unless full. */
  function valueSegments(text, cls, full) {
    if (full || text.length <= VALUE_LIMIT) return [{ cls: cls, text: text }];
    return [
      { cls: cls, text: text.slice(0, 18) },
      { cls: 'x-ellipsis', text: '… ' + formatNumber(text.length) + ' chars …', title: 'Shortened: use "Full values" to see it all' },
      { cls: cls, text: text.slice(-10) }
    ];
  }

  function nameSegments(name) {
    const parts = splitName(name);
    const segs = [];
    if (parts.prefix) segs.push({ cls: 'x-prefix', text: parts.prefix + ':' });
    segs.push({ cls: 'x-name', text: parts.local });
    return segs;
  }

  function openTagSegments(node, closeNow) {
    let segs = [{ cls: 'x-punct', text: '<' }].concat(nameSegments(node.name));
    node.attrs.forEach(function (attr) {
      segs.push({ cls: '', text: ' ' });
      segs.push({ cls: 'x-attr', text: attr.name });
      segs.push({ cls: 'x-eq', text: '=' });
      segs = segs.concat(valueSegments(attr.quote + attr.value + attr.quote, 'x-value', true));
    });
    segs.push({ cls: 'x-punct', text: closeNow ? '/>' : '>' });
    return segs;
  }

  function closeTagSegments(node) {
    return [{ cls: 'x-punct', text: '</' }].concat(nameSegments(node.name), [{ cls: 'x-punct', text: '>' }]);
  }

  /**
   * Turns a parsed tree into display lines: { depth, segs, nodeId,
   * start (TRUE on the first line of an element) }. Each element gets
   * node.first and node.last, its range of lines.
   */
  function prettyLines(tree, full) {
    const lines = [];
    function push(depth, segs, node, start) {
      lines.push({ depth: depth, segs: segs, nodeId: node ? node.id : null, start: !!start });
      return lines.length - 1;
    }
    function walk(node, depth) {
      if (node.type === 'text') {
        const text = node.raw.trim();
        if (text) push(depth, valueSegments(text, 'x-text', full), null, false);
        return;
      }
      if (node.type === 'decl') { push(depth, [{ cls: 'x-decl', text: node.raw }], null, false); return; }
      if (node.type === 'comment') { push(depth, [{ cls: 'x-decl', text: node.raw }], null, false); return; }
      if (node.type === 'doctype') {
        node.raw.split('\n').forEach(function (part, i) {
          push(depth + (i === 0 || /^\s*\]>/.test(part) ? 0 : 1), [{ cls: 'x-doctype', text: part.trim() }], null, false);
        });
        return;
      }
      const elements = elementChildren(node);
      const text = textOf(node).trim();
      if (node.selfClosing || (elements.length === 0 && !text)) {
        node.first = node.last = push(depth, openTagSegments(node, node.selfClosing), node, true);
        if (!node.selfClosing) lines[node.first].segs = lines[node.first].segs.concat(closeTagSegments(node));
        return;
      }
      if (elements.length === 0) {
        node.first = node.last = push(depth, openTagSegments(node, false).concat(valueSegments(text, 'x-text', full), closeTagSegments(node)), node, true);
        return;
      }
      node.first = push(depth, openTagSegments(node, false), node, true);
      node.children.forEach(function (child) { walk(child, depth + 1); });
      node.last = push(depth, closeTagSegments(node), node, false);
    }
    tree.children.forEach(function (child) { walk(child, 0); });
    return lines;
  }

  function lineText(line) {
    return '  '.repeat(line.depth) + line.segs.map(function (s) { return s.text; }).join('');
  }

  /* ---------- Annotations ---------- */

  const ANNOTATIONS = {
    'Signature': 'Root of the enveloping XML signature: everything it signs is inside it. The library requires it to be the document element; a ds:Signature wrapped in another element is refused.',
    'SignedInfo': 'The part that is actually signed. It names the algorithms and holds the reference to the signed content, with its digest. SignatureValue is computed over its canonical form.',
    'CanonicalizationMethod': 'How SignedInfo is canonicalized before it is signed and verified, so that formatting (attribute order, namespace declarations, line breaks in tags) does not change the bytes signed.',
    'SignatureMethod': 'Algorithm of SignatureValue. The receiver compares it with the algorithm it expects (option signatureAlgorithm): another one is refused, and a key transport algorithm is never accepted here.',
    'Reference': 'Points to the signed content: URI="#Token" is the element whose Id is "Token". The library requires exactly one such element, the ds:Object child of ds:Signature, and reads the token only from the node the digest was computed over.',
    'Transforms': 'The transforms applied to ds:Object before its digest is computed.',
    'Transform': 'Canonicalization of ds:Object before its digest is computed. The receiver checks it like the other algorithms.',
    'DigestMethod': 'Hash algorithm of the referenced content (option digestAlgorithm), checked against the expected one.',
    'DigestValue': 'Hash of the canonicalized ds:Object, in base64. Changing a single byte of the token changes it: the Digest check fails. Recomputing it is easy; signing it again needs the issuer\'s private key.',
    'SignatureValue': 'Signature of the canonicalized SignedInfo, made with the issuer\'s private key. It covers DigestValue, and through it the whole token. It is verified with the public key of the certificate below: only an OpenSSL result of exactly 1 counts as valid.',
    'KeyInfo': 'Carries the signing certificate. The signature does not cover it: anyone can put any certificate here. That is why the receiver needs a trust anchor.',
    'X509Data': 'Container of the X.509 certificate.',
    'X509Certificate': 'The issuer\'s certificate (DER, base64). The signature is verified with its public key; then the certificate itself must be trusted: valid now, allowed to sign, its chain verified by OpenSSL up to caCertPath, equal to the pinned signerCertPath, and matching expectedSubject, as configured.',
    'Object': 'The signed content of this enveloping signature, Id="Token". DigestValue covers everything inside it.',
    'Token': 'The token: its timestamp, its identifier and the user data.',
    'TokenTimestamp': 'Creation time, in UTC. It is signed, so it cannot be moved. The library does not check it in isSignatureValid(): the receiver calls isOutOfDate($ttl).',
    'TokenId': '128 random bits in hexadecimal, signed. getTokenId() returns it for a valid token; the receiver stores it to refuse a token it has already accepted (replay).',
    'TokenData': 'The user data, as nested elements. With base64Encode (the default), each value is base64 encoded and marked Algorithm="base64".',
    'data-leaf': 'A user data value. getData() returns it decoded, as a string.',
    'data-group': 'A group of user data values: getData() returns it as a nested array.',
    'EncryptedData': 'XML Encryption of the token content (Type="…#Content"). The data are encrypted before they are signed: the signature covers the ciphertext, so an altered ciphertext fails the digest check before any decryption.',
    'EncryptionMethod@data': 'Symmetric algorithm of the content (option sessionKeyCipheringAlgorithm). AES-GCM checks an authentication tag before returning any data; CBC has no integrity and is only accepted when the receiver declares it.',
    'KeyInfo@enc': 'Holds the session key, encrypted for the recipient.',
    'EncryptedKey': 'The random session key of this token, encrypted with the public key of the recipient\'s certificate (key transport). Only the recipient\'s private key decrypts it.',
    'EncryptionMethod@key': 'Key transport algorithm: RSA-OAEP. RSA 1.5 is refused, at creation and at analysis: how its padding fails is a Bleichenbacher oracle.',
    'CipherData@key': 'Container of the encrypted session key.',
    'CipherValue@key': 'The encrypted session key, in base64.',
    'CipherData@data': 'Container of the encrypted content.',
    'CipherValue@data': 'The encrypted token (timestamp, identifier and data), in base64: IV, ciphertext and, for GCM, the authentication tag. Whatever fails while decrypting it, the error is the same: "Token decryption failed!".'
  };

  function annotationKey(node) {
    const parentLocal = node.parent ? node.parent.local : null;
    if (node.local !== 'TokenData' && hasAncestor(node, 'TokenData')) {
      return elementChildren(node).length ? 'data-group' : 'data-leaf';
    }
    if (node.local === 'EncryptionMethod') return parentLocal === 'EncryptedKey' ? 'EncryptionMethod@key' : 'EncryptionMethod@data';
    if (node.local === 'KeyInfo' && parentLocal === 'EncryptedData') return 'KeyInfo@enc';
    if (node.local === 'CipherData' || node.local === 'CipherValue') {
      return node.local + (hasAncestor(node, 'EncryptedKey') ? '@key' : '@data');
    }
    return ANNOTATIONS[node.local] ? node.local : null;
  }

  /** Where the node stands with respect to the signature. */
  function coverage(node) {
    const chain = [node].concat(ancestors(node));
    const top = chain.length >= 2 ? chain[chain.length - 2] : null;
    if (chain.length === 1) return { text: 'Root of the signature', kind: 'info' };
    if (!top) return null;
    if (top.local === 'SignedInfo') return { text: 'Signed: covered by SignatureValue', kind: 'ok' };
    if (top.local === 'SignatureValue') return { text: 'The signature itself', kind: 'accent' };
    if (top.local === 'Object') return { text: 'Covered by DigestValue, hence signed', kind: 'ok' };
    if (top.local === 'KeyInfo') return { text: 'Not covered by the signature', kind: 'warn' };
    return { text: 'Not covered by the signature', kind: 'warn' };
  }

  function describeAge(timestamp) {
    const time = Date.parse(timestamp);
    if (isNaN(time)) return null;
    const seconds = Math.round((Date.now() - time) / 1000);
    if (seconds < 0) return 'in ' + (-seconds) + ' s (in the future)';
    if (seconds < 120) return seconds + ' s ago';
    if (seconds < 7200) return Math.floor(seconds / 60) + ' min ago';
    return Math.floor(seconds / 3600) + ' h ago';
  }

  function nodeFacts(node) {
    const facts = [];
    node.attrs.forEach(function (attr) {
      if (attr.name === 'Algorithm' && /^https?:/.test(attr.value)) facts.push(['Algorithm', algorithmLabel(attr.value)]);
      if (attr.name === 'URI') facts.push(['URI', attr.value]);
      if (attr.name === 'Id') facts.push(['Id', attr.value]);
    });
    const text = elementChildren(node).length ? '' : textOf(node).trim();
    const key = annotationKey(node);
    if (key === 'data-leaf') {
      const encoded = node.attrs.some(function (a) { return a.name === 'Algorithm' && a.value === 'base64'; });
      const decoded = encoded ? decodeBase64Utf8(text) : text;
      facts.push(['Decoded value', decoded === null ? '(not UTF-8 text)' : decoded]);
    } else if (node.local === 'TokenTimestamp' && text) {
      const age = describeAge(text);
      if (age) facts.push(['Issued', age]);
    } else if (node.local === 'TokenId' && text) {
      facts.push(['Bits', String(text.length * 4)]);
    } else if (/^(DigestValue|SignatureValue|CipherValue|X509Certificate)$/.test(node.local) && text) {
      facts.push(['Size', formatNumber(base64Length(text)) + ' bytes']);
      if (node.local === 'X509Certificate' && state.verified && state.verified.xml === state.token.xml && state.verified.result.token.certSubject) {
        facts.push(['Subject', state.verified.result.token.certSubject]);
        facts.push(['Issuer', state.verified.result.token.certIssuer]);
      }
    }
    return facts;
  }

  const LEGEND = ['SignedInfo', 'DigestValue', 'SignatureValue', 'X509Certificate', 'Object', 'TokenTimestamp', 'TokenId', 'TokenData', 'EncryptedData', 'EncryptedKey'];

  function renderAnnotation() {
    const box = $('annotation');
    clear(box);
    const node = state.activeId ? findNode(state.activeId) : null;
    if (!node) {
      const legend = el('div', { class: 'legend' });
      LEGEND.forEach(function (local) {
        const target = findNodeByLocal(local);
        if (!target) return;
        legend.appendChild(el('button', {
          text: local,
          attrs: { type: 'button', 'aria-label': 'Explain ' + target.name },
          on: { click: function () { selectNode(target.id, true, true); } }
        }));
      });
      box.appendChild(el('div', { class: 'annotation-empty' }, [
        el('p', { text: 'Point at a tag, or focus the token and use the arrow keys, to see what each block does and whether the signature covers it.' }),
        legend
      ]));
      return;
    }
    const key = annotationKey(node);
    const cover = coverage(node);
    box.appendChild(el('h3', { text: node.name }));
    if (cover) box.appendChild(chip(cover.text, cover.kind));
    box.appendChild(el('p', { text: key ? ANNOTATIONS[key] : 'This element is not part of the structure of a token.' }));
    const facts = nodeFacts(node);
    if (facts.length) {
      const list = el('dl', { class: 'annotation-facts' });
      facts.forEach(function (fact) {
        list.appendChild(el('div', {}, [el('dt', { text: fact[0] }), el('dd', { text: fact[1] })]));
      });
      box.appendChild(list);
    }
    box.appendChild(el('p', { class: 'annotation-pin', text: state.pinnedId === node.id ? 'Selected. Esc clears the selection.' : 'Click to keep this block selected.' }));
  }

  /* ---------- Token viewer ---------- */

  let allNodes = [];

  function collectNodes(tree) {
    const list = [];
    (function walk(node) {
      node.children.forEach(function (child) {
        if (child.type === 'element') {
          list.push(child);
          walk(child);
        }
      });
    })(tree);
    return list;
  }

  function findNode(id) {
    for (let i = 0; i < allNodes.length; i++) if (allNodes[i].id === id) return allNodes[i];
    return null;
  }

  function findNodeByLocal(local) {
    for (let i = 0; i < allNodes.length; i++) if (allNodes[i].local === local) return allNodes[i];
    return null;
  }

  function renderSegments(container, segs) {
    segs.forEach(function (seg) {
      const span = el('span', { class: seg.cls || null, text: seg.text });
      if (seg.title) span.title = seg.title;
      container.appendChild(span);
    });
  }

  function renderXmlView() {
    const view = $('xml-view');
    clear(view);
    view.removeAttribute('aria-activedescendant');
    if (!state.token) {
      view.classList.add('is-empty');
      view.appendChild(el('span', { text: 'Create a token with the issuer.' }));
      allNodes = [];
      renderAnnotation();
      return;
    }
    view.classList.remove('is-empty');
    state.tree = parseXml(state.token.xml);
    allNodes = collectNodes(state.tree);
    const lines = prettyLines(state.tree, state.fullValues);
    lines.forEach(function (line, index) {
      const div = el('div', { class: 'xml-line', attrs: { id: 'xl-' + index, role: line.start ? 'option' : 'none' } });
      div.style.setProperty('--depth', String(line.depth));
      if (line.nodeId) {
        div.dataset.node = line.nodeId;
        if (line.start) {
          div.setAttribute('aria-selected', 'false');
          const node = findNode(line.nodeId);
          div.setAttribute('aria-label', node.name);
        }
      }
      renderSegments(div, line.segs);
      view.appendChild(div);
    });
    if (state.activeId && !findNode(state.activeId)) state.activeId = state.pinnedId = null;
    highlight();
    renderAnnotation();
  }

  function highlight() {
    const view = $('xml-view');
    const node = state.activeId ? findNode(state.activeId) : null;
    Array.prototype.forEach.call(view.children, function (line, index) {
      const inside = !!node && index >= node.first && index <= node.last;
      line.classList.toggle('in-block', inside);
      line.classList.toggle('is-active-start', !!node && index === node.first);
      if (line.getAttribute('role') === 'option') line.setAttribute('aria-selected', node && index === node.first ? 'true' : 'false');
    });
    if (node) view.setAttribute('aria-activedescendant', 'xl-' + node.first);
    else view.removeAttribute('aria-activedescendant');
  }

  function selectNode(id, pin, scroll) {
    state.activeId = id;
    if (pin) state.pinnedId = id;
    highlight();
    renderAnnotation();
    if (scroll && id) {
      const node = findNode(id);
      const line = node && $('xl-' + node.first);
      if (line) line.scrollIntoView({ block: 'nearest', behavior: reducedMotion.matches ? 'auto' : 'smooth' });
    }
  }

  function initXmlView() {
    const view = $('xml-view');
    view.addEventListener('mouseover', function (event) {
      const line = event.target.closest('.xml-line');
      if (line && line.dataset.node && line.dataset.node !== state.activeId) selectNode(line.dataset.node, false, false);
    });
    view.addEventListener('mouseleave', function () {
      if (state.activeId !== state.pinnedId) selectNode(state.pinnedId, false, false);
    });
    view.addEventListener('click', function (event) {
      const line = event.target.closest('.xml-line');
      if (line && line.dataset.node) selectNode(line.dataset.node, true, false);
    });
    view.addEventListener('keydown', function (event) {
      if (!allNodes.length) return;
      const index = allNodes.findIndex(function (n) { return n.id === state.activeId; });
      let next = null;
      if (event.key === 'ArrowDown') next = allNodes[Math.min(allNodes.length - 1, index + 1)];
      else if (event.key === 'ArrowUp') next = allNodes[Math.max(0, index < 0 ? 0 : index - 1)];
      else if (event.key === 'Home') next = allNodes[0];
      else if (event.key === 'End') next = allNodes[allNodes.length - 1];
      else if (event.key === 'Escape') {
        state.pinnedId = null;
        selectNode(null, false, false);
        event.preventDefault();
        return;
      } else return;
      event.preventDefault();
      selectNode(next.id, true, true);
    });
  }

  function renderTokenMeta() {
    const meta = $('token-meta');
    clear(meta);
    if (!state.token) return;
    const t = state.token;
    meta.appendChild(t.encrypted ? chip('signed + encrypted', 'accent', 'lock') : chip('signed', 'accent'));
    const sig = findNodeByLocal('SignatureMethod');
    const digest = findNodeByLocal('DigestMethod');
    const encryption = allNodes.filter(function (n) { return n.local === 'EncryptionMethod' && n.parent && n.parent.local === 'EncryptedData'; })[0];
    [sig, digest, encryption].forEach(function (node) {
      const algorithm = node && node.attrs.filter(function (a) { return a.name === 'Algorithm'; })[0];
      if (algorithm) meta.appendChild(chip(algorithmLabel(algorithm.value)));
    });
    meta.appendChild(chip(formatBytes(new Blob([t.xml]).size)));
    if (t.edited) meta.appendChild(chip('edited by hand', 'warn', 'edit'));
  }

  function setToken(token) {
    state.token = token;
    state.activeId = state.pinnedId = null;
    renderXmlView();
    renderTokenMeta();
  }

  function initTokenTools() {
    $('copy-token').addEventListener('click', function () {
      if (state.token) copyText(state.token.xml, 'XML token');
    });
    $('toggle-full').addEventListener('click', function () {
      state.fullValues = !state.fullValues;
      this.setAttribute('aria-pressed', String(state.fullValues));
      renderXmlView();
    });
    $('edit-token').addEventListener('click', function () {
      setEditing(!state.editing);
    });
    $('edit-cancel').addEventListener('click', function () { setEditing(false); });
    $('edit-apply').addEventListener('click', function () {
      const xml = $('xml-edit').value;
      if (state.token && xml !== state.token.xml) {
        setToken({ xml: xml, encrypted: /EncryptedData/.test(xml), algorithms: state.token.algorithms, data: state.token.data, edited: true });
        resetVerification('Token edited: verify it to see what the receiver says.');
      }
      setEditing(false);
    });
  }

  function setEditing(on) {
    state.editing = on && !!state.token;
    $('edit-token').setAttribute('aria-pressed', String(state.editing));
    $('xml-view').hidden = state.editing;
    $('xml-edit-wrap').hidden = !state.editing;
    $('toggle-full').disabled = state.editing;
    if (state.editing) {
      $('xml-edit').value = state.token.xml;
      $('xml-edit').focus();
    }
  }

  /* ---------- PHP code ---------- */

  const PHP_RE = /(\/\/[^\n]*)|('(?:[^'\\]|\\.)*')|(\$[A-Za-z_][A-Za-z0-9_]*)|\b(require|use|new|if|null|true|false|throw|return)\b|\b(XMLDSigToken|RuntimeException)\b|(<\?php)/g;

  function renderPhp(pre, code) {
    clear(pre);
    let last = 0;
    let match;
    PHP_RE.lastIndex = 0;
    while ((match = PHP_RE.exec(code)) !== null) {
      if (match.index > last) pre.appendChild(document.createTextNode(code.slice(last, match.index)));
      const cls = match[1] ? 'php-com' : match[2] ? 'php-str' : match[3] ? 'php-var' : match[4] || match[6] ? 'php-kw' : 'php-cls';
      pre.appendChild(el('span', { class: cls, text: match[0] }));
      last = match.index + match[0].length;
    }
    if (last < code.length) pre.appendChild(document.createTextNode(code.slice(last)));
  }

  function initCopyButtons() {
    document.querySelectorAll('.copy-code').forEach(function (button) {
      button.addEventListener('click', function () {
        copyText($(button.dataset.copy).textContent, 'PHP code');
      });
    });
  }

  /* ---------- Receiver ---------- */

  const STEP_IDLE = [
    ['structure', 'Parsing & structure', 'library', 'UTF-8, no DOCTYPE, ds:Signature as document element, a single Id="Token", the fixed elements of a token.'],
    ['algorithms', 'Algorithms', 'library', 'The algorithms of the token are the expected ones.'],
    ['digest', 'Digest', 'library', 'The hash of the canonicalized ds:Object matches ds:DigestValue.'],
    ['signature', 'Signature', 'library', 'ds:SignatureValue verifies with the key of the certificate the token carries.'],
    ['trust', 'Certificate trust', 'library', 'The certificate is trusted by the configured anchor.'],
    ['decryption', 'Decryption', 'library', 'Only for an encrypted token, once the checks above have passed.'],
    ['content', 'Token content', 'library', 'TokenTimestamp, TokenId and TokenData are well formed.'],
    ['freshness', 'Freshness', 'caller', 'isOutOfDate($ttl): the token is recent enough.'],
    ['replay', 'Replay', 'caller', 'getTokenId() was never accepted before.']
  ];

  function readReceiver() {
    const ttl = parseInt($('rc-ttl').value, 10);
    return {
      ca: $('rc-ca').checked,
      pin: $('rc-pin').checked,
      subject: $('rc-subject').checked,
      subjectO: $('rc-subjectO').value,
      subjectOU: $('rc-subjectOU').value,
      decrypt: $('rc-decrypt').checked,
      ttl: isNaN(ttl) ? state.config.receiver.ttl : ttl,
      replay: $('rc-replay').checked,
      algorithms: readAlgorithms('rc-')
    };
  }

  function applyReceiverDefaults() {
    const d = state.config.receiver;
    $('rc-ca').checked = d.ca;
    $('rc-pin').checked = d.pin;
    $('rc-subject').checked = d.subject;
    $('rc-subjectO').value = d.subjectO;
    $('rc-subjectOU').value = d.subjectOU;
    $('rc-decrypt').checked = d.decrypt;
    $('rc-ttl').value = d.ttl;
    $('rc-ttl-range').value = d.ttl;
    $('rc-replay').checked = d.replay;
    Object.keys(d.algorithms).forEach(function (option) { $('rc-' + option).value = d.algorithms[option]; });
  }

  function syncReceiverFields() {
    const subjectOn = $('rc-subject').checked;
    $('rc-subjectO').disabled = $('rc-subjectOU').disabled = !subjectOn;
    $('rc-subject-fields').dataset.disabled = String(!subjectOn);
    $('rc-sessionKeyCipheringAlgorithm').disabled = !$('rc-decrypt').checked;
    $('replay-clear').disabled = !$('rc-replay').checked;
  }

  function updateAlgoHint() {
    const issuer = readAlgorithms('issuer-');
    const receiver = readAlgorithms('rc-');
    const differs = Object.keys(issuer).filter(function (option) {
      if (option === 'sessionKeyCipheringAlgorithm' && !$('encrypt').checked) return false;
      return issuer[option] !== receiver[option];
    });
    const hint = $('algo-sync-hint');
    clear(hint);
    if (differs.length === 0) {
      hint.appendChild(document.createTextNode('Same as the issuer. Change one to see the token refused.'));
    } else {
      hint.appendChild(document.createTextNode('Differs from the issuer: tokens will be refused. '));
      hint.appendChild(el('button', {
        class: 'btn btn-ghost btn-xs', text: 'Match the issuer', attrs: { type: 'button' },
        on: { click: matchIssuerAlgorithms }
      }));
    }
  }

  function matchIssuerAlgorithms() {
    const issuer = readAlgorithms('issuer-');
    Object.keys(issuer).forEach(function (option) { $('rc-' + option).value = issuer[option]; });
    updateAlgoHint();
    refreshReceiverCode();
  }

  const refreshReceiverCode = debounce(async function () {
    try {
      const result = await api('/api/receiver-code', { receiver: readReceiver() });
      renderPhp($('receiver-code'), result.code);
    } catch (e) {
      renderVerdictMessage('bad', 'Invalid receiver setting', e.message);
    }
  }, 200);

  function setReplayMemory(size) {
    $('replay-memory').textContent = 'Memory: ' + size + (size === 1 ? ' id' : ' ids');
  }

  function renderVerdictMessage(kind, title, text, error) {
    const box = $('verdict');
    clear(box);
    box.className = 'verdict' + (kind ? ' is-' + kind : '');
    const iconName = kind === 'ok' ? 'check' : kind === 'bad' ? 'cross' : kind === 'warn' ? 'warn' : 'dash';
    box.appendChild(el('span', { class: 'verdict-icon' }, [icon(iconName)]));
    box.appendChild(el('div', {}, [
      el('p', { class: 'verdict-title', text: title }),
      text ? el('p', { class: 'verdict-text', text: text }) : null,
      error ? el('p', { class: 'verdict-error', text: error }) : null
    ]));
  }

  function stepItem(step) {
    const iconName = { pass: 'check', fail: 'cross', skip: 'dash', off: 'off', idle: 'dash' }[step.status] || 'dash';
    return el('li', { class: 'step', data: { status: step.status, step: step.id } }, [
      el('span', { class: 'step-icon', attrs: { 'aria-hidden': 'true' } }, [icon(iconName)]),
      el('div', { class: 'step-main' }, [
        el('div', { class: 'step-title' }, [
          el('span', { text: step.label }),
          el('span', { class: 'step-by step-by-' + step.by, text: step.by === 'caller' ? 'your code' : 'library' }),
          el('span', { class: 'sr-only', text: ': ' + ({ pass: 'passed', fail: 'failed', skip: 'not reached', off: 'turned off', idle: 'not run yet' }[step.status] || step.status) })
        ]),
        el('p', { class: 'step-detail', text: step.detail }),
        step.message ? el('p', { class: 'step-message', text: step.message }) : null
      ])
    ]);
  }

  function renderIdlePipeline() {
    const list = $('pipeline');
    clear(list);
    const encrypted = state.token && state.token.encrypted;
    STEP_IDLE.forEach(function (s) {
      if (s[0] === 'decryption' && !encrypted) return;
      list.appendChild(stepItem({ id: s[0], label: s[1], by: s[2], detail: s[3], status: 'idle', message: null }));
    });
  }

  function resetVerification(text) {
    renderVerdictMessage(null, 'Not verified yet', text);
    renderIdlePipeline();
    $('readback').hidden = true;
  }

  function firstFailure(result) {
    return result.steps.filter(function (s) { return s.status === 'fail'; })[0] || null;
  }

  function renderVerdict(result) {
    const failure = firstFailure(result);
    if (result.accepted) {
      const replayOff = result.steps.some(function (s) { return s.id === 'replay' && s.status === 'off'; });
      if (replayOff) {
        renderVerdictMessage('warn', 'Accepted, without replay protection', 'Every check ran but replay: the same token would be accepted again until it is out of date.');
      } else {
        renderVerdictMessage('ok', 'Accepted: the data can be trusted', 'isSignatureValid() returned TRUE, the token is fresh, and its identifier was never seen.');
      }
      return;
    }
    if (failure && failure.by === 'caller') {
      renderVerdictMessage('bad', 'Refused by your code: ' + failure.label, 'isSignatureValid() returned TRUE: the library accepted the token, the caller\'s check refused it.', failure.message);
    } else {
      renderVerdictMessage('bad', 'Refused' + (failure ? ' at ' + failure.label : ''), 'isSignatureValid() returned FALSE. getError():', result.error);
    }
  }

  function renderDataTree(container, data) {
    clear(container);
    function build(value) {
      const list = el('ul');
      Object.keys(value).forEach(function (key) {
        const item = value[key];
        if (item !== null && typeof item === 'object') {
          list.appendChild(el('li', {}, [el('span', { class: 'dt-key', text: key }), ':', build(item)]));
        } else {
          list.appendChild(el('li', {}, [el('span', { class: 'dt-key', text: key }), ': ', el('span', { class: 'dt-value', text: JSON.stringify(String(item)) })]));
        }
      });
      return list;
    }
    container.appendChild(build(data));
  }

  async function animatePipeline(list, steps) {
    clear(list);
    const items = steps.map(function (step) {
      const item = stepItem(step);
      item.classList.add('is-pending');
      list.appendChild(item);
      return item;
    });
    for (let i = 0; i < items.length; i++) {
      await sleep(i === 0 ? 30 : 110);
      items[i].classList.remove('is-pending');
    }
  }

  let verifying = false;

  async function verifyToken() {
    if (!state.token || verifying) return;
    verifying = true;
    const button = $('verify-token');
    button.disabled = true;
    try {
      const xml = state.token.xml;
      const result = await api('/api/verify', { xml: xml, receiver: readReceiver() });
      state.verified = { xml: xml, result: result };
      renderPhp($('receiver-code'), result.code);
      setReplayMemory(result.replayMemory);
      renderVerdictMessage(null, 'Checking…', 'The library analyzes the token, then your code checks freshness and replay.');
      $('readback').hidden = true;
      await animatePipeline($('pipeline'), result.steps);
      renderVerdict(result);
      if (result.accepted && result.data) {
        renderDataTree($('data-tree'), result.data);
        $('readback').hidden = false;
      }
      renderAnnotation();
    } catch (e) {
      renderVerdictMessage('bad', 'Verification failed to run', e.message);
    } finally {
      button.disabled = false;
      verifying = false;
    }
  }

  function initReceiver() {
    const form = $('receiver-form');
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      verifyToken();
    });
    form.addEventListener('change', function (event) {
      if (event.target.id === 'rc-ttl-range') $('rc-ttl').value = event.target.value;
      if (event.target.id === 'rc-ttl') {
        const value = Math.max(5, Math.min(86400, parseInt(event.target.value, 10) || state.config.receiver.ttl));
        event.target.value = value;
        $('rc-ttl-range').value = Math.min(600, value);
      }
      syncReceiverFields();
      updateAlgoHint();
      refreshReceiverCode();
    });
    $('rc-ttl-range').addEventListener('input', function () {
      $('rc-ttl').value = this.value;
      refreshReceiverCode();
    });
    ['rc-subjectO', 'rc-subjectOU'].forEach(function (id) {
      $(id).addEventListener('input', refreshReceiverCode);
    });
    $('replay-clear').addEventListener('click', async function () {
      try {
        const result = await api('/api/replay/clear', {});
        setReplayMemory(result.replayMemory);
        toast('Replay memory cleared.');
      } catch (e) {
        toast(e.message);
      }
    });
  }

  /* ---------- Diff ---------- */

  function diffLines(a, b) {
    const n = a.length;
    const m = b.length;
    const lcs = [];
    for (let i = 0; i <= n; i++) lcs.push(new Array(m + 1).fill(0));
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
      }
    }
    const ops = [];
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
      if (a[i] === b[j]) { ops.push({ op: ' ', text: a[i] }); i++; j++; }
      else if (lcs[i + 1][j] >= lcs[i][j + 1]) { ops.push({ op: '-', text: a[i] }); i++; }
      else { ops.push({ op: '+', text: b[j] }); j++; }
    }
    while (i < n) ops.push({ op: '-', text: a[i++] });
    while (j < m) ops.push({ op: '+', text: b[j++] });
    return ops;
  }

  const DIFF_WIDTH = 120;

  /** Shortens a line around a position, keeping its indentation. */
  function shortenAround(text, at, mark) {
    const indent = (text.match(/^\s*/) || [''])[0];
    const body = text.slice(indent.length);
    const pos = Math.max(0, at - indent.length);
    if (body.length <= DIFF_WIDTH) return { indent: indent, before: body.slice(0, pos), marked: body.slice(pos, pos + mark), after: body.slice(pos + mark) };
    // A long line shows 40 characters before the change, at most 32 of the
    // change, then its end. A line without a counterpart shows its start
    // and its end.
    if (mark === 0) {
      return { indent: indent, before: body.slice(0, DIFF_WIDTH - 24) + '…' + body.slice(-20), marked: '', after: '' };
    }
    const start = Math.max(0, pos - 40);
    const before = (start > 0 ? '…' : '') + body.slice(start, pos);
    if (mark > 32) {
      return { indent: indent, before: before, marked: body.slice(pos, pos + 32) + '…', after: body.slice(Math.max(pos + mark, body.length - 24)) };
    }
    const end = Math.min(body.length, pos + mark + 40);
    return { indent: indent, before: before, marked: body.slice(pos, pos + mark), after: body.slice(pos + mark, end) + (end < body.length ? '…' : '') };
  }

  function renderDiff(container, beforeXml, afterXml) {
    clear(container);
    const a = prettyLines(parseXml(beforeXml), true).map(lineText);
    const b = prettyLines(parseXml(afterXml), true).map(lineText);
    const ops = diffLines(a, b);
    const CONTEXT = 2;
    const keep = ops.map(function () { return false; });
    ops.forEach(function (op, index) {
      if (op.op === ' ') return;
      for (let k = Math.max(0, index - CONTEXT); k <= Math.min(ops.length - 1, index + CONTEXT); k++) keep[k] = true;
    });
    if (!ops.some(function (op) { return op.op !== ' '; })) {
      container.appendChild(el('div', { class: 'diff-gap', text: 'No difference: the very same bytes.' }));
      return;
    }
    let skipped = 0;
    function flushGap() {
      if (skipped) container.appendChild(el('div', { class: 'diff-gap', text: '⋯ ' + skipped + ' unchanged line' + (skipped > 1 ? 's' : '') }));
      skipped = 0;
    }
    ops.forEach(function (op, index) {
      if (!keep[index]) { skipped++; return; }
      flushGap();
      let at = 0;
      let mark = 0;
      if (op.op !== ' ') {
        // Pairs a removed line with the added line next to it to mark where
        // they differ.
        const other = op.op === '-' ? ops.slice(index + 1).filter(function (o) { return o.op === '+'; })[0]
          : ops.slice(0, index).reverse().filter(function (o) { return o.op === '-'; })[0];
        if (other) {
          const x = op.text;
          const y = other.text;
          while (at < x.length && at < y.length && x[at] === y[at]) at++;
          let endX = x.length;
          let endY = y.length;
          while (endX > at && endY > at && x[endX - 1] === y[endY - 1]) { endX--; endY--; }
          mark = endX - at;
        }
      }
      const parts = shortenAround(op.text, at, mark);
      const kind = op.op === '+' ? 'diff-add' : op.op === '-' ? 'diff-del' : '';
      container.appendChild(el('div', { class: 'diff-line ' + kind }, [
        el('span', { class: 'diff-sign', text: op.op === ' ' ? '' : op.op, attrs: { 'aria-label': op.op === '+' ? 'added' : op.op === '-' ? 'removed' : null } }),
        el('span', {}, [parts.indent + parts.before, parts.marked ? el('mark', { class: 'diff-mark', text: parts.marked }) : null, parts.after])
      ]));
    });
    flushGap();
  }

  /* ---------- Attack lab ---------- */

  const BASE_LABELS = { plain: 'signed token', encrypted: 'encrypted token', any: 'any token' };

  function renderLab() {
    const grid = $('lab-grid');
    clear(grid);
    state.config.attacks.forEach(function (attack, index) {
      const card = el('article', { class: 'card', attrs: { id: 'attack-' + attack.id, 'aria-labelledby': 'attack-title-' + attack.id } });
      const tags = el('div', { class: 'card-tags' }, [chip(BASE_LABELS[attack.base])]);
      if (attack.ghsa) {
        tags.appendChild(el('a', {
          class: 'chip chip-info', text: attack.ghsa,
          attrs: { href: attack.advisory, target: '_blank', rel: 'noopener noreferrer', title: 'Security advisory of the 0.x versions' }
        }, [icon('external')]));
      }
      const runButton = el('button', {
        class: 'btn btn-sm btn-primary', attrs: { type: 'button' },
        on: { click: function () { runAttack(attack.id); } }
      }, [icon('play'), 'Run']);
      const detailsButton = el('button', {
        class: 'btn btn-sm btn-ghost btn-details', text: 'Details',
        attrs: { type: 'button', 'aria-expanded': 'false', 'aria-controls': 'attack-details-' + attack.id, hidden: true },
        on: { click: function () { toggleDetails(attack.id); } }
      });
      card.appendChild(el('div', { class: 'card-main' }, [
        el('div', { class: 'card-top' }, [
          el('span', { class: 'card-num', text: String(index + 1).padStart(2, '0') }),
          el('h3', { text: attack.title, attrs: { id: 'attack-title-' + attack.id } })
        ]),
        el('p', { class: 'card-summary', text: attack.summary }),
        tags,
        el('div', { class: 'card-result', attrs: { hidden: true, 'aria-live': 'polite' } })
      ]));
      card.appendChild(el('div', { class: 'card-foot' }, [runButton, el('div', { class: 'mini-pipeline', attrs: { 'aria-hidden': 'true' } }), detailsButton]));
      card.appendChild(el('div', { class: 'card-details', attrs: { id: 'attack-details-' + attack.id, hidden: true } }));
      grid.appendChild(card);
    });
  }

  function toggleDetails(id, open) {
    const card = $('attack-' + id);
    const details = card.querySelector('.card-details');
    const button = card.querySelector('.btn-details');
    const show = open === undefined ? details.hidden : open;
    details.hidden = !show;
    button.setAttribute('aria-expanded', String(show));
    button.textContent = show ? 'Hide details' : 'Details';
    card.classList.toggle('is-open', show);
  }

  function labInput(id) {
    let data = state.token ? state.token.data : state.config.data;
    return {
      id: id,
      lastXml: state.token ? state.token.xml : null,
      data: data,
      algorithms: state.token ? state.token.algorithms : readAlgorithms('issuer-'),
      receiver: readReceiver()
    };
  }

  async function runAttack(id) {
    const card = $('attack-' + id);
    const runButton = card.querySelector('.card-foot .btn-primary');
    const resultBox = card.querySelector('.card-result');
    runButton.disabled = true;
    clear(runButton);
    runButton.appendChild(el('span', { class: 'spinner', attrs: { 'aria-hidden': 'true' } }));
    runButton.appendChild(document.createTextNode('Running'));
    try {
      const result = await api('/api/attack', labInput(id));
      state.labResults[id] = result;
      renderAttackResult(card, result);
      return result;
    } catch (e) {
      clear(resultBox);
      resultBox.hidden = false;
      resultBox.appendChild(el('p', { class: 'card-message', text: e.message }));
      return null;
    } finally {
      runButton.disabled = false;
      clear(runButton);
      runButton.appendChild(icon('play'));
      runButton.appendChild(document.createTextNode('Run again'));
    }
  }

  function renderAttackResult(card, result) {
    const resultBox = card.querySelector('.card-result');
    const verdict = result.verdict;
    const stop = result.stoppedBy;
    const expectAccepted = result.attack.id === 'script';
    clear(resultBox);
    resultBox.hidden = false;
    card.classList.remove('is-refused', 'is-accepted', 'is-bad');

    const outcome = el('div', { class: 'card-outcome' });
    if (stop) {
      card.classList.add('is-refused');
      outcome.appendChild(chip('Refused', 'ok', 'check'));
      outcome.appendChild(el('span', { text: 'at ' + stop.label }));
      outcome.appendChild(el('span', { class: 'step-by step-by-' + stop.by, text: stop.by === 'caller' ? 'your code' : 'library' }));
      resultBox.appendChild(outcome);
      resultBox.appendChild(el('p', { class: 'card-message', text: stop.by === 'caller' ? stop.message : verdict.error }));
    } else {
      card.classList.add(expectAccepted ? 'is-accepted' : 'is-bad');
      outcome.appendChild(chip('Accepted', expectAccepted ? 'warn' : 'bad', expectAccepted ? 'warn' : 'cross'));
      outcome.appendChild(el('span', { text: expectAccepted ? 'valid token, harmless value' : 'the receiver accepted the forged token' }));
      resultBox.appendChild(outcome);
      if (expectAccepted && verdict.data && verdict.data.note) {
        resultBox.appendChild(el('p', { class: 'card-message', text: 'note = ' + verdict.data.note }));
      }
    }

    const mini = card.querySelector('.mini-pipeline');
    clear(mini);
    verdict.steps.forEach(function (step) {
      mini.appendChild(el('span', { class: 'mini-step', data: { status: step.status }, attrs: { title: step.label + ': ' + step.status } }));
    });
    card.querySelector('.btn-details').hidden = false;

    renderAttackDetails(card.querySelector('.card-details'), result);
  }

  function renderAttackDetails(box, result) {
    clear(box);
    const left = el('div');
    const right = el('div');

    const changes = el('ul', { class: 'changes' });
    result.changes.forEach(function (change) { changes.appendChild(el('li', { text: change })); });
    left.appendChild(el('section', {}, [
      el('h4', { text: 'What the attacker changed' }),
      changes,
      el('p', { class: 'base-note', text: result.base.note })
    ]));
    if (!result.base.verdict.accepted) {
      const baseStop = firstFailure(result.base.verdict);
      left.appendChild(el('p', { class: 'form-error', text: 'Your receiver configuration refuses even the legitimate token' + (baseStop ? ' (at ' + baseStop.label + ')' : '') + ': this attack proves nothing with it.' }));
    }
    const diff = el('div', { class: 'diff', attrs: { tabindex: '0', 'aria-label': 'Difference between the legitimate and the forged token' } });
    renderDiff(diff, result.base.xml, result.forged);
    left.appendChild(el('section', {}, [el('h4', { text: 'Diff: legitimate → forged' }), diff]));

    const pipeline = el('ol', { class: 'pipeline' });
    result.verdict.steps.forEach(function (step) { pipeline.appendChild(stepItem(step)); });
    right.appendChild(el('section', {}, [el('h4', { text: 'Receiver pipeline' }), pipeline]));

    if (result.attack.id === 'script') {
      const note = result.verdict.data && result.verdict.data.note;
      right.appendChild(el('section', {}, [
        el('h4', { text: 'Displayed safely' }),
        el('p', { class: 'step-detail', text: 'This page writes the value as text:' }),
        el('div', { class: 'rendered-value', text: note || '' }),
        result.htmlDump ? el('p', { class: 'step-detail', text: 'getHTMLDump() escapes it:' }) : null,
        result.htmlDump ? el('pre', { class: 'html-dump', text: result.htmlDump }) : null
      ]));
    }

    if (result.attack.history || result.attack.ghsa) {
      const history = el('p', { class: 'history' }, [result.attack.history || '']);
      if (result.attack.ghsa) {
        history.appendChild(el('a', {
          text: result.attack.ghsa,
          attrs: { href: result.attack.advisory, target: '_blank', rel: 'noopener noreferrer' }
        }, [icon('external')]));
      }
      right.appendChild(el('section', {}, [el('h4', { text: 'In the 0.x versions' }), history]));
    }

    box.appendChild(left);
    box.appendChild(right);
  }

  async function runAll() {
    const button = $('run-all');
    button.disabled = true;
    try {
      for (let i = 0; i < state.config.attacks.length; i++) {
        await runAttack(state.config.attacks[i].id);
        await sleep(80);
      }
      toast('All attacks ran.');
    } finally {
      button.disabled = false;
    }
  }

  /* ---------- Start ---------- */

  async function init() {
    initTheme();
    initXmlView();
    initTokenTools();
    initCopyButtons();
    renderXmlView();
    try {
      state.config = await api('/api/config');
    } catch (e) {
      renderVerdictMessage('bad', 'The demo could not start', e.message);
      return;
    }
    if (state.config.version) $('version').textContent = 'v' + state.config.version;
    ['issuer-', 'rc-'].forEach(function (prefix) {
      Object.keys(state.config.algorithms).forEach(function (option) { fillSelect($(prefix + option), option); });
    });
    entries = toEntries(state.config.data);
    renderDataEditor();
    applyReceiverDefaults();
    syncReceiverFields();
    syncEncryptionSelect();
    setReplayMemory(state.config.replayMemory);
    initReceiver();
    renderLab();

    $('issuer-form').addEventListener('submit', function (event) {
      event.preventDefault();
      createToken();
    });
    $('issuer-form').addEventListener('change', function (event) {
      if (event.target.id === 'encrypt') syncEncryptionSelect();
      if (event.target.dataset && event.target.dataset.option) {
        $('rc-' + event.target.dataset.option).value = event.target.value;
        refreshReceiverCode();
      }
      updateAlgoHint();
      refreshIssuerCode();
    });
    $('add-field').addEventListener('click', function () {
      entries.push({ id: ++entryCounter, key: 'key' + (entries.length + 1), value: 'value', children: null });
      renderDataEditor();
      onDataChange();
      const inputs = $('data-editor').querySelectorAll('.data-key input');
      if (inputs.length) inputs[inputs.length - 1].focus();
    });
    $('run-all').addEventListener('click', runAll);

    updateAlgoHint();
    resetVerification('Create a token, then verify it: each check lights up in turn.');
    refreshReceiverCode();
    await createToken();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
