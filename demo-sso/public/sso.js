/*
 * Trace of the SSO demo: shows, on every site, what the three sites did and
 * what passed between them (GET /trace.json), as a sequence of hops between
 * four lanes: the browser, idp, mail and crm.
 *
 * Every value is written with textContent: the script builds no markup from
 * strings.
 */
(function () {
  'use strict';

  const LANES = ['browser', 'idp', 'mail', 'crm'];
  const KIND_LABEL = { ok: 'accepted', bad: 'refused', sso: 'single sign-on', info: '' };
  // The newest event shown: undefined until the first render, so that an
  // empty trace (newest NULL) is drawn too.
  let lastId;
  const open = {};

  /** The name of a party of the trace as the pages write it: the sites in
      capitals (IDP, MAIL, CRM), the browser as it is. */
  function siteName(party) {
    return party === 'browser' ? party : String(party).toUpperCase();
  }

  function el(tag, props, children) {
    const node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (key) {
        if (key === 'text') node.textContent = props[key];
        else if (key === 'class') node.className = props[key];
        else node.setAttribute(key, props[key]);
      });
    }
    (children || []).forEach(function (child) {
      if (child) node.appendChild(child);
    });
    return node;
  }

  /* ---------- XML ---------- */

  const XML_TOKEN_RE = /<\?[\s\S]*?\?>|<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<\/?[^<>]+>|[^<]+/g;
  const XML_ATTR_RE = /([^\s=]+)\s*=\s*("[^"]*"|'[^']*')/g;

  /** The spans of a tag name: its prefix, then its local name. */
  function xmlName(name) {
    const colon = name.indexOf(':');
    return colon < 0
      ? [el('span', { class: 'x-name', text: name })]
      : [el('span', { class: 'x-prefix', text: name.slice(0, colon + 1) }), el('span', { class: 'x-name', text: name.slice(colon + 1) })];
  }

  /** The spans of an opening or closing tag. */
  function xmlTag(raw) {
    const match = /^<(\/?)([^\s/>]+)([\s\S]*?)(\/?)>$/.exec(raw);
    if (!match) return [el('span', { class: 'x-text', text: raw })];
    const spans = [el('span', { class: 'x-punct', text: '<' + match[1] })].concat(xmlName(match[2]));
    let attr;
    XML_ATTR_RE.lastIndex = 0;
    while ((attr = XML_ATTR_RE.exec(match[3])) !== null) {
      spans.push(document.createTextNode(' '), el('span', { class: 'x-attr', text: attr[1] }), el('span', { class: 'x-eq', text: '=' }), el('span', { class: 'x-value', text: attr[2] }));
    }
    spans.push(el('span', { class: 'x-punct', text: match[4] + '>' }));
    return spans;
  }

  /**
   * Fills a <pre> with an XML document, one tag per line, indented, and
   * coloured as in the token demo. An element that holds only text keeps
   * it on its line; the lines of a long text go under it. Each line is a
   * block indented by its depth: a line too long for the panel wraps under
   * itself, not at the left edge.
   */
  function showXml(pre, xml) {
    const tokens = (xml.match(XML_TOKEN_RE) || []).filter(function (token) { return token.trim() !== ''; });
    const lines = [];
    let depth = 0;
    function push(lineDepth, nodes) { lines.push({ depth: lineDepth, nodes: nodes }); }
    function pushText(lineDepth, text) {
      text.trim().split(/\s*\n\s*/).forEach(function (part) { push(lineDepth, [el('span', { class: 'x-text', text: part })]); });
    }
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (/^<\?|^<!/.test(token)) {
        push(depth, [el('span', { class: 'x-decl', text: token.trim() })]);
      } else if (token.charAt(0) !== '<') {
        pushText(depth, token);
      } else if (token.charAt(1) === '/') {
        depth = Math.max(0, depth - 1);
        push(depth, xmlTag(token));
      } else if (/\/>$/.test(token)) {
        push(depth, xmlTag(token));
      } else if (i + 2 < tokens.length && tokens[i + 1].charAt(0) !== '<' && tokens[i + 2].charAt(1) === '/') {
        if (/\n/.test(tokens[i + 1].trim())) {
          push(depth, xmlTag(token));
          pushText(depth + 1, tokens[i + 1]);
          push(depth, xmlTag(tokens[i + 2]));
        } else {
          push(depth, xmlTag(token).concat([el('span', { class: 'x-text', text: tokens[i + 1].trim() })], xmlTag(tokens[i + 2])));
        }
        i += 2;
      } else {
        push(depth, xmlTag(token));
        depth++;
      }
    }
    pre.textContent = '';
    pre.classList.add('xml-lines');
    lines.forEach(function (line) {
      const row = el('span', { class: 'xml-row' }, line.nodes);
      row.style.setProperty('--depth', String(line.depth));
      pre.appendChild(row);
    });
    return pre;
  }

  /* ---------- PHP ---------- */

  const PHP_RE = /(\/\/[^\n]*)|('(?:[^'\\]|\\.)*')|(\$[A-Za-z_][A-Za-z0-9_]*)|\b(require|use|new|if|null|true|false|throw|return)\b|\b(XMLDSigToken|RuntimeException)\b|(<\?php)/g;

  /** Fills a <pre> with PHP code, coloured as in the token demo. */
  function showPhp(pre, code) {
    pre.textContent = '';
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
    return pre;
  }

  /** The row that draws a hop between two lanes. */
  function hop(event) {
    const from = LANES.indexOf(event.from);
    const to = LANES.indexOf(event.to);
    const row = el('div', { class: 'trace-hop', 'aria-hidden': 'true' });
    LANES.forEach(function (_lane, index) {
      const cell = el('span', { class: 'trace-cell' });
      if (index === from) cell.classList.add('is-from');
      if (index === to) cell.classList.add('is-to');
      if (index > Math.min(from, to) && index < Math.max(from, to)) cell.classList.add('is-through');
      row.appendChild(cell);
    });
    if (from === to) row.classList.add('is-self');
    else row.classList.add(to > from ? 'is-right' : 'is-left');
    row.style.setProperty('--from', String(from));
    row.style.setProperty('--to', String(to));
    return row;
  }

  function steps(list) {
    const ol = el('ol', { class: 'trace-steps' });
    list.forEach(function (step) {
      ol.appendChild(el('li', { 'data-status': step.status }, [
        el('span', { class: 'trace-step-label', text: step.label }),
        el('span', { class: 'step-by step-by-' + step.by, text: step.by === 'caller' ? 'application' : 'library' }),
        step.message ? el('span', { class: 'trace-step-message', text: step.message }) : null
      ]));
    });
    return ol;
  }

  function item(event) {
    const detailsId = 'trace-detail-' + event.id;
    const hasMore = event.detail || event.http || event.xml || event.steps || event.cookie;
    const head = el('div', { class: 'trace-head' }, [
      el('span', { class: 'trace-time', text: event.at }),
      el('span', { class: 'trace-route', text: event.from === event.to ? siteName(event.from) : siteName(event.from) + ' → ' + siteName(event.to) }),
      KIND_LABEL[event.kind] ? el('span', { class: 'trace-kind', text: KIND_LABEL[event.kind] }) : null
    ]);
    const li = el('li', { class: 'trace-item', 'data-kind': event.kind }, [hop(event), head, el('p', { class: 'trace-title', text: event.title })]);
    if (hasMore) {
      const more = el('div', { class: 'trace-more', id: detailsId }, [
        event.detail ? el('p', { text: event.detail }) : null,
        event.http ? el('p', { class: 'trace-http' }, [el('code', { text: event.http })]) : null,
        event.cookie ? el('p', { class: 'trace-cookie' }, [el('code', { text: event.cookie.name }), document.createTextNode(' ' + event.cookie.action + ' on ' + (event.cookie.host || event.cookie.site + '.localhost'))]) : null,
        event.steps ? steps(event.steps) : null,
        event.xml ? showXml(el('pre', { class: 'code trace-xml' }), event.xml) : null
      ]);
      more.hidden = !open[event.id];
      const button = el('button', { type: 'button', class: 'btn btn-ghost btn-xs trace-toggle', 'aria-expanded': String(!!open[event.id]), 'aria-controls': detailsId, text: open[event.id] ? 'Less' : 'Details' });
      button.addEventListener('click', function () {
        open[event.id] = !open[event.id];
        more.hidden = !open[event.id];
        button.setAttribute('aria-expanded', String(open[event.id]));
        button.textContent = open[event.id] ? 'Less' : 'Details';
      });
      li.appendChild(button);
      li.appendChild(more);
    }
    return li;
  }

  function render(events) {
    const list = document.getElementById('trace-list');
    if (!list) return;
    const newest = events.length ? events[events.length - 1].id : null;
    if (newest === lastId) return;
    lastId = newest;
    while (list.firstChild) list.removeChild(list.firstChild);
    if (!events.length) {
      list.appendChild(el('li', { class: 'trace-empty', text: 'Nothing yet. Open MAIL or CRM to start.' }));
      return;
    }
    events.forEach(function (event) { list.appendChild(item(event)); });
    list.lastChild.classList.add('is-new');
    list.scrollTop = list.scrollHeight;
  }

  async function refresh() {
    try {
      const response = await fetch('/trace.json', { cache: 'no-store' });
      if (response.ok) render((await response.json()).events);
    } catch (e) {
      // The server is gone: keep what is shown.
    }
  }

  function init() {
    // The tokens a page shows, written as they were signed.
    document.querySelectorAll('pre[data-xml]').forEach(function (pre) { showXml(pre, pre.textContent); });
    // The code that verified the token.
    document.querySelectorAll('pre[data-php]').forEach(function (pre) { showPhp(pre, pre.textContent); });
    const reset = document.getElementById('trace-reset');
    if (reset) {
      reset.addEventListener('click', async function () {
        reset.disabled = true;
        try {
          await fetch('/trace/reset', { method: 'POST' });
          lastId = undefined;
          // Back to the home page of the demo: the root of mail or crm would
          // start a new login at once.
          window.location.href = document.documentElement.dataset.home || '/';
        } finally {
          reset.disabled = false;
        }
      });
    }
    refresh();
    window.setInterval(refresh, 2000);
    window.addEventListener('focus', refresh);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
