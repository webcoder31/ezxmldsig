/*
 * Home page of the SSO demo: the protections of the live demo, and the
 * attack lab (GET /lab.json, POST /settings, POST /lab/run).
 *
 * Every value is written with textContent: the script builds no markup from
 * strings.
 */
(function () {
  'use strict';

  const PROTECTIONS = {
    audience: ['Audience', 'IDP addresses each token to its application, which checks it (audience, expectedAudience).'],
    returnUrl: ['Return address', 'IDP only posts a token to the address registered for the application.'],
    freshness: ['Freshness', 'Each application refuses a token that is out of date (isOutOfDate()).'],
    replay: ['Replay', 'Each application refuses a token it has already accepted (getTokenId()).'],
    encrypt: ['Encryption', 'IDP encrypts each token for its application, with the certificate of that application. An option rather than a protection.']
  };
  const BY = { library: 'library', application: 'application', idp: 'IDP' };

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
      if (child) node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  async function post(path, fields) {
    const response = await fetch(path, { method: 'POST', body: new URLSearchParams(fields) });
    const data = await response.json().catch(function () { return {}; });
    if (!response.ok) throw new Error(data.error || 'The server refused the request (HTTP ' + response.status + ').');
    return data;
  }

  function renderSettings(settings) {
    const form = document.getElementById('protection-form');
    clear(form);
    Object.keys(PROTECTIONS).forEach(function (name) {
      const input = el('input', { type: 'checkbox', role: 'switch', id: 'setting-' + name });
      input.checked = !!settings[name];
      input.addEventListener('change', async function () {
        input.disabled = true;
        try {
          const fields = {};
          fields[name] = String(input.checked);
          renderSettings((await post('/settings', fields)).settings);
        } catch (e) {
          input.checked = !input.checked;
          window.alert(e.message);
        } finally {
          input.disabled = false;
        }
      });
      form.appendChild(el('label', { class: 'switch protection' }, [
        input,
        el('span', { class: 'switch-track', 'aria-hidden': 'true' }, [el('span', { class: 'switch-thumb' })]),
        el('span', { class: 'switch-label' }, [
          el('strong', { text: PROTECTIONS[name][0] }),
          el('span', { class: 'muted', text: PROTECTIONS[name][1] })
        ])
      ]));
    });
  }

  function renderResult(box, result) {
    clear(box);
    const stopped = result.stoppedBy;
    const verdict = result.accepted
      ? el('div', { class: 'lab-verdict is-bad' }, [
        el('strong', { text: 'The attack succeeds' }),
        el('span', { text: result.protected ? '' : ' — protection off: the attacker gets a session as the victim.' })
      ])
      : el('div', { class: 'lab-verdict is-ok' }, [
        el('strong', { text: 'Refused' }),
        el('span', { text: stopped ? ' at ' + stopped.label + ' ' : '' }),
        stopped ? el('span', { class: 'step-by step-by-' + (stopped.by === 'application' ? 'caller' : (stopped.by === 'idp' ? 'idp' : 'library')), text: BY[stopped.by] }) : null,
        stopped && stopped.message ? el('p', { class: 'step-message', text: stopped.message }) : null
      ]);
    box.appendChild(verdict);
    const list = el('ol', { class: 'lab-events' });
    result.events.forEach(function (event) {
      list.appendChild(el('li', { 'data-kind': event.kind }, [
        el('code', { text: event.from === event.to ? siteName(event.from) : siteName(event.from) + ' → ' + siteName(event.to) }),
        ' ' + event.title
      ]));
    });
    const details = el('details', { class: 'code-details' }, [el('summary', { text: 'What happened (' + result.events.length + ' steps)' }), list]);
    box.appendChild(details);
  }

  function card(attack) {
    const result = el('div', { class: 'lab-result', 'aria-live': 'polite' });
    let toggle = null;
    if (attack.protection) {
      toggle = el('input', { type: 'checkbox', id: 'protect-' + attack.id });
      toggle.checked = true;
    }
    const run = el('button', { type: 'button', class: 'btn btn-primary btn-sm', text: 'Run' });
    run.addEventListener('click', async function () {
      run.disabled = true;
      clear(result);
      result.appendChild(el('p', { class: 'muted', text: 'Running…' }));
      try {
        renderResult(result, await post('/lab/run', { id: attack.id, protected: String(toggle ? toggle.checked : true) }));
      } catch (e) {
        clear(result);
        result.appendChild(el('p', { class: 'step-message', text: e.message }));
      } finally {
        run.disabled = false;
      }
    });
    const foot = el('div', { class: 'lab-foot' }, [
      toggle
        ? el('label', { class: 'check' }, [toggle, el('span', {}, ['Protection on ', el('span', { class: 'muted', text: '(' + PROTECTIONS[attack.protection][0] + ')' })])])
        : el('span', { class: 'muted', text: 'Stopped by the library: no switch.' }),
      run
    ]);
    return el('article', { class: 'lab-card', id: 'attack-' + attack.id }, [
      el('header', { class: 'lab-head' }, [
        el('h3', { text: attack.title }),
        el('span', { class: 'step-by step-by-' + (attack.by === 'application' ? 'caller' : (attack.by === 'idp' ? 'idp' : 'library')), text: 'stopped by ' + BY[attack.by] })
      ]),
      el('p', { text: attack.summary }),
      el('p', { class: 'hint', text: attack.lesson }),
      foot,
      result
    ]);
  }

  async function init() {
    const cards = document.getElementById('lab-cards');
    if (!cards) return;
    let config;
    try {
      const response = await fetch('/lab.json', { cache: 'no-store' });
      config = await response.json();
    } catch (e) {
      cards.appendChild(el('p', { class: 'step-message', text: 'The lab could not start: ' + e.message }));
      return;
    }
    renderSettings(config.settings);
    config.attacks.forEach(function (attack) { cards.appendChild(card(attack)); });
    document.getElementById('run-all').addEventListener('click', async function () {
      const buttons = cards.querySelectorAll('.lab-foot .btn-primary');
      for (let i = 0; i < buttons.length; i++) {
        buttons[i].click();
        // One run at a time: the PHP built-in server answers one request at a time.
        await new Promise(function (resolve) {
          const wait = window.setInterval(function () {
            if (!buttons[i].disabled) { window.clearInterval(wait); resolve(); }
          }, 100);
        });
      }
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
