/*
 * The page of idp that sends the token: the browser posts the form to the
 * application after a few seconds, long enough to read where it goes, unless
 * the user pauses it. Without JavaScript, the button posts it.
 */
(function () {
  'use strict';

  const DELAY = 4;

  function init() {
    const form = document.getElementById('post-token');
    const counter = document.getElementById('post-countdown');
    const pause = document.getElementById('post-pause');
    if (!form || !counter || !pause) return;
    let left = DELAY;
    let paused = false;
    let sent = false;
    const action = form.getAttribute('action');

    // The token is posted once: a second post would be refused as a replay.
    form.addEventListener('submit', function (event) {
      if (sent) {
        event.preventDefault();
        return;
      }
      sent = true;
      window.clearInterval(timer);
      counter.textContent = 'Posting the token to ' + action + '…';
      form.querySelectorAll('button').forEach(function (button) { button.disabled = true; });
    });

    function show() {
      counter.textContent = paused
        ? 'Paused. Post the token when you are ready.'
        : 'Posting the token to ' + action + ' in ' + left + ' s…';
    }

    const timer = window.setInterval(function () {
      if (paused) return;
      left -= 1;
      if (left <= 0) {
        // requestSubmit() fires the submit event, unlike submit().
        if (typeof form.requestSubmit === 'function') form.requestSubmit();
        else if (!sent) { sent = true; window.clearInterval(timer); form.submit(); }
        return;
      }
      show();
    }, 1000);

    pause.addEventListener('click', function () {
      paused = !paused;
      pause.setAttribute('aria-pressed', String(paused));
      pause.textContent = paused ? 'Resume' : 'Pause';
      show();
    });
    show();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
