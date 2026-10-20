/*
 * The login page of idp: each demo account has a button that fills in the
 * form with its user name and password. The user still posts the form.
 */
(function () {
  'use strict';

  function init() {
    const form = document.querySelector('.login-form');
    if (!form) return;
    form.querySelectorAll('button[data-username]').forEach(function (button) {
      button.addEventListener('click', function () {
        form.elements.username.value = button.dataset.username;
        form.elements.password.value = button.dataset.password;
        form.querySelector('button[type="submit"]').focus();
      });
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
