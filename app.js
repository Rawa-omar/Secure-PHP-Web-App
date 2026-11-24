// SecurePortal front-end helpers.
// JavaScript is only a convenience: every rule here is enforced again in PHP.
// User-related text is always written with textContent, never innerHTML (prevents DOM XSS).
(function () {
  'use strict';

  // ---------- Show / hide password ----------
  function addPasswordToggles() {
    document.querySelectorAll('input[type="password"]').forEach(function (input) {
      var wrap = document.createElement('span');
      wrap.className = 'pw-wrap';
      input.parentNode.insertBefore(wrap, input);
      wrap.appendChild(input);

      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'pw-toggle';
      btn.textContent = 'Show';
      btn.setAttribute('aria-label', 'Show password');
      btn.setAttribute('aria-pressed', 'false');
      wrap.appendChild(btn);

      btn.addEventListener('click', function () {
        var show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        btn.textContent = show ? 'Hide' : 'Show';
        btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        btn.setAttribute('aria-pressed', show ? 'true' : 'false');
        input.focus();
      });
    });
  }

  // ---------- Password strength meter ----------
  function passwordScore(pw) {
    var score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    if (pw.length < 8) score = Math.min(score, 1);   // too short is always weak
    return score;                                     // 0 to 5
  }

  function addStrengthMeter(input) {
    var meter = document.createElement('div');
    meter.className = 'meter';
    var bar = document.createElement('div');
    bar.className = 'meter-bar';
    meter.appendChild(bar);

    var label = document.createElement('p');
    label.className = 'meter-label hint';
    label.setAttribute('aria-live', 'polite');

    var anchor = input.closest('.pw-wrap') || input;
    anchor.insertAdjacentElement('afterend', label);
    anchor.insertAdjacentElement('afterend', meter);

    var levels = [
      { text: 'Weak', cls: 'weak' },
      { text: 'Weak', cls: 'weak' },
      { text: 'Fair', cls: 'fair' },
      { text: 'Good', cls: 'good' },
      { text: 'Strong', cls: 'strong' },
      { text: 'Strong', cls: 'strong' }
    ];

    function update() {
      var pw = input.value;
      if (pw === '') {
        bar.style.width = '0';
        bar.className = 'meter-bar';
        label.textContent = '';
        return;
      }
      var s = passwordScore(pw);
      bar.style.width = (Math.max(s, 1) / 5 * 100) + '%';
      bar.className = 'meter-bar ' + levels[s].cls;
      label.textContent = 'Password strength: ' + levels[s].text;
    }
    input.addEventListener('input', update);
    update();
  }

  // ---------- Live form validation ----------
  var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  function messageFor(input) {
    var id = input.id + '-msg';
    var el = document.getElementById(id);
    if (!el) {
      el = document.createElement('p');
      el.id = id;
      el.className = 'field-msg';
      el.setAttribute('aria-live', 'polite');
      var anchor = input.closest('.pw-wrap') || input;
      anchor.insertAdjacentElement('afterend', el);
      input.setAttribute('aria-describedby', id);
    }
    return el;
  }

  function setupValidation(form, rules) {
    var touched = {};

    function check(name) {
      var input = form.elements[name];
      if (!input) return true;
      var error = rules[name](input.value, form);
      var msg = messageFor(input);
      msg.textContent = error || '';
      input.classList.toggle('invalid', !!error);
      input.setAttribute('aria-invalid', error ? 'true' : 'false');
      return !error;
    }

    Object.keys(rules).forEach(function (name) {
      var input = form.elements[name];
      if (!input) return;
      input.addEventListener('blur', function () {
        touched[name] = true;
        check(name);
      });
      input.addEventListener('input', function () {
        if (touched[name]) check(name);
        // re-check confirm when the password changes
        if (name === 'password' && touched.confirm) check('confirm');
      });
    });

    form.addEventListener('submit', function (ev) {
      var firstBad = null;
      Object.keys(rules).forEach(function (name) {
        touched[name] = true;
        if (!check(name) && !firstBad) firstBad = form.elements[name];
      });
      if (firstBad) {
        ev.preventDefault();
        firstBad.focus();
      }
    });
  }

  var registerRules = {
    name: function (v) {
      v = v.trim();
      if (v === '') return 'Enter your name.';
      if (v.length > 100) return 'Your name can be up to 100 characters.';
      return '';
    },
    mobile: function (v) {
      return /^\+?[0-9]{9,15}$/.test(v.trim()) ? '' : 'Enter 9 to 15 digits (for example 0501234567).';
    },
    email: function (v) {
      v = v.trim();
      if (!EMAIL_RE.test(v)) return 'Enter a valid email address.';
      if (v.length > 150) return 'Email can be up to 150 characters.';
      return '';
    },
    password: function (v) {
      return v.length >= 8 ? '' : 'Use at least 8 characters.';
    },
    confirm: function (v, form) {
      if (v === '') return 'Type your password again.';
      return v === form.elements.password.value ? '' : 'The two passwords do not match.';
    }
  };

  var loginRules = {
    email: function (v) {
      v = v.trim();
      if (v === '') return 'Enter your email.';
      return EMAIL_RE.test(v) ? '' : 'Enter a valid email address.';
    },
    password: function (v) {
      return v === '' ? 'Enter your password.' : '';
    }
  };

  // ---------- Warning before automatic logout ----------
  function setupTimeoutWarning() {
    var seconds = parseInt(document.body.getAttribute('data-idle-timeout'), 10);
    if (!(seconds > 0)) return;

    var WARN_BEFORE = 120;                               // show the warning 2 minutes before logout
    var deadline = Date.now() + seconds * 1000;

    setTimeout(showWarning, Math.max(seconds - WARN_BEFORE, 0) * 1000);

    function showWarning() {
      var box = document.createElement('div');
      box.className = 'timeout-warning';
      box.setAttribute('role', 'alert');

      var text = document.createElement('p');
      var count = document.createElement('strong');
      text.appendChild(document.createTextNode('You will be logged out in '));
      text.appendChild(count);
      text.appendChild(document.createTextNode(' because of inactivity.'));

      var stay = document.createElement('button');
      stay.type = 'button';
      stay.className = 'btn btn-small';
      stay.textContent = 'Stay logged in';
      stay.addEventListener('click', function () {
        window.location.reload();                        // any request resets the server-side timer
      });

      box.appendChild(text);
      box.appendChild(stay);
      document.body.appendChild(box);
      stay.focus();

      function tick() {
        var left = Math.ceil((deadline - Date.now()) / 1000);
        if (left <= 0) {
          clearInterval(timer);
          count.textContent = '0:00';
          // a little after the deadline, so the server has really expired the session
          setTimeout(function () { window.location.href = 'profile.php'; }, 2000);
          return;
        }
        var m = Math.floor(left / 60);
        var s = left % 60;
        count.textContent = m + ':' + (s < 10 ? '0' : '') + s;
      }
      var timer = setInterval(tick, 1000);
      tick();
    }
  }

  // ---------- Start ----------
  addPasswordToggles();

  var registerForm = document.querySelector('form[action="register.php"]');
  if (registerForm) {
    addStrengthMeter(registerForm.elements.password);
    setupValidation(registerForm, registerRules);
  }

  var loginForm = document.querySelector('form[action="login.php"]');
  if (loginForm) {
    setupValidation(loginForm, loginRules);
  }

  setupTimeoutWarning();
})();
