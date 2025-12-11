// public/js/register.js
// Client-side validation for the registration form

(function () {

  function $(id) { return document.getElementById(id); }

  // Show or clear an error message for a specific field
  function setError(id, msg) {
    const el = $('err-' + id);
    if (el) el.textContent = msg || '';

    const input = $(id);
    if (input) {
      if (msg) input.classList.add('input-invalid');
      else input.classList.remove('input-invalid');
    }
  }

  // Email pattern check
  function isEmail(v) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  }

  // Field by field validation rules
  function validateField(id) {
    const value = ($(id) && $(id).value || '').trim();

    switch (id) {
      case 'first':
      case 'last':
        if (!value) return 'Required';
        return '';

      case 'email':
        if (!value) return 'Required';
        if (!isEmail(value)) return 'Enter a valid email address';
        return '';

      case 'username':
        if (!value) return 'Required';
        if (value.length < 5 || value.length > 30) return 'Username must be 5–30 characters';
        return '';

      case 'password':
        if (!value) return 'Required';
        if (value.length < 8) return 'Password must be at least 8 characters';
        if (!/[a-z]/.test(value)) return 'Must include a lowercase letter';
        if (!/[A-Z]/.test(value)) return 'Must include an uppercase letter';
        if (!/[0-9]/.test(value)) return 'Must include a number';
        if (!/[^A-Za-z0-9]/.test(value)) return 'Must include a special character';
        return '';

      default:
        return '';
    }
  }

  // Hook up blur + input listeners for live validation
  function wireField(id) {
    const el = $(id);
    if (!el) return;

    el.addEventListener('blur', function () {
      setError(id, validateField(id));
    });

    el.addEventListener('input', function () {
      // Clear error while typing
      setError(id, '');
    });
  }

  // Fields to validate
  const fields = ['first', 'last', 'email', 'username', 'password'];

  document.addEventListener('DOMContentLoaded', function () {
    // Activate per-field validation
    fields.forEach(wireField);

    const form = $('registerForm');
    if (!form) return;

    // Final check on submit
    form.addEventListener('submit', function (e) {
      let ok = true;

      fields.forEach(function (f) {
        const err = validateField(f);
        setError(f, err);
        if (err) ok = false;
      });

      if (!ok) {
        e.preventDefault();

        // Move focus to the first invalid field
        for (let f of fields) {
          if ($(f) && $(f).classList.contains('input-invalid')) {
            $(f).focus();
            break;
          }
        }
      }
    });
  });
})();
