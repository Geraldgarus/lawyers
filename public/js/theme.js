// Site-wide light/dark theme toggle. Applied as early as possible (this
// script must be loaded in <head>, before the body renders) so the
// correct theme is set before first paint — no flash of the wrong theme.
(function () {
  var THEME_KEY = 'theme';

  function getStoredTheme() {
    try { return localStorage.getItem(THEME_KEY); } catch (e) { return null; }
  }

  function setStoredTheme(theme) {
    try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    syncToggleIcons(theme);
  }

  function syncToggleIcons(theme) {
    var icons = document.querySelectorAll('.theme-toggle-btn i');
    icons.forEach(function (icon) {
      icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    });
    var btns = document.querySelectorAll('.theme-toggle-btn');
    btns.forEach(function (btn) {
      btn.title = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
    });
  }

  window.toggleTheme = function () {
    var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    var next = current === 'dark' ? 'light' : 'dark';
    setStoredTheme(next);
    applyTheme(next);
  };

  // Apply immediately, before the rest of the page parses.
  applyTheme(getStoredTheme() === 'dark' ? 'dark' : 'light');

  // Icons don't exist in the DOM yet at this point (script runs in <head>),
  // so re-sync once the navbar markup is actually there.
  document.addEventListener('DOMContentLoaded', function () {
    syncToggleIcons(document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
  });
})();
