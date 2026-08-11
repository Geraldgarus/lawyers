function getCurrentUser() {
  const raw = sessionStorage.getItem('advocate_user');
  return raw ? JSON.parse(raw) : null;
}

function requireAuth() {
  const user = getCurrentUser();
  if (!user) {
    window.location.href = '/';
    return null;
  }
  return user;
}

async function logout() {
  try { await apiPost('/auth/logout', {}); } catch (e) { /* ignore */ }
  sessionStorage.clear();
  window.location.href = '/';
}

// The logged-in user's granted capabilities, fetched once per page load and
// cached — every page/button gate should check against this (via
// getMyCapabilities()) rather than the user's role string, so a role's
// capabilities as saved on Permissions & Access actually take effect. This
// is a UX nicety only; every one of these is independently enforced
// server-side via requireCapability() so it's not the real security
// boundary, but it must stay in sync with it or granted access looks broken.
let __capabilitiesPromise = null;
function getMyCapabilities() {
  if (!__capabilitiesPromise) {
    __capabilitiesPromise = apiGet('/my-capabilities').then(r => r.capabilities || []).catch(() => []);
  }
  return __capabilitiesPromise;
}

// Which capability a sidebar nav item requires to be shown at all. Pages not
// listed here have no capability gate (open to every authenticated role).
const PAGE_CAPABILITY = {
  billing: 'view_billing',
  reports: 'view_reports',
  'case-status-report': 'view_reports',
  'recent-activity': 'view_reports',
  users: 'manage_users',
  permissions: 'manage_users',
  settings: 'manage_settings',
};

function initPageChrome() {
  const user = requireAuth();
  if (!user) return;

  const nameEl = document.getElementById('userName');
  const roleEl = document.getElementById('userRole');
  const avatarEl = document.getElementById('userAvatar');
  if (nameEl) nameEl.innerText = user.fullName || user.username;
  if (roleEl) roleEl.innerText = user.role.charAt(0).toUpperCase() + user.role.slice(1);
  if (avatarEl) avatarEl.innerText = (user.fullName || user.username || 'U').charAt(0).toUpperCase();

  getMyCapabilities().then(caps => {
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
      const needed = PAGE_CAPABILITY[item.dataset.page];
      if (needed && !caps.includes(needed)) item.style.display = 'none';
    });
  });

  const currentPage = window.location.pathname.replace('/', '') || 'dashboard';
  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    if (item.dataset.page === currentPage) item.classList.add('active');
  });

  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('overlay-main');
  // 'open' controls the mobile off-canvas drawer, 'collapsed' controls the
  // desktop pinned sidebar — opposite defaults per breakpoint (see
  // style.css), so a single toggle flips both together and CSS decides
  // which one actually matters at the current width.
  document.getElementById('hamburger-btn')?.addEventListener('click', () => {
    sidebar.classList.toggle('open');
    sidebar.classList.toggle('collapsed');
    overlay.classList.toggle('show');
    document.body.classList.toggle('sidebar-collapsed');
  });
  const closeSidebar = () => {
    sidebar.classList.remove('open');
    sidebar.classList.add('collapsed');
    overlay.classList.remove('show');
    document.body.classList.add('sidebar-collapsed');
  };
  document.getElementById('sidebar-close-btn')?.addEventListener('click', closeSidebar);
  overlay?.addEventListener('click', closeSidebar);

  const userPill = document.getElementById('userPill');
  const dropdownMenu = document.getElementById('dropdownMenu');
  userPill?.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdownMenu.classList.toggle('show');
  });
  document.addEventListener('click', () => dropdownMenu?.classList.remove('show'));

  document.getElementById('logoutBtn')?.addEventListener('click', logout);

  enforcePageAccess();

  return user;
}

// Pages an admin hasn't customized are unrestricted for that user (their
// normal role-based set); the moment any grant is saved for them, they can
// only reach exactly what's listed — both in the sidebar and by direct URL.
// Runs fire-and-forget from initPageChrome() (rather than making it — and
// every page's synchronous `const user = initPageChrome()` call site —
// async) so a denied page blanks itself and redirects as soon as the check
// resolves, using the user's own JWT-authenticated identity as the source
// of truth, not anything spoofable client-side.
async function enforcePageAccess() {
  const pageKey = window.location.pathname.replace('/', '') || 'dashboard';
  try {
    const { customized, pages } = await apiGet('/permissions/me');
    if (!customized) return;

    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
      if (item.dataset.page !== 'dashboard' && !pages.includes(item.dataset.page)) item.style.display = 'none';
    });

    if (pageKey !== 'dashboard' && pageKey !== 'case-detail' && !pages.includes(pageKey)) {
      document.body.innerHTML = '<div class="empty-state" style="padding:80px 20px;"><i class="fas fa-lock"></i>You do not have access to this page. Redirecting…</div>';
      document.body.classList.add('loaded');
      setTimeout(() => { window.location.href = '/dashboard'; }, 900);
    }
  } catch (e) { /* fail open — don't lock a user out over a network hiccup */ }
}
