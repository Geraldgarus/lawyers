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

// Nav items whose href matches one of these page names are hidden for anyone
// who isn't a lawyer or admin — purely a UX nicety, every one of these is
// independently enforced server-side via requireCapability() so this is not
// the real security boundary.
const LAWYER_ONLY_PAGES = ['billing', 'reports', 'case-status-report', 'recent-activity', 'users', 'permissions'];
const hasFullAccessUI = user => user.role === 'lawyer' || user.role === 'admin';

function initPageChrome() {
  const user = requireAuth();
  if (!user) return;

  const nameEl = document.getElementById('userName');
  const roleEl = document.getElementById('userRole');
  const avatarEl = document.getElementById('userAvatar');
  if (nameEl) nameEl.innerText = user.fullName || user.username;
  if (roleEl) roleEl.innerText = user.role.charAt(0).toUpperCase() + user.role.slice(1);
  if (avatarEl) avatarEl.innerText = (user.fullName || user.username || 'U').charAt(0).toUpperCase();

  if (!hasFullAccessUI(user)) {
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
      if (LAWYER_ONLY_PAGES.includes(item.dataset.page)) item.style.display = 'none';
    });
  }

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
