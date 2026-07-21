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
// who isn't a lawyer — purely a UX nicety, every one of these is independently
// enforced server-side via requireRole() so this is not the real security boundary.
const LAWYER_ONLY_PAGES = ['billing', 'reports', 'users', 'permissions'];

function initPageChrome() {
  const user = requireAuth();
  if (!user) return;

  const nameEl = document.getElementById('userName');
  const roleEl = document.getElementById('userRole');
  const avatarEl = document.getElementById('userAvatar');
  if (nameEl) nameEl.innerText = user.fullName || user.username;
  if (roleEl) roleEl.innerText = user.role.charAt(0).toUpperCase() + user.role.slice(1);
  if (avatarEl) avatarEl.innerText = (user.fullName || user.username || 'U').charAt(0).toUpperCase();

  if (user.role !== 'lawyer') {
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
  document.getElementById('hamburger-btn')?.addEventListener('click', () => {
    sidebar.classList.toggle('open');
    overlay.classList.toggle('show');
  });
  document.getElementById('sidebar-close-btn')?.addEventListener('click', () => {
    sidebar.classList.remove('open');
    overlay.classList.remove('show');
  });
  overlay?.addEventListener('click', () => {
    sidebar.classList.remove('open');
    overlay.classList.remove('show');
  });

  const userPill = document.getElementById('userPill');
  const dropdownMenu = document.getElementById('dropdownMenu');
  userPill?.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdownMenu.classList.toggle('show');
  });
  document.addEventListener('click', () => dropdownMenu?.classList.remove('show'));

  document.getElementById('logoutBtn')?.addEventListener('click', logout);

  return user;
}
