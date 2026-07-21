function isoDate(d) {
  const date = new Date(d);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function fmtDate(d) {
  if (!d) return '—';
  const date = new Date(d);
  return date.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' });
}

function fmtDateShort(d) {
  if (!d) return '—';
  const date = new Date(d);
  return date.toLocaleDateString('en-GB', { month: 'short', day: 'numeric' });
}

function fmtDateTime(d) {
  if (!d) return '—';
  const date = new Date(d);
  return date.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' }) +
    ' ' + date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

function fmtCurrency(n) {
  return 'TSh ' + Number(n || 0).toLocaleString();
}

function isPastDate(d) {
  if (!d) return false;
  return new Date(d) < new Date(new Date().toDateString());
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[m]));
}

function showToast(msg, type = 'success') {
  let tc = document.getElementById('toast-container');
  if (!tc) {
    tc = document.createElement('div');
    tc.id = 'toast-container';
    tc.className = 'toast-container';
    document.body.appendChild(tc);
  }
  const icon = type === 'error' ? 'fa-circle-exclamation' : 'fa-circle-check';
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<i class="fas ${icon}"></i><span>${escapeHtml(msg)}</span>`;
  tc.appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

function setLoading(containerId) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted)"><i class="fas fa-spinner fa-spin"></i> Loading…</div>';
}

function statusLabel(status) {
  return String(status || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
