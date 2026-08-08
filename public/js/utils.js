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

// Formats a "HH:MM[:SS]" time-only string (e.g. a court/consultation
// start/end time) as "h:MM AM/PM" — shared because print-timechart.js
// (used on both case-detail.html and case-status-report.html) needs it.
function fmtTimeStr(t) {
  if (!t) return '—';
  const [h, m] = String(t).split(':').map(Number);
  const period = h >= 12 ? 'PM' : 'AM';
  const h12 = h % 12 || 12;
  return `${h12}:${String(m).padStart(2, '0')} ${period}`;
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

// Case status is now the Time Chart's court-proceeding stage — a few of
// those slugs (the PTC ones) don't title-case cleanly on their own
// ("first_ptc" -> "First Ptc" instead of "1st PTC"), so they're spelled
// out explicitly; everything else still falls through to generic title-case.
const STAGE_LABELS = {
  mention: 'Mention', first_ptc: '1st PTC', mediation: 'Mediation',
  hearing: 'Hearing', final_ptc: 'Final PTC', judgment: 'Judgment', ruling: 'Ruling'
};
function statusLabel(status) {
  if (STAGE_LABELS[status]) return STAGE_LABELS[status];
  return String(status || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
