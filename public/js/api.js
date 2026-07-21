// API Configuration
const API_BASE = '/api';

function getAuthToken() {
  return sessionStorage.getItem('token');
}

function handleUnauthorized(response) {
  if (response.status === 401 || response.status === 403) {
    // Only kill the session on genuine auth failure (401), not permission
    // denials (403) — a 403 means "logged in but not allowed", not "logged out".
    if (response.status === 401) {
      sessionStorage.clear();
      window.location.href = '/';
    }
  }
  return response;
}

async function apiFetch(path, opts = {}) {
  const token = getAuthToken();
  const headers = {
    ...(opts.body && !(opts.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}),
    ...(token && { 'Authorization': `Bearer ${token}` }),
    ...opts.headers
  };
  const res = await fetch(API_BASE + path, { ...opts, headers });
  handleUnauthorized(res);
  let data;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
  return data;
}

async function apiGet(path) {
  return apiFetch(path);
}

async function apiPost(path, body) {
  const isForm = body instanceof FormData;
  return apiFetch(path, { method: 'POST', body: isForm ? body : JSON.stringify(body) });
}

async function apiPut(path, body) {
  return apiFetch(path, { method: 'PUT', body: JSON.stringify(body) });
}

async function apiDelete(path) {
  return apiFetch(path, { method: 'DELETE' });
}
