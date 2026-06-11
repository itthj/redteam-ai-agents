// Thin API client for the redteam-ai-agents backend.
// Configure with VITE_API_BASE (default http://localhost:8000) and, if the backend
// has API_SECRET_KEY set, VITE_API_KEY. The /events SSE stream is open (no key).

const BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';
const KEY = import.meta.env.VITE_API_KEY || '';
const authHeaders = KEY ? { 'X-API-Key': KEY } : {};

export const API_BASE = BASE;

export async function getJSON(path) {
  const r = await fetch(BASE + path, { headers: authHeaders });
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}

export async function post(path, body) {
  return fetch(BASE + path, {
    method: 'POST',
    headers: { ...authHeaders, 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
}

export function eventSource() {
  return new EventSource(BASE + '/events');
}
