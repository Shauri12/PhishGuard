import axios from 'axios';

const API = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  timeout: 10000,
});

export default API;

// ── Core Endpoints ───────────────────────────────────────────
export const checkHealth     = ()          => API.get('/api/v1/health');
export const getStats        = ()          => API.get('/api/v1/stats');
export const predictUrl      = (url)       => API.post('/api/v1/predict',  { url });
export const explainUrl      = (url)       => API.post('/api/v1/explain',  { url });
export const submitFeedback  = (payload)   => API.post('/api/v1/feedback', payload);
export const getFeedback     = ()          => API.get('/api/v1/feedback');
export const getHistory      = (limit=200) => API.get(`/api/v1/history?limit=${limit}`);
export const getAdminLogs    = ()          => API.get('/api/v1/admin/logs');

// ── List Management Endpoints ────────────────────────────────
export const getAllowlist    = ()          => API.get('/api/v1/allowlist');
export const addAllowlist    = (url)       => API.post('/api/v1/allowlist', { url });
export const removeAllowlist = (domain)    => API.delete(`/api/v1/allowlist/${encodeURIComponent(domain)}`);

export const getBlocklist    = ()          => API.get('/api/v1/blocklist');
export const addBlocklist    = (url)       => API.post('/api/v1/blocklist', { url });
export const removeBlocklist = (domain)    => API.delete(`/api/v1/blocklist/${encodeURIComponent(domain)}`);
