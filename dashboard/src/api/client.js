import axios from 'axios';

const API = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  timeout: 10000,
});

export default API;

// ── Endpoints ───────────────────────────────────────────────
export const checkHealth  = ()          => API.get('/api/v1/health');
export const predictUrl   = (url)       => API.post('/api/v1/predict',  { url });
export const submitFeedback = (payload) => API.post('/api/v1/feedback', payload);
export const getStats     = ()          => API.get('/api/v1/stats');
export const getHistory   = (limit=200) => API.get(`/api/v1/history?limit=${limit}`);
export const getAdminLogs = ()          => API.get('/api/v1/admin/logs');

