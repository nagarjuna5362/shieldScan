export const API_BASE = import.meta.env.VITE_API_URL || '/api';
export const BACKEND_ROOT = API_BASE.replace(/\/api\/?$/, '');
