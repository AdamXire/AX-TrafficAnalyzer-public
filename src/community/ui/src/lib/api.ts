import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8443';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - add JWT token
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  console.debug('[API] Request:', config.method, config.url);
  return config;
});

// Response interceptor - handle 401
apiClient.interceptors.response.use(
  (response) => {
    console.debug('[API] Response:', response.status, response.config.url);
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    console.error('[API] Error:', error.response?.status, error.message);
    return Promise.reject(error);
  }
);

export default apiClient;

