import { create } from 'zustand';
import apiClient from '../lib/api';
import { wsClient } from '../lib/websocket';

interface AuthState {
  token: string | null;
  user: { user_id: string; role: string } | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem('token'),
  user: null,
  
  login: async (username, password) => {
    console.debug('[Auth] Logging in...');
    const response = await apiClient.post('/api/v1/auth/login', { username, password });
    const { access_token, user_id, role } = response.data;
    
    localStorage.setItem('token', access_token);
    set({ token: access_token, user: { user_id, role } });
    
    wsClient.connect(access_token);
    console.debug('[Auth] Login successful');
  },
  
  logout: () => {
    console.debug('[Auth] Logging out');
    localStorage.removeItem('token');
    wsClient.disconnect();
    set({ token: null, user: null });
  },
  
  checkAuth: async () => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const response = await apiClient.get('/api/v1/auth/me');
        set({ user: response.data, token });
        wsClient.connect(token);
        console.debug('[Auth] Auth check successful');
      } catch (error) {
        localStorage.removeItem('token');
        set({ token: null, user: null });
        console.debug('[Auth] Auth check failed');
      }
    }
  },
}));

