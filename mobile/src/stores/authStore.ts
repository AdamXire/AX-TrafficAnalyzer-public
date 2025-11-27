/**
 * AX-TrafficAnalyzer Mobile - Auth Store
 * Copyright © 2025 MMeTech (Macau) Ltd.
 */

import { create } from 'zustand';
import { api } from '../api/client';

interface AuthState {
  isAuthenticated: boolean;
  token: string | null;
  serverUrl: string;
  loading: boolean;
  error: string | null;
  
  setServerUrl: (url: string) => void;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  checkConnection: () => Promise<boolean>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  isAuthenticated: false,
  token: null,
  serverUrl: '',
  loading: false,
  error: null,
  
  setServerUrl: (url: string) => {
    console.log('[AUTH] Setting server URL:', url);
    api.setBaseURL(url);
    set({ serverUrl: url, error: null });
  },
  
  login: async (username: string, password: string) => {
    console.log('[AUTH] Login attempt');
    set({ loading: true, error: null });
    
    try {
      const response = await api.login(username, password);
      set({
        isAuthenticated: true,
        token: response.access_token,
        loading: false,
      });
      console.log('[AUTH] Login successful');
      return true;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Login failed';
      console.log('[AUTH] Login failed:', message);
      set({ loading: false, error: message });
      return false;
    }
  },
  
  logout: () => {
    console.log('[AUTH] Logout');
    api.clearToken();
    set({ isAuthenticated: false, token: null });
  },
  
  checkConnection: async () => {
    console.log('[AUTH] Checking connection');
    try {
      await api.getHealth();
      console.log('[AUTH] Connection OK');
      return true;
    } catch {
      console.log('[AUTH] Connection failed');
      set({ error: 'Cannot connect to server' });
      return false;
    }
  },
}));

