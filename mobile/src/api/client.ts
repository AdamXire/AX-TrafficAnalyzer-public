/**
 * AX-TrafficAnalyzer Mobile - API Client
 * Copyright © 2025 MMeTech (Macau) Ltd.
 */

import axios, { AxiosInstance } from 'axios';

export interface Session {
  session_id: string;
  name: string;
  start_time: string;
  end_time?: string;
  flow_count: number;
  status: string;
}

export interface Flow {
  id: string;
  session_id: string;
  timestamp: string;
  method: string;
  url: string;
  status_code: number;
  content_type?: string;
  request_size: number;
  response_size: number;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
}

class APIClient {
  private client: AxiosInstance;
  private token: string | null = null;

  constructor() {
    this.client = axios.create({
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add auth interceptor
    this.client.interceptors.request.use((config) => {
      if (this.token) {
        config.headers.Authorization = `Bearer ${this.token}`;
      }
      return config;
    });
  }

  setBaseURL(url: string): void {
    this.client.defaults.baseURL = url;
    console.log('[API] Base URL set:', url);
  }

  setToken(token: string): void {
    this.token = token;
    console.log('[API] Token set');
  }

  clearToken(): void {
    this.token = null;
  }

  // Auth
  async login(username: string, password: string): Promise<AuthResponse> {
    console.log('[API] Login attempt:', username);
    const response = await this.client.post('/api/v1/auth/login', {
      username,
      password,
    });
    this.token = response.data.access_token;
    return response.data;
  }

  // Health
  async getHealth(): Promise<{ status: string }> {
    const response = await this.client.get('/api/v1/health');
    return response.data;
  }

  // Sessions
  async getSessions(limit = 50, offset = 0): Promise<Session[]> {
    console.log('[API] Fetching sessions');
    const response = await this.client.get('/api/v1/sessions', {
      params: { limit, offset },
    });
    return response.data.items || response.data;
  }

  async getSession(sessionId: string): Promise<Session> {
    const response = await this.client.get(`/api/v1/sessions/${sessionId}`);
    return response.data;
  }

  // Flows
  async getFlows(sessionId?: string, limit = 100, offset = 0): Promise<Flow[]> {
    console.log('[API] Fetching flows', { sessionId });
    const params: Record<string, unknown> = { limit, offset };
    if (sessionId) params.session_id = sessionId;
    
    const response = await this.client.get('/api/v1/flows', { params });
    return response.data.items || response.data;
  }

  async getFlow(flowId: string): Promise<Flow> {
    const response = await this.client.get(`/api/v1/flows/${flowId}`);
    return response.data;
  }

  // Capture control
  async startCapture(): Promise<void> {
    console.log('[API] Starting capture');
    await this.client.post('/api/v1/capture/start');
  }

  async stopCapture(): Promise<void> {
    console.log('[API] Stopping capture');
    await this.client.post('/api/v1/capture/stop');
  }

  // Findings
  async getFindings(limit = 50, offset = 0): Promise<unknown[]> {
    const response = await this.client.get('/api/v1/findings', {
      params: { limit, offset },
    });
    return response.data.items || response.data;
  }
}

export const api = new APIClient();

