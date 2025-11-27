import { create } from 'zustand';
import apiClient from '../lib/api';
import type { Finding, AnalysisStats, ProtocolAnalysis, ThreatIntel } from '../types/api';

interface AnalysisState {
  findings: Finding[];
  totalFindings: number;
  loading: boolean;
  stats: AnalysisStats | null;
  fetchFindings: (params?: {
    session_id?: string;
    severity?: string;
    category?: string;
    limit?: number;
    offset?: number;
  }) => Promise<void>;
  fetchStats: () => Promise<void>;
  getFinding: (findingId: string) => Promise<Finding | null>;
  getProtocolAnalysis: (flowId: string) => Promise<ProtocolAnalysis | null>;
  getThreatIntel: (domain: string) => Promise<ThreatIntel | null>;
}

export const useAnalysisStore = create<AnalysisState>((set) => ({
  findings: [],
  totalFindings: 0,
  loading: false,
  stats: null,
  
  fetchFindings: async (params = {}) => {
    set({ loading: true });
    console.debug('[Analysis] Fetching findings...', params);
    try {
      const response = await apiClient.get('/api/v1/analysis/findings', { params });
      set({
        findings: response.data.items,
        totalFindings: response.data.total,
        loading: false,
      });
      console.debug('[Analysis] Findings fetched:', response.data.total);
    } catch (error) {
      set({ loading: false });
      console.error('[Analysis] Fetch error:', error);
    }
  },
  
  fetchStats: async () => {
    console.debug('[Analysis] Fetching stats...');
    try {
      const response = await apiClient.get('/api/v1/analysis/stats');
      set({ stats: response.data });
      console.debug('[Analysis] Stats fetched:', response.data);
    } catch (error) {
      console.error('[Analysis] Stats fetch error:', error);
    }
  },
  
  getFinding: async (findingId: string) => {
    console.debug('[Analysis] Fetching finding:', findingId);
    try {
      const response = await apiClient.get(`/api/v1/analysis/findings/${findingId}`);
      return response.data;
    } catch (error) {
      console.error('[Analysis] Finding fetch error:', error);
      return null;
    }
  },
  
  getProtocolAnalysis: async (flowId: string) => {
    console.debug('[Analysis] Fetching protocol analysis:', flowId);
    try {
      const response = await apiClient.get(`/api/v1/analysis/protocols/${flowId}`);
      return response.data;
    } catch (error) {
      console.error('[Analysis] Protocol analysis fetch error:', error);
      return null;
    }
  },
  
  getThreatIntel: async (domain: string) => {
    console.debug('[Analysis] Fetching threat intel:', domain);
    try {
      const response = await apiClient.get(`/api/v1/analysis/threat-intel/${encodeURIComponent(domain)}`);
      return response.data;
    } catch (error) {
      console.error('[Analysis] Threat intel fetch error:', error);
      return null;
    }
  },
}));

