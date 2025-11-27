import { create } from 'zustand';
import apiClient from '../lib/api';

interface TrafficState {
  flows: any[];
  totalFlows: number;
  loading: boolean;
  fetchFlows: (params?: any) => Promise<void>;
  addFlow: (flow: any) => void;
}

export const useTrafficStore = create<TrafficState>((set) => ({
  flows: [],
  totalFlows: 0,
  loading: false,
  
  fetchFlows: async (params = {}) => {
    set({ loading: true });
    console.debug('[Traffic] Fetching flows...', params);
    try {
      const response = await apiClient.get('/api/v1/flows', { params });
      set({ flows: response.data.items, totalFlows: response.data.total, loading: false });
      console.debug('[Traffic] Flows fetched:', response.data.total);
    } catch (error) {
      set({ loading: false });
      console.error('[Traffic] Fetch error:', error);
    }
  },
  
  addFlow: (flow) => {
    set((state) => ({ flows: [flow, ...state.flows].slice(0, 100) }));
    console.debug('[Traffic] Flow added:', flow.flow_id);
  },
}));

