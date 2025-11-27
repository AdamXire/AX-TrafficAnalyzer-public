import { useEffect, useState } from 'react';
import { Card } from '../components/ui/card';
import apiClient from '../lib/api';
import { wsClient } from '../lib/websocket';

export function DashboardPage() {
  const [stats, setStats] = useState({ sessions: 0, flows: 0, devices: 0 });
  const [recentFlows, setRecentFlows] = useState<any[]>([]);
  
  useEffect(() => {
    fetchStats();
    const handleFlow = (data: any) => {
      console.debug('[Dashboard] New flow received');
      setRecentFlows(prev => [data, ...prev].slice(0, 10));
    };
    wsClient.on('http_flow', handleFlow);
    
    return () => {
      wsClient.off('http_flow', handleFlow);
    };
  }, []);
  
  const fetchStats = async () => {
    console.debug('[Dashboard] Fetching stats...');
    try {
      const [sessions, flows, devices] = await Promise.all([
        apiClient.get('/api/v1/sessions', { params: { limit: 1 } }),
        apiClient.get('/api/v1/flows', { params: { limit: 1 } }),
        apiClient.get('/api/v1/devices', { params: { limit: 1 } }),
      ]);
      setStats({
        sessions: sessions.data.total || 0,
        flows: flows.data.total || 0,
        devices: devices.data.length || 0,
      });
      console.debug('[Dashboard] Stats fetched:', stats);
    } catch (error) {
      console.error('[Dashboard] Stats fetch error:', error);
    }
  };
  
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Dashboard</h1>
      
      <div className="grid grid-cols-3 gap-6">
        <Card className="p-6">
          <h3 className="text-sm text-gray-500">Total Sessions</h3>
          <p className="text-3xl font-bold">{stats.sessions}</p>
        </Card>
        <Card className="p-6">
          <h3 className="text-sm text-gray-500">Total Flows</h3>
          <p className="text-3xl font-bold">{stats.flows}</p>
        </Card>
        <Card className="p-6">
          <h3 className="text-sm text-gray-500">Active Devices</h3>
          <p className="text-3xl font-bold">{stats.devices}</p>
        </Card>
      </div>
      
      <Card className="p-6">
        <h2 className="text-xl font-bold mb-4">Recent Traffic</h2>
        <div className="space-y-2">
          {recentFlows.length === 0 ? (
            <p className="text-gray-500">No recent traffic</p>
          ) : (
            recentFlows.map((flow: any, i) => (
              <div key={i} className="flex items-center justify-between text-sm">
                <span>{flow.method} {flow.url}</span>
                <span className="text-gray-500">{flow.status_code}</span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}

