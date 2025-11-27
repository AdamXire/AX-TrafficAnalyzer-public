import { useEffect, useState } from 'react';
import { Card } from '../components/ui/card';
import apiClient from '../lib/api';
import type { Device } from '../types/api';

export function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    fetchDevices();
  }, []);
  
  const fetchDevices = async () => {
    console.debug('[Devices] Fetching devices...');
    setLoading(true);
    try {
      const response = await apiClient.get('/api/v1/devices', { params: { limit: 100 } });
      setDevices(response.data || []);
      console.debug('[Devices] Devices fetched:', response.data.length);
    } catch (error) {
      console.error('[Devices] Fetch error:', error);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Devices</h1>
      
      <Card className="p-6">
        {loading ? (
          <p className="text-gray-500">Loading...</p>
        ) : devices.length === 0 ? (
          <p className="text-gray-500">No devices found</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left p-2">Identifier</th>
                <th className="text-left p-2">IP Address</th>
                <th className="text-left p-2">MAC Address</th>
                <th className="text-left p-2">Sessions</th>
                <th className="text-left p-2">Total Requests</th>
                <th className="text-left p-2">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device, i) => (
                <tr key={i} className="border-b hover:bg-gray-50">
                  <td className="p-2 font-mono text-sm">{device.identifier}</td>
                  <td className="p-2">{device.client_ip}</td>
                  <td className="p-2">{device.mac_address || 'N/A'}</td>
                  <td className="p-2">{device.session_count}</td>
                  <td className="p-2">{device.total_requests}</td>
                  <td className="p-2">{device.last_seen ? new Date(device.last_seen).toLocaleString() : 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

