import { useEffect, useState } from 'react';
import { Card } from '../components/ui/card';
import apiClient from '../lib/api';
import type { Session } from '../types/api';

export function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    fetchSessions();
  }, []);
  
  const fetchSessions = async () => {
    console.debug('[Sessions] Fetching sessions...');
    setLoading(true);
    try {
      const response = await apiClient.get('/api/v1/sessions', { params: { limit: 100 } });
      setSessions(response.data.items || []);
      console.debug('[Sessions] Sessions fetched:', response.data.total);
    } catch (error) {
      console.error('[Sessions] Fetch error:', error);
    } finally {
      setLoading(false);
    }
  };
  
  const handleGenerateReport = async (sessionId: string) => {
    console.debug('[Sessions] Generating report for:', sessionId);
    try {
      const response = await apiClient.get(`/api/v1/analysis/reports/${sessionId}`, {
        params: { format: 'pdf' },
        responseType: 'blob',
      });
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `report-${sessionId.slice(0, 8)}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      console.debug('[Sessions] Report downloaded');
    } catch (error) {
      console.error('[Sessions] Report generation error:', error);
      alert('Report generation is not yet implemented. Check backend logs.');
    }
  };
  
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Sessions</h1>
      
      <Card className="p-6">
        {loading ? (
          <p className="text-gray-500">Loading...</p>
        ) : sessions.length === 0 ? (
          <p className="text-gray-500">No sessions found</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left p-2">Session ID</th>
                <th className="text-left p-2">IP Address</th>
                <th className="text-left p-2">MAC Address</th>
                <th className="text-left p-2">Requests</th>
                <th className="text-left p-2">Last Activity</th>
                <th className="text-left p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={session.session_id} className="border-b hover:bg-gray-50 dark:hover:bg-gray-800">
                  <td className="p-2 font-mono text-sm">{session.session_id.slice(0, 8)}...</td>
                  <td className="p-2">{session.client_ip}</td>
                  <td className="p-2">{session.mac_address || 'N/A'}</td>
                  <td className="p-2">{session.request_count}</td>
                  <td className="p-2">{new Date(session.last_activity).toLocaleString()}</td>
                  <td className="p-2">
                    <button
                      onClick={() => handleGenerateReport(session.session_id)}
                      className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
                    >
                      Report
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

