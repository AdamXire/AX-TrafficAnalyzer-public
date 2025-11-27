import { useEffect, useState } from 'react';
import { Card } from '../components/ui/card';
import apiClient from '../lib/api';

export function SettingsPage() {
  const [settings, setSettings] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    fetchSettings();
  }, []);
  
  const fetchSettings = async () => {
    console.debug('[Settings] Fetching settings...');
    setLoading(true);
    try {
      const response = await apiClient.get('/api/v1/settings');
      setSettings(response.data);
      console.debug('[Settings] Settings fetched');
    } catch (error) {
      console.error('[Settings] Fetch error:', error);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Settings</h1>
      
      <Card className="p-6">
        {loading ? (
          <p className="text-gray-500">Loading...</p>
        ) : settings ? (
          <pre className="bg-gray-100 dark:bg-gray-800 p-4 rounded overflow-auto">
            {JSON.stringify(settings, null, 2)}
          </pre>
        ) : (
          <p className="text-gray-500">No settings available</p>
        )}
      </Card>
    </div>
  );
}

