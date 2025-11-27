import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useEffect } from 'react';
import { useAuthStore } from './stores/authStore';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { TrafficPage } from './pages/TrafficPage';
import { AnalysisPage } from './pages/AnalysisPage';
import { FindingsPage } from './pages/FindingsPage';
import { SessionsPage } from './pages/SessionsPage';
import { DevicesPage } from './pages/DevicesPage';
import { SettingsPage } from './pages/SettingsPage';
import { Layout } from './components/layout/Layout';

function App() {
  const { checkAuth } = useAuthStore();
  
  useEffect(() => {
    checkAuth();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // checkAuth is stable from Zustand
  
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="traffic" element={<TrafficPage />} />
          <Route path="analysis" element={<AnalysisPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="sessions" element={<SessionsPage />} />
          <Route path="devices" element={<DevicesPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;

