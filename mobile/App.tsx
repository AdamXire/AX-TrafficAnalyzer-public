/**
 * AX-TrafficAnalyzer Mobile App
 * Copyright © 2025 MMeTech (Macau) Ltd.
 */

import React, { useState } from 'react';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { LoginScreen } from './src/screens/LoginScreen';
import { DashboardScreen } from './src/screens/DashboardScreen';
import { useAuthStore } from './src/stores/authStore';

export default function App() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const [showDashboard, setShowDashboard] = useState(false);
  
  console.log('[APP] Render', { isAuthenticated, showDashboard });
  
  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      {isAuthenticated || showDashboard ? (
        <DashboardScreen />
      ) : (
        <LoginScreen onLoginSuccess={() => setShowDashboard(true)} />
      )}
    </SafeAreaProvider>
  );
}

