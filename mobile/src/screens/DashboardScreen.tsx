/**
 * AX-TrafficAnalyzer Mobile - Dashboard Screen
 * Copyright © 2025 MMeTech (Macau) Ltd.
 */

import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
} from 'react-native';
import { api, Session, Flow } from '../api/client';

export function DashboardScreen() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [recentFlows, setRecentFlows] = useState<Flow[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const loadData = async () => {
    console.log('[DASHBOARD] Loading data');
    try {
      const [sessionsData, flowsData] = await Promise.all([
        api.getSessions(5),
        api.getFlows(undefined, 10),
      ]);
      setSessions(sessionsData);
      setRecentFlows(flowsData);
      setError(null);
      console.log('[DASHBOARD] Data loaded', {
        sessions: sessionsData.length,
        flows: flowsData.length,
      });
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed to load data';
      console.log('[DASHBOARD] Error:', message);
      setError(message);
    }
  };
  
  const onRefresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };
  
  useEffect(() => {
    loadData();
  }, []);
  
  return (
    <ScrollView
      style={styles.container}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }
    >
      <Text style={styles.title}>Dashboard</Text>
      
      {error && (
        <View style={styles.errorBox}>
          <Text style={styles.errorText}>{error}</Text>
        </View>
      )}
      
      {/* Stats */}
      <View style={styles.statsRow}>
        <View style={styles.statCard}>
          <Text style={styles.statValue}>{sessions.length}</Text>
          <Text style={styles.statLabel}>Sessions</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={styles.statValue}>{recentFlows.length}</Text>
          <Text style={styles.statLabel}>Recent Flows</Text>
        </View>
      </View>
      
      {/* Recent Sessions */}
      <Text style={styles.sectionTitle}>Recent Sessions</Text>
      {sessions.map((session) => (
        <TouchableOpacity key={session.session_id} style={styles.card}>
          <Text style={styles.cardTitle}>{session.name || 'Unnamed'}</Text>
          <Text style={styles.cardSubtitle}>
            {session.flow_count} flows • {session.status}
          </Text>
          <Text style={styles.cardTime}>
            {new Date(session.start_time).toLocaleString()}
          </Text>
        </TouchableOpacity>
      ))}
      
      {/* Recent Flows */}
      <Text style={styles.sectionTitle}>Recent Traffic</Text>
      {recentFlows.map((flow) => (
        <View key={flow.id} style={styles.flowCard}>
          <View style={styles.flowHeader}>
            <Text style={[styles.method, styles[`method_${flow.method}`]]}>
              {flow.method}
            </Text>
            <Text style={[
              styles.status,
              flow.status_code >= 400 ? styles.statusError : styles.statusOk
            ]}>
              {flow.status_code}
            </Text>
          </View>
          <Text style={styles.url} numberOfLines={1}>
            {flow.url}
          </Text>
        </View>
      ))}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a2e',
    padding: 16,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 20,
    marginTop: 40,
  },
  errorBox: {
    backgroundColor: '#ff444433',
    padding: 12,
    borderRadius: 8,
    marginBottom: 16,
  },
  errorText: {
    color: '#ff4444',
  },
  statsRow: {
    flexDirection: 'row',
    gap: 12,
    marginBottom: 24,
  },
  statCard: {
    flex: 1,
    backgroundColor: '#2a2a4e',
    padding: 20,
    borderRadius: 12,
    alignItems: 'center',
  },
  statValue: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#00d9ff',
  },
  statLabel: {
    color: '#888',
    marginTop: 4,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#fff',
    marginBottom: 12,
    marginTop: 8,
  },
  card: {
    backgroundColor: '#2a2a4e',
    padding: 16,
    borderRadius: 8,
    marginBottom: 12,
  },
  cardTitle: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  cardSubtitle: {
    color: '#888',
    marginTop: 4,
  },
  cardTime: {
    color: '#666',
    fontSize: 12,
    marginTop: 8,
  },
  flowCard: {
    backgroundColor: '#2a2a4e',
    padding: 12,
    borderRadius: 8,
    marginBottom: 8,
  },
  flowHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 4,
  },
  method: {
    fontWeight: 'bold',
    fontSize: 12,
  },
  method_GET: { color: '#4caf50' },
  method_POST: { color: '#2196f3' },
  method_PUT: { color: '#ff9800' },
  method_DELETE: { color: '#f44336' },
  status: {
    fontWeight: 'bold',
  },
  statusOk: { color: '#4caf50' },
  statusError: { color: '#f44336' },
  url: {
    color: '#aaa',
    fontSize: 13,
  },
});

