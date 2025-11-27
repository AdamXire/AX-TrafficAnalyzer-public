/**
 * AX-TrafficAnalyzer Mobile - Login Screen
 * Copyright © 2025 MMeTech (Macau) Ltd.
 */

import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { useAuthStore } from '../stores/authStore';

interface Props {
  onLoginSuccess: () => void;
}

export function LoginScreen({ onLoginSuccess }: Props) {
  const [serverUrl, setServerUrl] = useState('http://192.168.1.100:8443');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  
  const { login, setServerUrl: saveServerUrl, loading, error } = useAuthStore();
  
  const handleLogin = async () => {
    console.log('[LOGIN] Attempting login');
    saveServerUrl(serverUrl);
    const success = await login(username, password);
    if (success) {
      onLoginSuccess();
    }
  };
  
  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
    >
      <View style={styles.header}>
        <Text style={styles.title}>AX-TrafficAnalyzer</Text>
        <Text style={styles.subtitle}>Mobile Monitor</Text>
      </View>
      
      <View style={styles.form}>
        <Text style={styles.label}>Server URL</Text>
        <TextInput
          style={styles.input}
          value={serverUrl}
          onChangeText={setServerUrl}
          placeholder="http://server:8443"
          placeholderTextColor="#666"
          autoCapitalize="none"
          autoCorrect={false}
        />
        
        <Text style={styles.label}>Username</Text>
        <TextInput
          style={styles.input}
          value={username}
          onChangeText={setUsername}
          placeholder="admin"
          placeholderTextColor="#666"
          autoCapitalize="none"
          autoCorrect={false}
        />
        
        <Text style={styles.label}>Password</Text>
        <TextInput
          style={styles.input}
          value={password}
          onChangeText={setPassword}
          placeholder="••••••••"
          placeholderTextColor="#666"
          secureTextEntry
        />
        
        {error && <Text style={styles.error}>{error}</Text>}
        
        <TouchableOpacity
          style={[styles.button, loading && styles.buttonDisabled]}
          onPress={handleLogin}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>Connect</Text>
          )}
        </TouchableOpacity>
      </View>
      
      <Text style={styles.footer}>© 2025 MMeTech (Macau) Ltd.</Text>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a2e',
    padding: 20,
  },
  header: {
    alignItems: 'center',
    marginTop: 60,
    marginBottom: 40,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#00d9ff',
  },
  subtitle: {
    fontSize: 16,
    color: '#888',
    marginTop: 8,
  },
  form: {
    flex: 1,
  },
  label: {
    color: '#aaa',
    fontSize: 14,
    marginBottom: 8,
    marginTop: 16,
  },
  input: {
    backgroundColor: '#2a2a4e',
    borderRadius: 8,
    padding: 14,
    color: '#fff',
    fontSize: 16,
    borderWidth: 1,
    borderColor: '#3a3a5e',
  },
  button: {
    backgroundColor: '#00d9ff',
    borderRadius: 8,
    padding: 16,
    alignItems: 'center',
    marginTop: 32,
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  buttonText: {
    color: '#1a1a2e',
    fontSize: 18,
    fontWeight: 'bold',
  },
  error: {
    color: '#ff4444',
    marginTop: 16,
    textAlign: 'center',
  },
  footer: {
    color: '#666',
    textAlign: 'center',
    marginBottom: 20,
  },
});

