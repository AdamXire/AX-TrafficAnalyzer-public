/**
 * AX-TrafficAnalyzer Desktop - Preload Script
 * Copyright © 2025 MMeTech (Macau) Ltd.
 * 
 * Secure IPC bridge between main and renderer processes.
 */

import { contextBridge, ipcRenderer } from 'electron';

// Expose safe APIs to renderer
contextBridge.exposeInMainWorld('electronAPI', {
    // App info
    getVersion: () => ipcRenderer.invoke('get-version'),
    getPlatform: () => process.platform,
    
    // Capture controls
    onStartCapture: (callback: () => void) => {
        ipcRenderer.on('start-capture', callback);
    },
    onStopCapture: (callback: () => void) => {
        ipcRenderer.on('stop-capture', callback);
    },
    
    // Notifications
    showNotification: (title: string, body: string) => {
        ipcRenderer.send('show-notification', title, body);
    },
    
    // Updates
    checkForUpdates: () => ipcRenderer.invoke('check-updates'),
    onUpdateAvailable: (callback: () => void) => {
        ipcRenderer.on('update-available', callback);
    },
    
    // Logging
    log: (level: string, message: string) => {
        ipcRenderer.send('log', level, message);
    }
});

console.log('[PRELOAD] Electron APIs exposed');

