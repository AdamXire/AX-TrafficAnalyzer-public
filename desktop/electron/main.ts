/**
 * AX-TrafficAnalyzer Desktop - Main Process
 * Copyright © 2025 MMeTech (Macau) Ltd.
 * 
 * Fail-fast checks for dependencies before starting.
 */

import { app, BrowserWindow, Tray, Menu, nativeImage, dialog, Notification } from 'electron';
import { autoUpdater } from 'electron-updater';
import log from 'electron-log';
import * as path from 'path';
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';

// Configure logging
log.transports.file.level = 'info';
log.info('[STARTUP] AX-TrafficAnalyzer Desktop starting...');

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let backendProcess: ChildProcess | null = null;
let isQuitting = false;

const BACKEND_PORT = 8443;
const isDev = !app.isPackaged;

// ============================================================================
// FAIL-FAST DEPENDENCY CHECKS
// ============================================================================

function failFast(title: string, message: string): never {
    log.error(`[FAIL-FAST] ${title}: ${message}`);
    dialog.showErrorBoxSync(title, message);
    app.exit(1);
    throw new Error(message); // Never reached
}

function checkDependencies(): void {
    log.info('[STARTUP] Checking dependencies...');

    // Check Node.js version
    const nodeVersion = process.versions.node;
    const majorVersion = parseInt(nodeVersion.split('.')[0], 10);
    if (majorVersion < 18) {
        failFast(
            'Node.js Version Too Old',
            `Node.js 18+ required. Found: ${nodeVersion}\n\nInstall from: https://nodejs.org/`
        );
    }
    log.info(`[STARTUP] Node.js version OK: ${nodeVersion}`);

    // Check backend bundle exists (in production)
    if (!isDev) {
        const backendPath = getBackendPath();
        if (!fs.existsSync(backendPath)) {
            failFast(
                'Backend Not Found',
                `Backend bundle missing at: ${backendPath}\n\nRun: npm run bundle-backend`
            );
        }
        log.info(`[STARTUP] Backend bundle found: ${backendPath}`);
    }

    // Check UI exists
    const uiPath = getUIPath();
    if (!fs.existsSync(uiPath)) {
        failFast(
            'UI Not Found',
            `UI bundle missing at: ${uiPath}\n\nRun: cd src/community/ui && npm run build`
        );
    }
    log.info(`[STARTUP] UI bundle found: ${uiPath}`);
}

function getBackendPath(): string {
    if (isDev) {
        return path.join(__dirname, '../../src/community/main.py');
    }
    return path.join(process.resourcesPath, 'backend', 'ax-traffic-analyzer');
}

function getUIPath(): string {
    if (isDev) {
        return path.join(__dirname, '../../src/community/ui/dist/index.html');
    }
    return path.join(process.resourcesPath, 'ui', 'index.html');
}

// ============================================================================
// BACKEND MANAGEMENT
// ============================================================================

async function startBackend(): Promise<void> {
    log.info('[BACKEND] Starting backend server...');

    const backendPath = getBackendPath();
    
    if (isDev) {
        // Dev mode: run Python directly
        backendProcess = spawn('python', ['-m', 'community.main'], {
            cwd: path.join(__dirname, '../../src'),
            env: { ...process.env, PYTHONPATH: path.join(__dirname, '../../src') },
            stdio: ['ignore', 'pipe', 'pipe']
        });
    } else {
        // Production: run bundled executable
        backendProcess = spawn(backendPath, [], {
            cwd: path.dirname(backendPath),
            stdio: ['ignore', 'pipe', 'pipe']
        });
    }

    backendProcess.stdout?.on('data', (data) => {
        log.info(`[BACKEND] ${data.toString().trim()}`);
    });

    backendProcess.stderr?.on('data', (data) => {
        log.warn(`[BACKEND] ${data.toString().trim()}`);
    });

    backendProcess.on('error', (err) => {
        log.error(`[BACKEND] Failed to start: ${err.message}`);
        showNotification('Backend Error', `Failed to start backend: ${err.message}`);
    });

    backendProcess.on('exit', (code) => {
        log.info(`[BACKEND] Exited with code: ${code}`);
        if (!isQuitting && code !== 0) {
            showNotification('Backend Stopped', `Backend exited with code ${code}`);
        }
    });

    // Wait for backend to be ready
    await waitForBackend();
}

async function waitForBackend(timeout = 30000): Promise<void> {
    log.info('[BACKEND] Waiting for backend to be ready...');
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
        try {
            const response = await fetch(`http://localhost:${BACKEND_PORT}/api/v1/health`);
            if (response.ok) {
                log.info('[BACKEND] Backend is ready!');
                return;
            }
        } catch {
            // Backend not ready yet
        }
        await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    failFast('Backend Timeout', `Backend did not start within ${timeout/1000}s`);
}

function stopBackend(): void {
    if (backendProcess) {
        log.info('[BACKEND] Stopping backend...');
        backendProcess.kill('SIGTERM');
        backendProcess = null;
    }
}

// ============================================================================
// WINDOW MANAGEMENT
// ============================================================================

function createWindow(): void {
    log.info('[WINDOW] Creating main window...');
    
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1024,
        minHeight: 768,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        },
        icon: path.join(__dirname, '../resources/icon.png'),
        show: false
    });

    // Load UI
    if (isDev) {
        mainWindow.loadURL(`http://localhost:${BACKEND_PORT}`);
        mainWindow.webContents.openDevTools();
    } else {
        mainWindow.loadFile(getUIPath());
    }

    mainWindow.once('ready-to-show', () => {
        log.info('[WINDOW] Window ready to show');
        mainWindow?.show();
    });

    mainWindow.on('close', (event) => {
        if (!isQuitting) {
            event.preventDefault();
            mainWindow?.hide();
            showNotification('AX-TrafficAnalyzer', 'Running in background. Click tray icon to open.');
        }
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// ============================================================================
// SYSTEM TRAY
// ============================================================================

function createTray(): void {
    log.info('[TRAY] Creating system tray...');
    
    const iconPath = path.join(__dirname, '../resources/tray-icon.png');
    const icon = nativeImage.createFromPath(iconPath);
    
    tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon);
    tray.setToolTip('AX-TrafficAnalyzer');
    
    const contextMenu = Menu.buildFromTemplate([
        { label: 'Open', click: () => mainWindow?.show() },
        { type: 'separator' },
        { label: 'Start Capture', click: () => sendToRenderer('start-capture') },
        { label: 'Stop Capture', click: () => sendToRenderer('stop-capture') },
        { type: 'separator' },
        { label: 'Check for Updates', click: () => autoUpdater.checkForUpdatesAndNotify() },
        { type: 'separator' },
        { label: 'Quit', click: () => { isQuitting = true; app.quit(); } }
    ]);
    
    tray.setContextMenu(contextMenu);
    tray.on('click', () => mainWindow?.show());
}

function sendToRenderer(channel: string, ...args: unknown[]): void {
    mainWindow?.webContents.send(channel, ...args);
}

// ============================================================================
// NOTIFICATIONS
// ============================================================================

function showNotification(title: string, body: string): void {
    if (Notification.isSupported()) {
        new Notification({ title, body }).show();
    }
}

// ============================================================================
// AUTO-UPDATER
// ============================================================================

function setupAutoUpdater(): void {
    log.info('[UPDATER] Setting up auto-updater...');
    
    autoUpdater.logger = log;
    
    autoUpdater.on('update-available', () => {
        log.info('[UPDATER] Update available');
        showNotification('Update Available', 'A new version is available. Downloading...');
    });
    
    autoUpdater.on('update-downloaded', () => {
        log.info('[UPDATER] Update downloaded');
        showNotification('Update Ready', 'Update downloaded. Restart to apply.');
    });
    
    autoUpdater.on('error', (err) => {
        log.error(`[UPDATER] Error: ${err.message}`);
    });
    
    // Check for updates on startup (production only)
    if (!isDev) {
        autoUpdater.checkForUpdatesAndNotify();
    }
}

// ============================================================================
// APP LIFECYCLE
// ============================================================================

app.whenReady().then(async () => {
    log.info('[APP] Electron ready');
    
    try {
        checkDependencies();
        await startBackend();
        createWindow();
        createTray();
        setupAutoUpdater();
    } catch (err) {
        log.error(`[APP] Startup failed: ${err}`);
        app.exit(1);
    }
});

app.on('window-all-closed', () => {
    // Don't quit on macOS
    if (process.platform !== 'darwin') {
        // Keep running in tray
    }
});

app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();
    } else {
        mainWindow.show();
    }
});

app.on('before-quit', () => {
    log.info('[APP] Before quit');
    isQuitting = true;
    stopBackend();
});

app.on('quit', () => {
    log.info('[APP] Quit');
});

