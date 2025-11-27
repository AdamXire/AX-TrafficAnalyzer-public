export class WebSocketClient {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private listeners: Map<string, Set<(data: any) => void>> = new Map();
  private shouldReconnect = true; // Flag to prevent reconnection after manual disconnect

  connect(token: string) {
    this.shouldReconnect = true; // Allow reconnection
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8443';
    const wsUrl = apiUrl.replace(/^http/, 'ws') + `/ws/traffic?token=${token}`;
    console.debug('[WS] Connecting to:', wsUrl);
    this.ws = new WebSocket(wsUrl);
    
    this.ws.onopen = () => {
      console.debug('[WS] Connected');
      this.reconnectAttempts = 0;
    };
    
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.debug('[WS] Message:', data.event);
      this.emit(data.event, data.data);
    };
    
    this.ws.onerror = (error) => {
      console.error('[WS] Error:', error);
    };
    
    this.ws.onclose = () => {
      console.debug('[WS] Disconnected');
      this.reconnect(token);
    };
  }

  private reconnect(token: string) {
    if (!this.shouldReconnect) {
      console.debug('[WS] Reconnection disabled (manual disconnect)');
      return;
    }
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.debug(`[WS] Reconnecting (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      setTimeout(() => this.connect(token), 2000 * this.reconnectAttempts);
    } else {
      console.warn('[WS] Max reconnection attempts reached');
    }
  }

  on(event: string, callback: (data: any) => void) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
  }

  private emit(event: string, data: any) {
    this.listeners.get(event)?.forEach(callback => callback(data));
  }

  disconnect() {
    this.shouldReconnect = false; // Prevent reconnection after manual disconnect
    this.ws?.close();
    this.ws = null;
    this.listeners.clear();
    console.debug('[WS] Disconnected (reconnection disabled)');
  }
  
  off(event: string, callback?: (data: any) => void) {
    if (callback) {
      this.listeners.get(event)?.delete(callback);
    } else {
      this.listeners.delete(event);
    }
  }
}

export const wsClient = new WebSocketClient();

