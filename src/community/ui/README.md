# AX-TrafficAnalyzer Web UI

React + TypeScript frontend for AX-TrafficAnalyzer.

<!-- COMMUNITY-START -->
## Setup

1. **Install Node.js 18+ and npm** (if not already installed):
   ```bash
   # Ubuntu/Debian
   sudo apt install nodejs npm
   
   # Or use nvm
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
   nvm install 18
   ```

2. **Install dependencies**:
   ```bash
   cd src/community/ui
   npm install
   ```

3. **Start development server**:
   ```bash
   npm run dev
   ```

   The UI will be available at `http://localhost:5173`

4. **Build for production**:
   ```bash
   npm run build
   ```

   Output will be in `dist/` directory.

## Environment Variables

Create `.env.development`:
```
VITE_API_URL=http://localhost:8443
```

## Features

- **Login Page**: JWT authentication
- **Dashboard**: Real-time stats and recent traffic
- **Traffic Viewer**: List of HTTP flows with filtering
- **Sessions**: Session browser with device info
- **Devices**: Device list with statistics
- **Settings**: System configuration (read-only)

## Debug Logging

All API calls and WebSocket events are logged to browser console:
- `[API] Request:` - API requests
- `[API] Response:` - API responses
- `[WS] Connected` - WebSocket connection
- `[WS] Message:` - WebSocket events
- `[Auth]` - Authentication events
- `[Traffic]` - Traffic data operations
- `[Dashboard]` - Dashboard operations

## Tech Stack

- React 18
- TypeScript
- Vite
- TailwindCSS
- Zustand (state management)
- Axios (HTTP client)
- React Router (routing)

<!-- COMMUNITY-END -->

