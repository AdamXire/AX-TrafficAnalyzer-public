# Phase 4 Web UI - Setup Instructions

<!-- COMMUNITY-START -->
## Quick Start

1. **Install Node.js 18+** (if not installed):
   ```bash
   # Check version
   node --version  # Should be 18.0.0 or higher
   npm --version   # Should be 9.0.0 or higher
   
   # If not installed, use nvm:
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
   nvm install 18
   nvm use 18
   ```

2. **Install dependencies**:
   ```bash
   cd src/community/ui
   npm install
   ```

3. **Create environment file** (optional, defaults to localhost:8443):
   ```bash
   echo "VITE_API_URL=http://localhost:8443" > .env.development
   ```

4. **Start development server**:
   ```bash
   npm run dev
   ```

5. **Access UI**:
   - Open browser: `http://localhost:5173`
   - Default login: `admin` / `ChangeMe123!` (from config.json)

## Project Structure

```
src/community/ui/
├── src/
│   ├── components/
│   │   ├── ui/          # Basic UI components (Button, Card, Input, Badge)
│   │   └── layout/      # Layout components (Layout, Sidebar, Header)
│   ├── pages/           # Page components (Login, Dashboard, Traffic, etc.)
│   ├── lib/             # Utilities (api.ts, websocket.ts, utils.ts)
│   ├── stores/          # Zustand stores (authStore, trafficStore)
│   ├── types/           # TypeScript type definitions
│   ├── App.tsx          # Main app component with routing
│   └── main.tsx         # React entry point
├── package.json         # Dependencies and scripts
├── vite.config.ts       # Vite configuration
├── tsconfig.json        # TypeScript configuration
├── tailwind.config.js   # TailwindCSS configuration
└── README.md            # Documentation
```

## Available Scripts

- `npm run dev` - Start development server (port 5173)
- `npm run build` - Build for production (outputs to `dist/`)
- `npm run preview` - Preview production build
- `npm run type-check` - TypeScript type checking

## Debug Logging

All operations log to browser console with prefixes:
- `[API]` - HTTP API requests/responses
- `[WS]` - WebSocket connection events
- `[Auth]` - Authentication operations
- `[Traffic]` - Traffic data operations
- `[Dashboard]` - Dashboard updates
- `[Sessions]` - Session operations
- `[Devices]` - Device operations
- `[Settings]` - Settings operations

## Features

✅ JWT Authentication with auto-login check
✅ WebSocket real-time updates with auto-reconnect
✅ Dashboard with live statistics
✅ Traffic viewer with WebSocket streaming
✅ Sessions browser
✅ Devices list with statistics
✅ Settings page (read-only)
✅ Responsive design with TailwindCSS
✅ Dark mode support (via TailwindCSS dark mode)

## Troubleshooting

**Port 5173 already in use:**
- Change port in `vite.config.ts` or kill process using port 5173

**API connection failed:**
- Verify backend is running on port 8443
- Check CORS configuration in `src/community/main.py`
- Verify `VITE_API_URL` in `.env.development`

**WebSocket connection failed:**
- Check JWT token is valid
- Verify WebSocket endpoint: `/ws/traffic?token={jwt}`
- Check browser console for connection errors

**TypeScript errors:**
- Run `npm run type-check` to see all errors
- Ensure all dependencies are installed: `npm install`

## Next Steps

After setup:
1. Verify login works with default admin credentials
2. Check WebSocket connection in browser console
3. Test real-time updates by generating traffic
4. Verify all pages load correctly
5. Test navigation between pages

<!-- COMMUNITY-END -->

