import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dashboard talks to the FastAPI backend directly (VITE_API_BASE, default
// http://localhost:8000). The backend's CORS allow-list (API_CORS_ORIGINS) must
// permit this origin — it defaults to "*" for local development.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
});
