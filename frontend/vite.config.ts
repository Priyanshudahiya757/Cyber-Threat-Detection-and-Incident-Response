import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    allowedHosts: [".trycloudflare.com"],
    proxy: {
      // Lets the frontend call relative /api/v1/... paths in dev without
      // CORS friction; production instead sets VITE_API_BASE_URL directly
      // (see src/config/env.ts) and talks to the backend's real origin.
      "/api": {
        target: process.env.VITE_BACKEND_ORIGIN || "http://localhost:8000",
        changeOrigin: true,
      },
      "/health": {
        target: process.env.VITE_BACKEND_ORIGIN || "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
