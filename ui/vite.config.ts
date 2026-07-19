import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base "./" — assets are served by the Python API server from an arbitrary root.
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    proxy: { "/api": "http://127.0.0.1:8443", "/healthz": "http://127.0.0.1:8443" },
  },
});
