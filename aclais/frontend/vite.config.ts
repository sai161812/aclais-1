import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // Keep the frontend preview on a distinct loopback host. Browser cookies
    // are host-scoped, not port-scoped; the owner API bundle is served from
    // its authenticated 127.0.0.1 origin instead of proxying owner cookies.
    host: "127.0.0.2",
    port: 5173,
    strictPort: true,
  },
});
