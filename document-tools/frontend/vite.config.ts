import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.2",
    port: 5174,
    strictPort: true,
  },
  build: {
    target: "es2022",
    sourcemap: false,
  },
});
