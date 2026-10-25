import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// В разработке прокси на backend; значение — только локальное, к развёртыванию не относится.
const backend = process.env.DEV_BACKEND_URL ?? "http://127.0.0.1:8000";
// Адрес, который backend считает своим (APP_PUBLIC_URL): без него запросы с порта Vite отклоняются проверкой Origin.
const origin = process.env.DEV_ORIGIN;

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": { target: backend, changeOrigin: false, headers: origin ? { Origin: origin } : undefined } } },
  build: { sourcemap: false, target: "es2022" },
  test: { environment: "node" },
});
