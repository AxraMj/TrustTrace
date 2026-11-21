import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The browser talks ONLY to its own origin; /api is proxied to the TrustTrace API. That keeps the HttpOnly SameSite=Strict session
// cookie working without CORS, and means the browser never sees the API's address, Meko, or any key.
const target = process.env.TRUSTTRACE_API_URL ?? 'http://127.0.0.1:8787';
const proxy = { '/api': { target, changeOrigin: false } };

// Strict CSP for the built app (no inline scripts/styles, no third-party origins). Applied to dev-preview responses too.
// Vite's dev server needs inline/eval for HMR, so the header is only attached to `vite preview` (which serves the production build).
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const securityHeaders = {
  'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true, proxy },
  preview: { port: 4173, strictPort: true, proxy, headers: securityHeaders },
  build: { sourcemap: false, target: 'es2022' },
  test: { environment: 'jsdom', globals: true, setupFiles: ['./test/setup.js'], css: false, restoreMocks: true },
});
