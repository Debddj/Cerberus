import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8000',
      '/healthz': 'http://localhost:8000',
      '/metrics': 'http://localhost:8000',
      '/policy': 'http://localhost:8000',
      '/baselines': 'http://localhost:8000',
      '/admin': 'http://localhost:8000',
    }
  }
})
