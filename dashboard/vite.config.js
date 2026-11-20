import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// Slice 4 dev gateway: the browser only ever talks to localhost:3000; every
// backend hop is proxied here. `secure: false` keeps Chrome from rejecting the
// self-signed local TLS certificate on the Box 2 control plane.
const saasTarget = 'https://localhost:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3000,
    host: true,
    proxy: {
      '/api': { target: saasTarget, changeOrigin: true, secure: false },
      '/ws': { target: saasTarget, ws: true, changeOrigin: true, secure: false },
      '/chaos': { target: 'http://localhost:9000', changeOrigin: true },
      '/col-a': {
        target: 'http://localhost:4001',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/col-a/, ''),
      },
      '/col-b': {
        target: 'http://localhost:4002',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/col-b/, ''),
      },
    },
  },
})
