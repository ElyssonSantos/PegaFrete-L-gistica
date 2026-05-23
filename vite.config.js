import { defineConfig } from 'vite';
import { resolve } from 'path';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  server: {
    port: 3000,
    open: true
  },
  esbuild: {
    drop: ['console', 'debugger'],
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    minify: 'esbuild',
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        terms: resolve(__dirname, 'terms.html')
      },
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/firebase')) {
            return 'firebase';
          }
        }
      }
    }
  },
  plugins: [
    VitePWA({
      registerType: 'autoUpdate',
      devOptions: { enabled: false },
      manifest: {
        name: 'PegaFrete Logística',
        short_name: 'PegaFrete',
        description: 'Encontre cargas e motoristas em poucos segundos. Simples, rápido e sem burocracia.',
        theme_color: '#ea580c',
        background_color: '#ffffff',
        display: 'standalone',
        icons: [
          {
            src: 'google_icon.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: 'google_icon.png',
            sizes: '512x512',
            type: 'image/png'
          }
        ]
      }
    })
  ]
});

