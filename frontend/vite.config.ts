import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5174,
    host: true,
    strictPort: true
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    
    // ========================================
    // CODE SPLITTING OPTIMIZATIONS
    // ========================================
    rollupOptions: {
      output: {
        // Manual chunk splitting for optimal loading
        manualChunks: {
          // React core libraries - separate chunk
          'react-vendor': [
            'react',
            'react-dom',
            'react-router-dom'
          ],
          
          // UI libraries - separate chunk
          'ui-vendor': [
            'lucide-react',
            'framer-motion'
          ],
          
          // Markdown/syntax highlighting - large libraries
          'markdown-vendor': [
            'react-markdown',
            'react-syntax-highlighter'
          ],
          
          // Supabase - separate chunk
          'supabase': [
            '@supabase/supabase-js'
          ],
          
          // Utility libraries
          'utils-vendor': [
            'axios',
            'date-fns',
            'zod'
          ],
        },
        
        // Optimize chunk file names
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId
          
          // Tools go in tools/ subdirectory
          if (facadeModuleId?.includes('/tools/')) {
            return 'assets/tools/[name]-[hash].js'
          }
          
          // Pages go in pages/ subdirectory
          if (facadeModuleId?.includes('/pages/')) {
            return 'assets/pages/[name]-[hash].js'
          }
          
          // Default chunk naming
          return 'assets/[name]-[hash].js'
        },
        
        // Optimize asset file names
        assetFileNames: (assetInfo) => {
          const name = assetInfo.name || ''
          
          // Images
          if (/\.(png|jpe?g|svg|gif|webp|avif)$/.test(name)) {
            return 'assets/images/[name]-[hash][extname]'
          }
          
          // Fonts
          if (/\.(woff2?|eot|ttf|otf)$/.test(name)) {
            return 'assets/fonts/[name]-[hash][extname]'
          }
          
          // CSS
          if (/\.css$/.test(name)) {
            return 'assets/css/[name]-[hash][extname]'
          }
          
          // Default
          return 'assets/[name]-[hash][extname]'
        },
      },
      
      // Tree-shaking optimizations
      treeshake: {
        moduleSideEffects: 'no-external',
        preset: 'recommended'
      }
    },
    
    // Increase chunk size warning limit (we're intentionally creating chunks)
    chunkSizeWarningLimit: 600,
    
    // Minification options - using esbuild (faster than terser, built-in)
    minify: 'esbuild',
    // Note: esbuild doesn't drop console.* by default, but our logger utility handles this
    
    // Target modern browsers for smaller builds
    target: 'es2020',
    
    // Enable CSS code splitting
    cssCodeSplit: true,
    
    // Report compressed size
    reportCompressedSize: true,
  },
  
  // Optimize dependencies
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      '@supabase/supabase-js'
    ],
    exclude: [
      // Exclude large dependencies that should be lazy loaded
    ]
  }
}) 