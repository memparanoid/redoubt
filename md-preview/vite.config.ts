import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'
import { existsSync, createReadStream, readFileSync } from 'fs'
import { extname, join } from 'path'

const ROOT_DIR = resolve(__dirname, '..')

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'watch-markdown-files',
      configureServer(server) {
        // Watch all .md files recursively
        server.watcher.add(resolve(ROOT_DIR, '**/*.md'))
        server.watcher.on('change', (path) => {
          if (path.endsWith('.md')) {
            server.ws.send({ type: 'full-reload' })
          }
        })
      }
    },
    {
      name: 'serve-root-assets',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          // Serve images
          if (req.url?.match(/\.(png|jpg|jpeg|gif|svg|webp)$/)) {
            const filePath = join(ROOT_DIR, req.url)
            if (existsSync(filePath)) {
              const ext = extname(filePath).slice(1)
              res.setHeader('Content-Type', `image/${ext === 'svg' ? 'svg+xml' : ext}`)
              createReadStream(filePath).pipe(res)
              return
            }
          }
          next()
        })
      }
    },
    {
      name: 'serve-markdown-api',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          // API endpoint: /api/markdown?file=README.md
          if (req.url?.startsWith('/api/markdown')) {
            const url = new URL(req.url, 'http://localhost')
            const file = url.searchParams.get('file') || 'README.md'

            // Security: only allow .md files, prevent path traversal
            if (!file.endsWith('.md') || file.includes('..')) {
              res.statusCode = 400
              res.end('Invalid file')
              return
            }

            const filePath = join(ROOT_DIR, file)
            if (existsSync(filePath)) {
              res.setHeader('Content-Type', 'text/plain; charset=utf-8')
              res.end(readFileSync(filePath, 'utf-8'))
            } else {
              res.statusCode = 404
              res.end(`File not found: ${file}`)
            }
            return
          }
          next()
        })
      }
    }
  ],
  resolve: {
    alias: {
      '@root': ROOT_DIR
    }
  }
})
