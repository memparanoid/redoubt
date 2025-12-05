import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'
import { existsSync, createReadStream } from 'fs'
import { extname, join } from 'path'

const ROOT_README = resolve(__dirname, '..', 'README.md')

const ROOT_DIR = resolve(__dirname, '..')

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'watch-readme',
      configureServer(server) {
        server.watcher.add(ROOT_README)
        server.watcher.on('change', (path) => {
          if (path === ROOT_README) {
            server.restart()
          }
        })
      }
    },
    {
      name: 'serve-root-assets',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
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
    }
  ],
  assetsInclude: ['**/*.md'],
  resolve: {
    alias: {
      '@root': ROOT_DIR
    }
  }
})
