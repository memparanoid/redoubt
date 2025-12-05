import { useState, useEffect, type CSSProperties, type FC } from 'react'
import ReactMarkdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'
import rehypeRaw from 'rehype-raw'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark, oneLight } from 'react-syntax-highlighter/dist/esm/styles/prism'

// ─────────────────────────────────────────────────────────────────────────────
// Utils
// ─────────────────────────────────────────────────────────────────────────────

function getFileFromUrl(): string {
  const params = new URLSearchParams(window.location.search)
  return params.get('file') || 'README.md'
}

// ─────────────────────────────────────────────────────────────────────────────
// Theme
// ─────────────────────────────────────────────────────────────────────────────

interface Theme {
  bg: string
  fg: string
  fgMuted: string
  link: string
  codeBg: string
  border: string
  borderMuted: string
}

const THEME_DARK: Theme = {
  bg: '#0d1117',
  fg: '#e6edf3',
  fgMuted: '#8b949e',
  link: '#2f81f7',
  codeBg: '#161b22',
  border: '#30363d',
  borderMuted: '#21262d',
}

const THEME_LIGHT: Theme = {
  bg: '#ffffff',
  fg: '#1f2328',
  fgMuted: '#656d76',
  link: '#0969da',
  codeBg: '#f6f8fa',
  border: '#d0d7de',
  borderMuted: '#d8dee4',
}

// ─────────────────────────────────────────────────────────────────────────────
// Icons
// ─────────────────────────────────────────────────────────────────────────────

const ICON_STYLE: CSSProperties = { verticalAlign: 'text-bottom' }

const IconBook: FC = () => (
  <svg aria-hidden="true" viewBox="0 0 16 16" width="16" height="16" fill="currentColor" style={ICON_STYLE}>
    <path d="M0 1.75A.75.75 0 0 1 .75 1h4.253c1.227 0 2.317.59 3 1.501A3.743 3.743 0 0 1 11.006 1h4.245a.75.75 0 0 1 .75.75v10.5a.75.75 0 0 1-.75.75h-4.507a2.25 2.25 0 0 0-1.591.659l-.622.621a.75.75 0 0 1-1.06 0l-.622-.621A2.25 2.25 0 0 0 5.258 13H.75a.75.75 0 0 1-.75-.75Zm7.251 10.324.004-5.073-.002-2.253A2.25 2.25 0 0 0 5.003 2.5H1.5v9h3.757a3.75 3.75 0 0 1 1.994.574ZM8.755 4.75l-.004 7.322a3.752 3.752 0 0 1 1.992-.572H14.5v-9h-3.495a2.25 2.25 0 0 0-2.25 2.25Z" />
  </svg>
)

const IconList: FC = () => (
  <svg aria-hidden="true" viewBox="0 0 16 16" width="16" height="16" fill="currentColor" style={ICON_STYLE}>
    <path d="M5.75 2.5h8.5a.75.75 0 0 1 0 1.5h-8.5a.75.75 0 0 1 0-1.5Zm0 5h8.5a.75.75 0 0 1 0 1.5h-8.5a.75.75 0 0 1 0-1.5Zm0 5h8.5a.75.75 0 0 1 0 1.5h-8.5a.75.75 0 0 1 0-1.5ZM2 14a1 1 0 1 1 0-2 1 1 0 0 1 0 2Zm1-6a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM2 4a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z" />
  </svg>
)

const IconPencil: FC = () => (
  <svg aria-hidden="true" viewBox="0 0 16 16" width="16" height="16" fill="currentColor" style={ICON_STYLE}>
    <path d="M11.013 1.427a1.75 1.75 0 0 1 2.474 0l1.086 1.086a1.75 1.75 0 0 1 0 2.474l-8.61 8.61c-.21.21-.47.364-.756.445l-3.251.93a.75.75 0 0 1-.927-.928l.929-3.25c.081-.286.235-.547.445-.758l8.61-8.61Zm.176 4.823L9.75 4.81l-6.286 6.287a.253.253 0 0 0-.064.108l-.558 1.953 1.953-.558a.253.253 0 0 0 .108-.064Zm1.238-3.763a.25.25 0 0 0-.354 0L10.811 3.75l1.439 1.44 1.263-1.263a.25.25 0 0 0 0-.354Z" />
  </svg>
)

// ─────────────────────────────────────────────────────────────────────────────
// Styles
// ─────────────────────────────────────────────────────────────────────────────

const FONT_FAMILY = '-apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif'
const FONT_MONO = 'ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace'

const createRootStyle = (t: Theme): CSSProperties => ({
  minHeight: '100vh',
  backgroundColor: t.bg,
  color: t.fg,
  padding: 32,
  fontFamily: FONT_FAMILY,
  fontSize: 16,
  lineHeight: 1.5,
  wordWrap: 'break-word',
})

const createToggleStyle = (t: Theme): CSSProperties => ({
  position: 'fixed',
  top: 16,
  right: 16,
  padding: '5px 16px',
  borderRadius: 6,
  border: `1px solid ${t.border}`,
  backgroundColor: t.codeBg,
  color: t.fg,
  cursor: 'pointer',
  fontSize: 14,
  fontWeight: 500,
})

const CONTAINER_STYLE: CSSProperties = {
  maxWidth: 900,
  margin: '0 auto',
  border: '1px solid #3c444d',
  borderRadius: 6,
}

const createHeaderStyle = (dark: boolean): CSSProperties => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '8px 16px',
  borderBottom: '1px solid #3c444d',
  backgroundColor: dark ? '#161b22' : '#f6f8fa',
  borderRadius: '6px 6px 0 0',
})

const HEADER_TITLE_STYLE: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  padding: '8px 0',
  borderBottom: '4px solid #f78066',
  marginBottom: -9,
}

const HEADER_ACTIONS_STYLE: CSSProperties = { display: 'flex', gap: 8 }

const createIconButtonStyle = (t: Theme): CSSProperties => ({
  background: 'none',
  border: 'none',
  cursor: 'pointer',
  padding: 8,
  color: t.fgMuted,
  borderRadius: 6,
})

const ARTICLE_STYLE: CSSProperties = { padding: '16px 32px 32px 32px' }

// ─────────────────────────────────────────────────────────────────────────────
// Markdown Components
// ─────────────────────────────────────────────────────────────────────────────

const createMarkdownComponents = (t: Theme, dark: boolean): Components => {
  const headingBase: CSSProperties = { fontWeight: 600, lineHeight: 1.25, marginTop: 24, marginBottom: 16 }
  const withBorder = (s: CSSProperties): CSSProperties => ({ ...s, paddingBottom: '.3em', borderBottom: `1px solid ${t.border}` })

  return {
    h1: ({ children }) => <h1 style={withBorder({ ...headingBase, fontSize: '2em' })}>{children}</h1>,
    h2: ({ children }) => <h2 style={withBorder({ ...headingBase, fontSize: '1.5em' })}>{children}</h2>,
    h3: ({ children }) => <h3 style={{ ...headingBase, fontSize: '1.25em' }}>{children}</h3>,
    h4: ({ children }) => <h4 style={{ ...headingBase, fontSize: '1em' }}>{children}</h4>,

    p: ({ children, ...props }) => (
      <p style={{ marginTop: 0, marginBottom: 16, textAlign: (props as { align?: 'left' | 'center' | 'right' }).align ?? 'left' }}>
        {children}
      </p>
    ),

    a: ({ href, children }) => <a href={href} style={{ color: t.link, textDecoration: 'none' }}>{children}</a>,

    ul: ({ children }) => <ul style={{ paddingLeft: '2em', marginTop: 0, marginBottom: 16 }}>{children}</ul>,
    ol: ({ children }) => <ol style={{ paddingLeft: '2em', marginTop: 0, marginBottom: 16 }}>{children}</ol>,
    li: ({ children }) => <li style={{ marginTop: '.25em' }}>{children}</li>,

    blockquote: ({ children }) => (
      <blockquote style={{ margin: 0, marginBottom: 16, padding: '0 1em', color: t.fgMuted, borderLeft: `.25em solid ${t.border}` }}>
        {children}
      </blockquote>
    ),

    hr: () => <hr style={{ height: '.25em', padding: 0, margin: '24px 0', backgroundColor: t.borderMuted, border: 0 }} />,

    img: ({ src, alt, width, height }) => <img src={src} alt={alt} width={width} height={height} style={{ maxWidth: '100%', boxSizing: 'border-box' }} />,

    pre: ({ children }) => (
      <pre style={{ padding: 16, overflow: 'auto', fontSize: '85%', lineHeight: 1.45, backgroundColor: t.codeBg, borderRadius: 6, marginTop: 0, marginBottom: 16 }}>
        {children}
      </pre>
    ),

    code: ({ className, children, ...props }) => {
      const match = /language-(\w+)/.exec(className ?? '')

      if (match) {
        return (
          <SyntaxHighlighter
            style={dark ? oneDark : oneLight}
            language={match[1]}
            PreTag="div"
            customStyle={{ margin: 0, padding: 16, fontSize: 14, lineHeight: 1.45, borderRadius: 6, backgroundColor: t.codeBg }}
          >
            {String(children).replace(/\n$/, '')}
          </SyntaxHighlighter>
        )
      }

      return (
        <code
          style={{
            padding: '.2em .4em',
            margin: 0,
            fontSize: '85%',
            whiteSpace: 'break-spaces',
            backgroundColor: dark ? 'rgba(110,118,129,0.4)' : 'rgba(175,184,193,0.2)',
            borderRadius: 6,
            fontFamily: FONT_MONO,
          }}
          {...props}
        >
          {children}
        </code>
      )
    },

    table: ({ children }) => (
      <table style={{ borderSpacing: 0, borderCollapse: 'collapse', display: 'block', width: 'max-content', maxWidth: '100%', overflow: 'auto', marginTop: 0, marginBottom: 16 }}>
        {children}
      </table>
    ),
    thead: ({ children }) => <thead>{children}</thead>,
    tbody: ({ children }) => <tbody>{children}</tbody>,
    tr: ({ children }) => <tr style={{ backgroundColor: t.bg, borderTop: `1px solid ${t.borderMuted}` }}>{children}</tr>,
    th: ({ children }) => <th style={{ padding: '6px 13px', border: `1px solid ${t.border}`, fontWeight: 600 }}>{children}</th>,
    td: ({ children }) => <td style={{ padding: '6px 13px', border: `1px solid ${t.border}` }}>{children}</td>,

    strong: ({ children }) => <strong style={{ fontWeight: 600 }}>{children}</strong>,
    em: ({ children }) => <em>{children}</em>,
    del: ({ children }) => <del>{children}</del>,

    input: ({ checked, disabled }) => <input type="checkbox" checked={checked} disabled={disabled} style={{ marginRight: '.5em' }} />,
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Components
// ─────────────────────────────────────────────────────────────────────────────

interface HeaderProps {
  dark: boolean
  theme: Theme
  filename: string
}

const Header: FC<HeaderProps> = ({ dark, theme, filename }) => (
  <div style={createHeaderStyle(dark)}>
    <div style={HEADER_TITLE_STYLE}>
      <IconBook />
      <span style={{ fontWeight: 600, fontSize: 14 }}>{filename}</span>
    </div>
    <div style={HEADER_ACTIONS_STYLE}>
      <button style={createIconButtonStyle(theme)}><IconList /></button>
      <button style={createIconButtonStyle(theme)}><IconPencil /></button>
    </div>
  </div>
)

interface ThemeToggleProps {
  dark: boolean
  theme: Theme
  onToggle: () => void
}

const ThemeToggle: FC<ThemeToggleProps> = ({ dark, theme, onToggle }) => (
  <button onClick={onToggle} style={createToggleStyle(theme)}>
    {dark ? '☀️ Light' : '🌙 Dark'}
  </button>
)

// ─────────────────────────────────────────────────────────────────────────────
// App
// ─────────────────────────────────────────────────────────────────────────────

const App: FC = () => {
  const [dark, setDark] = useState(true)
  const [markdown, setMarkdown] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filename] = useState(getFileFromUrl)

  const theme = dark ? THEME_DARK : THEME_LIGHT
  const components = createMarkdownComponents(theme, dark)

  useEffect(() => {
    const fetchMarkdown = async () => {
      try {
        setLoading(true)
        setError(null)
        const response = await fetch(`/api/markdown?file=${encodeURIComponent(filename)}`)
        if (!response.ok) {
          throw new Error(await response.text())
        }
        const text = await response.text()
        setMarkdown(text)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load markdown')
      } finally {
        setLoading(false)
      }
    }

    fetchMarkdown()
  }, [filename])

  return (
    <div style={createRootStyle(theme)}>
      <ThemeToggle dark={dark} theme={theme} onToggle={() => setDark(d => !d)} />

      <div style={CONTAINER_STYLE}>
        <Header dark={dark} theme={theme} filename={filename} />

        <article style={ARTICLE_STYLE}>
          {loading && <p style={{ color: theme.fgMuted }}>Loading...</p>}
          {error && <p style={{ color: '#f85149' }}>Error: {error}</p>}
          {!loading && !error && (
            <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRaw]} components={components}>
              {markdown}
            </ReactMarkdown>
          )}
        </article>
      </div>
    </div>
  )
}

export default App
