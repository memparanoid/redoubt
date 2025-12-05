/// <reference types="vite/client" />

declare module '*.md?raw' {
  const content: string
  export default content
}

declare module '@root/README.md?raw' {
  const content: string
  export default content
}
