import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { App } from './App'
import { LanguageProvider } from './locale'
import './style.css'

const root = document.getElementById('root')
if (!root) throw new Error('Missing application root')

createRoot(root).render(
  <StrictMode>
    <LanguageProvider><App /></LanguageProvider>
  </StrictMode>,
)
