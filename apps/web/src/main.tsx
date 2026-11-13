import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { Dashboard } from './Dashboard'
import './style.css'

const root = document.getElementById('root')
if (!root) throw new Error('Missing application root')

createRoot(root).render(
  <StrictMode>
    <Dashboard />
  </StrictMode>,
)
