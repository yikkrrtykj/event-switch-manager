import type { ComponentProps } from 'react'

// Local adaptation of the shadcn/ui registry input for the shared desktop tokens.
export function Input({ className, type, ...props }: ComponentProps<'input'>) {
  return <input
    type={type}
    data-slot="input"
    className={['min-w-0 border-input', className].filter(Boolean).join(' ')}
    {...props}
  />
}
