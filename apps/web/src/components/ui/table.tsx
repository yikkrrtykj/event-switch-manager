import type { ComponentProps } from 'react'

// Local adaptation of the shadcn/ui table with a named, keyboard-scrollable container.
export function Table({ label, className, ...props }: ComponentProps<'table'> & { label: string }) {
  return <div data-slot="table-container" className="table-region relative w-full overflow-x-auto"
    role="region" aria-label={label} tabIndex={0}>
    <table data-slot="table" className={['w-full caption-bottom', className].filter(Boolean).join(' ')}
      aria-label={label} {...props} />
  </div>
}
