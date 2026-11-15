import { useEffect, useId, useRef } from 'react'
import type { ComponentProps, ReactNode } from 'react'

export function Button({ primary, ...props }: ComponentProps<'button'> & { primary?: boolean }) {
  return <button type="button" data-slot="button" data-primary={primary || undefined} {...props} />
}
export function Input(props: ComponentProps<'input'>) { return <input data-slot="input" {...props} /> }
export function Select(props: ComponentProps<'select'>) { return <select data-slot="select" {...props} /> }
export function Badge({ tone = 'neutral', children }: { tone?: string; children: ReactNode }) {
  return <span data-slot="badge" data-tone={tone}>{children}</span>
}
export function Table({ label, children }: { label: string; children: ReactNode }) {
  return <div className="table-region" role="region" aria-label={label} tabIndex={0}>
    <table data-slot="table" aria-label={label}>{children}</table>
  </div>
}
export function Dialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null)
  const id = useId()
  useEffect(() => {
    const dialog = ref.current
    dialog?.showModal()
    return () => dialog?.close()
  }, [])
  return <dialog ref={ref} data-slot="dialog" aria-labelledby={id}
    onCancel={(event) => { event.preventDefault(); onClose() }}>
    <div className="section-head"><h2 id={id}>{title}</h2>
      <Button onClick={onClose} aria-label={'Close ' + title}>Close</Button></div>
    {children}
  </dialog>
}
export function Loading({ children }: { children: ReactNode }) {
  return <div className="loading" role="status"><span>{children}</span>
    <span className="skeleton" aria-hidden="true" /><span className="skeleton" aria-hidden="true" /></div>
}
