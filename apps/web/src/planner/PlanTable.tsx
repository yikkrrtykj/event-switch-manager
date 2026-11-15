import { Fragment, useEffect, useRef, useState } from 'react'
import { Badge, Button, Input, Select, Table } from '../components/ui'
import { defaults, display, get, options, portFields } from './catalog'
import type { Field, Group } from './catalog'
import { Editor } from './Editor'
import { object, records } from './model'
import type { Issue, Plan, RecordValue } from './model'

export type Location = { key: string; index?: number; path: string }
export function PlanTable({ group, plan, issues, location, locked, update }: {
  group: Group; plan: Plan; issues: Issue[]; location?: Location; locked: boolean; update: (next: Plan) => void
}) {
  const isPort = group.key === 'physical_interfaces'
  const all = group.single ? plan[group.key] ? [object(plan[group.key])] : [] : records(plan, group.key)
  const [search, setSearch] = useState('')
  const [device, setDevice] = useState('')
  const [stack, setStack] = useState('')
  const [selected, setSelected] = useState<number[]>([])
  const [edit, setEdit] = useState<{ index: number; focus?: string; id?: string }>()
  const [batch, setBatch] = useState(false)
  const ref = useRef<HTMLElement>(null)
  const rowPath = (index: number) => group.key + (group.single ? '' : '.' + index)

  useEffect(() => {
    if (!location || location.key !== group.key) return
    setSearch('')
    setDevice('')
    setStack('')
    const { index, path } = location
    const subpath = path.split('.').slice(group.single ? 1 : 2).join('.')
    ref.current?.scrollIntoView({ block: 'nearest' })
    if (!locked && index !== undefined && all[index] && group.fields.some((item) =>
      item.key === subpath || subpath.startsWith(item.key + '.'))) {
      setEdit({ index, focus: path })
    } else {
      requestAnimationFrame(() => {
        const row = ref.current?.querySelector<HTMLElement>('[data-record="' + index + '"]')
        const element = row ?? ref.current
        element?.focus()
      })
    }
  }, [location]) // The location refers to the validated snapshot, before any new table edits.

  const columns: Field[] = group.columns.map((key) => group.fields.find((field) => field.key === key)
    ?? { key, label: key === 'capability_status' ? 'Capability' : key })
  const visible = all.map((item, index) => ({ item, index })).filter(({ item }) =>
    (!device || item.assignment_id === device) && (!stack || String(item.stack_member ?? 'standalone') === stack)
    && columns.map((field) => display(plan, field, get(item, field.key))).join(' ').toLowerCase().includes(search.trim().toLowerCase()))
  if (isPort) {
    visible.sort((a, b) => String(a.item.assignment_id).localeCompare(String(b.item.assignment_id))
      || Number(a.item.stack_member ?? 0) - Number(b.item.stack_member ?? 0)
      || String(a.item.name).localeCompare(String(b.item.name), undefined, { numeric: true }))
  }
  const stackIds = [...new Set(all.filter((item) => !device || item.assignment_id === device).map((item) =>
    String(item.stack_member ?? 'standalone')))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
  const allSelected = visible.every(({ index }) => selected.includes(index))
  function replace(values: RecordValue[]) {
    update({ ...plan, [group.key]: group.single ? values[0] ?? null : values })
  }
  function remove(index: number) {
    if (!window.confirm('Remove this ' + group.singular + ' from the draft?')) return
    setSelected([])
    replace(all.filter((_, n) => n !== index))
  }
  return <section className="panel collection" ref={ref} tabIndex={-1} aria-label={group.title}>
    <div className="section-head"><h2>{group.title} <span className="count">{all.length}</span></h2>
      {!locked && (!group.single || !all.length) && <Button
        onClick={() => setEdit({ index: all.length, id: group.id ? crypto.randomUUID() : undefined })}>Add {group.singular}</Button>}
    </div>
    {(all.length > 0 || isPort) && <div className="table-tools">
      <Input type="search" aria-label={'Search ' + group.title} placeholder="Search records"
        value={search} onChange={(event) => setSearch(event.target.value)} />
      {isPort && <>
        <Select aria-label="Filter ports by device" value={device}
          onChange={(event) => { setDevice(event.target.value); setStack('') }}>
          <option value="">All devices</option>
          {options(plan, 'assignments').map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
        </Select>
        <Select aria-label="Filter ports by Stack member" value={stack} onChange={(event) => setStack(event.target.value)}>
          <option value="">All Stack members</option>
          {stackIds.map((id) => <option key={id} value={id}>{id === 'standalone' ? 'Standalone' : 'Stack member ' + id}</option>)}
        </Select>
        {!locked && <Button disabled={!selected.length} onClick={() => setBatch(true)}>Batch edit ({selected.length})</Button>}
      </>}
    </div>}
    {!visible.length ? <p className="empty">{all.length ? 'No records match the filters.' : 'No records yet.'}</p>
      : <Table label={group.title}><thead><tr>
        {isPort && !locked && <th scope="col"><input type="checkbox" aria-label="Select all visible ports" checked={allSelected}
          onChange={() => {
            const ids = visible.map((row) => row.index)
            setSelected(allSelected ? selected.filter((id) => !ids.includes(id)) : [...new Set([...selected, ...ids])])
          }} /></th>}
        {columns.map((field) => <th scope="col" key={field.key}>{field.label}</th>)}
        <th scope="col">Validation</th>{!locked && <th scope="col">Actions</th>}
      </tr></thead><tbody>{visible.map(({ item, index }, position) => {
        const previous = visible[position - 1]?.item
        const newStack = isPort && (previous?.assignment_id !== item.assignment_id || previous?.stack_member !== item.stack_member)
        const first = columns[0]
        const name = first ? display(plan, first, get(item, first.key)) : 'record'
        const path = rowPath(index)
        const findings = issues.filter((issue) => issue.path === path || issue.path.startsWith(path + '.'))
        const invalid = findings.some((issue) => issue.severity === 'ERROR')
        return <Fragment key={String(item.id ?? '') + ':' + index}>
          {newStack && <tr className="group-row"><td colSpan={columns.length + (locked ? 1 : 3)}>
            {display(plan, { key: 'device', label: '', reference: 'assignments' }, item.assignment_id)}
            {' · '}{item.stack_member ? 'Stack member ' + String(item.stack_member) : 'Standalone'}</td></tr>}
          <tr data-record={index} tabIndex={-1} data-selected={selected.includes(index) || undefined}>
            {isPort && !locked && <td><input type="checkbox" aria-label={'Select port ' + name} checked={selected.includes(index)}
              onChange={(event) => setSelected(event.target.checked ? [...selected, index] : selected.filter((id) => id !== index))} /></td>}
            {columns.map((field) => <td key={field.key} className={/address|network|destination|serial/.test(field.key) ? 'fixed' : ''}>
              {display(plan, field, get(item, field.key))}
            </td>)}
            <td>{findings.length ? <Badge tone={invalid ? 'danger' : 'warning'}>
              {invalid ? 'ERROR' : 'WARNING'} · {findings.length}</Badge> : '—'}</td>
            {!locked && <td><div className="row-actions">
              <Button aria-label={'Edit ' + group.singular + ' ' + name} onClick={() => setEdit({ index })}>Edit</Button>
              <Button aria-label={'Remove ' + group.singular + ' ' + name} onClick={() => remove(index)}>Remove</Button>
            </div></td>}
          </tr>
        </Fragment>
      })}</tbody></Table>}
    {edit && !locked && <Editor key={edit.index} title={(all[edit.index] ? 'Edit ' : 'Add ') + group.singular}
      source={all[edit.index] ?? { ...defaults(group.fields), ...(edit.id ? { id: edit.id } : {}) }}
      plan={plan} fields={group.fields} path={rowPath(edit.index)} focus={edit.focus} issues={issues}
      close={() => setEdit(undefined)} commit={(item) => {
        const next = [...all]
        next[edit.index] = item
        setEdit(undefined)
        replace(next)
      }} />}
    {batch && !locked && <Editor title={'Batch edit ' + selected.length + ' ports'} source={defaults(portFields)}
      fields={portFields.filter((field) => field.key !== 'settings.address')} plan={plan} issues={[]} path="bulk"
      action={'Apply to ' + selected.length + ' ports'} close={() => setBatch(false)}
      hint="Existing routed addresses are retained when their ports stay routed."
      commit={(item) => {
        const settings = object(item.settings)
        replace(all.map((port, index) => {
          if (!selected.includes(index)) return port
          const previous = object(port.settings)
          return { ...port, settings: settings.mode === 'routed' && previous.mode === 'routed'
            ? { ...settings, address: previous.address ?? null } : settings }
        }))
        setSelected([])
        setBatch(false)
      }} />}
  </section>
}
