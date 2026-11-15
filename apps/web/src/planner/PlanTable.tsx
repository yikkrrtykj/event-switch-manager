import { Fragment, useEffect, useRef, useState } from 'react'
import { Badge, Button, Input, Select, Table } from '../components/ui'
import { clean, defaults, display, get, options } from './catalog'
import type { Field, Group } from './catalog'
import { Editor } from './Editor'
import { PortEditor } from './PortEditor'
import { describePortValue, isPortSetting, memberLabel } from './portSettings'
import { object, records } from './model'
import type { Issue, Plan, RecordValue } from './model'

type Row = { item: RecordValue; index: number }

const assignment = { key: 'assignment_id', label: 'Device', reference: 'assignments' }

export type Location = { key: string; index?: number; path: string }
export function PlanTable({ group, plan, issues, location, locked, update, onFormDirty }: {
  group: Group; plan: Plan; issues: Issue[]; location?: Location; locked: boolean; update: (next: Plan) => void
  onFormDirty: (dirty: boolean) => void
}) {
  const isPort = group.key === 'physical_interfaces'
  const isChannel = group.key === 'port_channels'
  const value = plan[group.key]
  const isRecord = (item: unknown) => item !== null && typeof item === 'object' && !Array.isArray(item)
  const malformed = group.single ? value != null && !isRecord(value)
    : value !== undefined && (!Array.isArray(value) || !value.every(isRecord))
  const all = group.single ? value && !malformed ? [object(value)] : [] : records(plan, group.key)
  const [search, setSearch] = useState('')
  const [device, setDevice] = useState('')
  const [stack, setStack] = useState('')
  const [selected, setSelected] = useState<RecordValue[]>([])
  const [edit, setEdit] = useState<{ index: number; focus?: string; id?: string }>()
  const [batch, setBatch] = useState<Row[]>()
  const [batchError, setBatchError] = useState('')
  const ref = useRef<HTMLElement>(null)
  const rowPath = (index: number) => group.key + (group.single ? '' : '.' + index)

  useEffect(() => {
    if (!location || location.key !== group.key) return
    setSearch('')
    setDevice('')
    setStack('')
    resetSelection()
    const { index, path } = location
    const subpath = path.split('.').slice(group.single ? 1 : 2).join('.')
    ref.current?.scrollIntoView({ block: 'nearest' })
    if (!locked && !malformed && index !== undefined && all[index] && group.fields.some((item) =>
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
    && [...columns.map((field) => display(plan, field, get(item, field.key))), get(item, 'settings.description')]
      .join(' ').toLowerCase().includes(search.trim().toLowerCase()))
  if (isPort) {
    visible.sort((a, b) => String(a.item.assignment_id).localeCompare(String(b.item.assignment_id))
      || Number(a.item.stack_member ?? 0) - Number(b.item.stack_member ?? 0)
      || String(a.item.name).localeCompare(String(b.item.name), undefined, { numeric: true }))
  }
  const stackIds = [...new Set(all.filter((item) => !device || item.assignment_id === device).map((item) =>
    String(item.stack_member ?? 'standalone')))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
  const picked = visible.filter(({ item }) => selected.includes(item))
  const allSelected = visible.every(({ item }) => selected.includes(item))

  function resetSelection() {
    setSelected([])
    setBatch(undefined)
    setBatchError('')
  }

  function applyBatch(items: RecordValue[]) {
    if (!batch || locked || batch.length !== picked.length ||
      batch.some(({ item, index }) => !picked.some((row) => row.item === item && row.index === index))) {
      resetSelection()
      setBatchError('The target ports changed. Select them again.')
      return
    }
    const replacements = new Map(batch.map(({ index }, position) => [index, items[position]]))
    replace(all.map((port, index) => replacements.get(index) ?? port))
    resetSelection()
  }

  function replace(values: RecordValue[]) {
    update({ ...plan, [group.key]: group.single ? values[0] ?? null : values })
  }
  function applyEdit(index: number, item: RecordValue) {
    const next = [...all]
    const previous = all[index]
    next[index] = item
    setSelected((current) => current.filter((port) => port !== previous))
    setEdit(undefined)
    replace(next)
  }
  function remove(index: number) {
    if (!window.confirm('Remove this ' + group.singular + ' from the draft?')) return
    setSelected((current) => current.filter((item) => item !== all[index]))
    setBatch(undefined)
    replace(all.filter((_, n) => n !== index))
  }
  const source = edit && (all[edit.index] ?? { ...defaults(group.fields), ...(edit.id ? { id: edit.id } : {}) })
  return <section className="panel collection" ref={ref} tabIndex={-1} aria-label={group.title}>
    <div className="section-head"><h2>{group.title} <span className="count">{all.length}</span></h2>
      {!locked && !malformed && (!group.single || !all.length) && <Button
        onClick={() => setEdit({ index: all.length, id: group.id ? crypto.randomUUID() : undefined })}>Add {group.singular}</Button>}
    </div>
    {malformed && <p role="alert" className="error-text">Correct this collection through JSON import before editing its records.</p>}
    {batchError && <p role="alert" className="error-text">{batchError}</p>}
    {!malformed && (all.length > 0 || isPort) && <div className="table-tools">
      <Input type="search" aria-label={'Search ' + group.title} placeholder="Search records"
        value={search} onChange={(event) => { setSearch(event.target.value); resetSelection() }} />
      {isPort && <>
        <Select aria-label="Filter ports by device" value={device}
          onChange={(event) => { setDevice(event.target.value); setStack(''); resetSelection() }}>
          <option value="">All devices</option>
          {options(plan, 'assignments').map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
        </Select>
        <Select aria-label="Filter ports by Stack member" value={stack} onChange={(event) => { setStack(event.target.value); resetSelection() }}>
          <option value="">All Stack members</option>
          {stackIds.map((id) => <option key={id} value={id}>{id === 'standalone' ? 'Standalone' : 'Stack member ' + id}</option>)}
        </Select>
        {!locked && <Button disabled={!picked.length} onClick={() => setBatch(picked)}>Batch edit ({picked.length})</Button>}
      </>}
    </div>}
    {!malformed && (!visible.length ? <p className="empty">{all.length ? 'No records match the filters.' : 'No records yet.'}</p>
      : <Table label={group.title} className={isPort ? 'port-list' : undefined}><thead><tr>
        {isPort && !locked && <th scope="col"><input type="checkbox" aria-label="Select all visible ports" checked={allSelected}
          onChange={() => setSelected(allSelected ? [] : visible.map(({ item }) => item))} /></th>}
        {columns.map((field) => <th scope="col" key={field.key} data-port-name={isPort && field.key === 'name' || undefined}>{field.label}</th>)}
        {(isPort || isChannel) && <th scope="col">Configuration</th>}
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
          {newStack && <tr className="group-row"><td colSpan={columns.length + (locked ? 2 : 4)}>
            {display(plan, assignment, item.assignment_id)}{' · '}{memberLabel(item)}</td></tr>}
          <tr data-record={index} tabIndex={-1} data-selected={selected.includes(item) || undefined}>
            {isPort && !locked && <td><input type="checkbox" aria-label={'Select port ' + name} checked={selected.includes(item)}
              onChange={(event) => {
                const checked = event.target.checked
                setSelected((current) => checked ? [...current, item] : current.filter((port) => port !== item))
              }} /></td>}
            {columns.map((field) => <td key={field.key} data-port-name={isPort && field.key === 'name' || undefined}
              className={/address|network|destination|serial/.test(field.key) ? 'data-mono' : ''}>
              {display(plan, field, get(item, field.key))}
            </td>)}
            {(isPort || isChannel) && <td><details className="port-config">
              <summary>{get(item, 'settings.admin_state') == null ? 'Default state' : String(get(item, 'settings.admin_state'))}
                {get(item, 'settings.description') && <> · <span>{String(get(item, 'settings.description'))}</span></>}</summary>
              <dl>{group.fields.filter((field) => isPortSetting(field) && !group.columns.includes(field.key)).map((field) =>
                <Fragment key={field.key}><dt>{field.label}</dt>
                  <dd>{describePortValue(plan, field, get(item, field.key))}</dd></Fragment>)}
                {isPort && <><dt>Port-Channel</dt><dd>{records(plan, 'port_channels').filter((channel) =>
                  Array.isArray(channel.member_ids) && item.id !== undefined && channel.member_ids.includes(item.id)).map((channel) => channel.number).join(', ') || 'None'}</dd></>}
                <dt>Hardware settings</dt><dd>NOT VERIFIED</dd>
              </dl>
            </details></td>}
            <td>{findings.length ? <Badge tone={invalid ? 'danger' : 'warning'}>
              {invalid ? 'ERROR' : 'WARNING'} · {findings.length}</Badge> : '—'}</td>
            {!locked && <td><div className="row-actions">
              <Button aria-label={'Edit ' + group.singular + ' ' + name} onClick={() => setEdit({ index })}>Edit</Button>
              <Button aria-label={'Remove ' + group.singular + ' ' + name} onClick={() => remove(index)}>Remove</Button>
            </div></td>}
          </tr>
        </Fragment>
      })}</tbody></Table>)}
    {edit && source && !locked && (isPort || isChannel ? <PortEditor key={edit.index}
      title={(all[edit.index] ? 'Edit ' : 'Add ') + group.singular} targets={[{ index: edit.index, item: source }]}
      creating={!all[edit.index]} aggregate={isChannel} fields={group.fields} plan={plan} path={rowPath(edit.index)}
      issues={issues} focus={edit.focus} onFormDirty={onFormDirty} close={() => setEdit(undefined)}
      commit={([item]) => { if (item) applyEdit(edit.index, item) }} /> :
      <Editor key={edit.index} title={(all[edit.index] ? 'Edit ' : 'Add ') + group.singular} source={source}
        plan={plan} fields={group.fields} path={rowPath(edit.index)} focus={edit.focus} issues={issues} onFormDirty={onFormDirty}
        close={() => setEdit(undefined)} commit={(item) => applyEdit(edit.index, clean(item, all[edit.index]))} />)}
    {batch && !locked && <PortEditor title={'Batch edit ' + batch.length + ' ports'} targets={batch}
      fields={group.fields.filter(isPortSetting)} plan={plan} issues={[]} path="bulk" batch
      onFormDirty={onFormDirty} close={() => setBatch(undefined)} commit={applyBatch} />}
  </section>
}
