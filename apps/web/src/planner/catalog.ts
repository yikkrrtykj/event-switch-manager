import { object, records } from './model'
import type { Plan, RecordValue, Value } from './model'

export type Field = {
  key: string
  label: string
  type?: 'number' | 'choice' | 'ref' | 'refs' | 'json' | 'records'
  optional?: boolean
  choices?: string[]
  reference?: string
  initial?: Value
  when?: [string, string]
  children?: Field[]
  accepts?: (candidate: RecordValue, record: RecordValue, plan: Plan) => boolean
}
export type Group = { key: string; title: string; singular: string; fields: Field[]; columns: string[]; id: boolean; single?: boolean }
const field = (key: string, label: string, optional = false): Field => ({ key, label, optional })
const number = (key: string, label: string, initial?: number, optional = false): Field =>
  ({ key, label, initial, optional, type: 'number' })
const choice = (key: string, label: string, choices: string[]): Field =>
  ({ key, label, choices, initial: choices[0], optional: choices.includes(''), type: 'choice' })
const ref = (key: string, label: string, reference: string, optional = false): Field =>
  ({ key, label, reference, optional, type: 'ref' })
const refs = (key: string, label: string, reference: string): Field => ({ key, label, reference, type: 'refs', initial: [] })
const children = (key: string, label: string, fields: Field[]): Field =>
  ({ key, label, type: 'records', initial: [], children: fields })
const raw = (key: string, label: string, initial: Value): Field => ({ key, label, initial, optional: true, type: 'json' })
const when = (item: Field, key: string, value: string): Field => ({ ...item, when: [key, value] })
const kind = (value: string) => (candidate: RecordValue) => candidate.kind === value
const owner = (key: string) => (candidate: RecordValue, record: RecordValue) =>
  !record[key] || candidate.assignment_id === record[key]
const accepts = (field: Field, predicate: NonNullable<Field['accepts']>): Field =>
  ({ ...field, accepts: predicate })
const device = ref('assignment_id', 'Device assignment', 'assignments')
const subnet = ref('subnet_id', 'Subnet', 'subnets')
const svi = accepts(ref('svi_id', 'SVI', 'logical_interfaces'), (candidate, record, plan) => {
  const subnet = records(plan, 'subnets').find((item) => item.id === record.subnet_id)
  return candidate.kind === 'svi' && (!subnet || candidate.vlan === subnet.vlan)
})
const source = ref('source_vlan', 'Source VLAN', 'vlans')
const target = field('destination', 'Destination CIDR')
const track = ref('track_id', 'Track', 'tracks')
const tunnel = accepts(ref('tunnel_id', 'Tunnel', 'ipsec_tunnels'), owner('assignment_id'))
const isp = accepts(ref('isp_id', 'ISP', 'isps'), owner('assignment_id'))
const pref = number('preference', 'Preference', 1)
const priority = number('priority', 'Priority', 10)
export const portFields = [
  choice('settings.mode', 'Mode', ['access', 'trunk', 'routed']),
  when(ref('settings.access_vlan', 'Access VLAN', 'vlans'), 'settings.mode', 'access'),
  when(ref('settings.native_vlan', 'Native VLAN', 'vlans', true), 'settings.mode', 'trunk'),
  when(refs('settings.allowed_vlans', 'Allowed VLANs', 'vlans'), 'settings.mode', 'trunk'),
  when(field('settings.address', 'IPv4 address / prefix', true), 'settings.mode', 'routed'),
]
const group = (key: string, title: string, singular: string, fields: Field[], columns: string[], id = false): Group =>
  ({ key, title, singular, fields, columns, id })

export const catalog = [
  group('vlans', 'VLANs', 'VLAN', [number('id', 'VLAN ID'), field('name', 'Name'),
    choice('purpose', 'Purpose', ['ordinary', 'management', 'guest', 'sensitive', 'transit'])], ['id', 'name', 'purpose']),
  group('subnets', 'Subnets', 'subnet', [ref('vlan', 'VLAN', 'vlans'), field('network', 'IPv4 CIDR')], ['network', 'vlan'], true),
  group('gateways', 'Gateways', 'gateway', [subnet, field('address', 'IPv4 address'), svi], ['subnet_id', 'address', 'svi_id']),
  group('logical_interfaces', 'Logical interfaces', 'logical interface', [device, field('name', 'Interface name'),
    choice('kind', 'Type', ['svi', 'port-channel', 'loopback']),
    when(ref('vlan', 'VLAN', 'vlans'), 'kind', 'svi'),
    field('address', 'IPv4 address / prefix', true)], ['name', 'assignment_id', 'kind', 'address'], true),
  group('vlan_access_policies', 'VLAN policies', 'VLAN policy', [source, ref('destination_vlan', 'Destination VLAN', 'vlans'),
    priority, choice('action', 'Action', ['deny', 'allow'])], ['source_vlan', 'destination_vlan', 'priority', 'action'], true),
  { ...group('transit', 'Core / Hillstone transit', 'transit', [ref('core_assignment_id', 'Cisco Core', 'assignments'),
    ref('hillstone_assignment_id', 'Hillstone firewall', 'assignments'),
    accepts(ref('core_port_id', 'Core port', 'physical_interfaces'), owner('core_assignment_id')),
    accepts(ref('hillstone_port_id', 'Firewall port', 'physical_interfaces'), owner('hillstone_assignment_id')),
    accepts(ref('core_svi_id', 'Core SVI', 'logical_interfaces'), (candidate, record) =>
      candidate.kind === 'svi' && owner('core_assignment_id')(candidate, record)),
    { ...ref('vlan', 'Transit VLAN', 'vlans'), initial: 9 }, field('network', 'Transit CIDR'), field('core_ip', 'Core IP'),
    field('hillstone_ip', 'Hillstone IP')], ['vlan', 'network', 'core_ip', 'hillstone_ip']), single: true },
  group('dhcp_pools', 'DHCP pools', 'pool', [subnet, field('start', 'Start address'), field('end', 'End address'),
    number('lease_seconds', 'Lease seconds', 43200)], ['subnet_id', 'start', 'end', 'lease_seconds'], true),
  group('dhcp_reservations', 'DHCP reservations', 'reservation', [subnet, field('address', 'IPv4 address'),
    field('client_mac', 'Client MAC')], ['subnet_id', 'address', 'client_mac'], true),
  group('dhcp_relays', 'DHCP relays', 'relay', [subnet, svi, raw('servers', 'Relay server addresses (JSON array)', [])], ['subnet_id', 'svi_id', 'servers']),
  group('tracks', 'Tracks', 'Track', [field('target', 'Probe target'), number('interval_seconds', 'Interval seconds', 5),
    number('failure_threshold', 'Failure threshold', 3), { ...tunnel, optional: true }], ['target', 'interval_seconds', 'tunnel_id'], true),
  group('isps', 'ISP uplinks', 'ISP', [field('name', 'Name'), device, accepts(ref('interface_id', 'WAN interface', 'physical_interfaces'), (candidate, record) =>
    get(candidate, 'settings.mode') === 'routed' && owner('assignment_id')(candidate, record)),
    field('address', 'IPv4 address / prefix'), field('gateway', 'Gateway'), { ...track, optional: true },
    children('routed_public_blocks', 'Routed public blocks', [field('network', 'CIDR'), field('reason', 'Reason')])],
    ['name', 'interface_id', 'address', 'gateway', 'track_id'], true),
  group('source_routes', 'Source-based routes', 'SBR rule', [device, source, accepts(refs('isp_priority', 'ISP failover order', 'isps'), owner('assignment_id')),
    children('no_nat', 'No-NAT exceptions', [isp, field('reason', 'Reason')])], ['source_vlan', 'isp_priority', 'no_nat'], true),
  group('snat', 'Source NAT', 'SNAT rule', [device, source, isp, field('translated_ip', 'Translated IPv4 address')],
    ['source_vlan', 'isp_id', 'translated_ip'], true),
  group('ipsec_tunnels', 'IPsec tunnels', 'tunnel', [field('name', 'Name'), device, isp, field('peer', 'Peer IPv4 address'),
    field('inside', 'Inside IPv4 / prefix'), field('remote_gateway', 'Remote gateway'), track,
    choice('state', 'Tunnel state', ['unknown', 'up', 'down'])], ['name', 'isp_id', 'peer', 'inside', 'state'], true),
  group('vpn_remote_prefixes', 'VPN remote prefixes', 'VPN prefix', [tunnel, field('network', 'Remote CIDR')], ['tunnel_id', 'network']),
  group('static_routes', 'Static routes', 'static route', [device, target, pref,
    choice('next_hop.kind', 'Next hop type', ['ip', 'tunnel', 'discard']),
    when(field('next_hop.address', 'Next hop address'), 'next_hop.kind', 'ip'),
    when({ ...tunnel, key: 'next_hop.tunnel_id', label: 'Next hop tunnel' }, 'next_hop.kind', 'tunnel'),
    choice('activation.kind', 'Activation', ['', 'always', 'track']),
    when({ ...track, key: 'activation.track_id', label: 'Route Track' }, 'activation.kind', 'track'),
    when(choice('activation.state', 'Required Track state', ['up', 'down']), 'activation.kind', 'track')],
    ['destination', 'assignment_id', 'next_hop.kind', 'preference', 'activation.kind'], true),
  group('default_routes', 'Default routes', 'default route', [device, choice('next_hop.kind', 'Next hop type', ['ip']),
    field('next_hop.address', 'Next hop address'), pref], ['assignment_id', 'next_hop.address', 'preference'], true),
  group('policy_routes', 'Policy-based routes', 'PBR rule', [device, source, target, tunnel, priority,
    choice('on_tunnel_down', 'When tunnel is down', ['discard', 'route-table', 'unknown', 'use-sbr'])],
    ['source_vlan', 'destination', 'tunnel_id', 'on_tunnel_down'], true),
  group('nat_exemptions', 'NAT exemptions', 'NAT exemption', [device, source, target, tunnel], ['source_vlan', 'destination', 'tunnel_id'], true),
  group('physical_devices', 'Physical chassis', 'chassis', [choice('vendor', 'Vendor', ['cisco', 'hillstone', 'other']),
    field('model', 'Model', true), field('verified_serial', 'Verified serial', true)], ['vendor', 'model', 'verified_serial'], true),
  group('assignments', 'Event assignments', 'assignment', [field('hostname', 'Hostname'),
    choice('role', 'Role', ['access', 'core', 'external-distribution']),
    choice('family', 'Catalyst family', ['', 'catalyst-2960x', 'catalyst-3850', 'catalyst-9200', 'catalyst-9300', 'catalyst-c1000']),
    ref('physical_device_id', 'Physical chassis', 'physical_devices', true), field('management_ip', 'Management IPv4 address', true),
    field('location', 'Location', true), raw('software', 'Software profile (JSON)', null)],
    ['hostname', 'role', 'physical_device_id', 'management_ip', 'location'], true),
  group('stacks', 'Stacks', 'Stack', [device, children('members', 'Stack members', [number('number', 'Member number'),
    ref('physical_device_id', 'Physical chassis', 'physical_devices'), choice('state', 'State', ['unknown', 'ready', 'missing'])])],
    ['assignment_id', 'members']),
  group('links', 'Topology links', 'link', [refs('endpoints', 'Link endpoints', 'physical_interfaces')], ['endpoints'], true),
  group('physical_interfaces', 'Physical ports', 'port', [device, ref('physical_device_id', 'Physical chassis', 'physical_devices'),
    field('name', 'Interface name'), number('stack_member', 'Stack member', undefined, true), ...portFields],
    ['name', 'settings.mode', 'settings.access_vlan', 'settings.native_vlan',
      'settings.allowed_vlans', 'settings.address', 'capability_status'], true),
  group('port_channels', 'Port-Channels', 'Port-Channel', [accepts(ref('interface_id', 'Port-Channel interface', 'logical_interfaces'), kind('port-channel')),
    number('number', 'Channel number'), accepts(refs('member_ids', 'Member ports', 'physical_interfaces'),
      (candidate, record, plan) => {
        const aggregate = records(plan, 'logical_interfaces').find((item) => item.id === record.interface_id)
        return !aggregate || candidate.assignment_id === aggregate.assignment_id
      }),
    choice('lacp', 'LACP mode', ['active', 'passive', 'static']), ...portFields], ['number', 'interface_id', 'lacp', 'member_ids']),
]

export const sections: Record<string, { label: string; keys: string[] }> = {
  addressing: { label: 'VLAN & IP', keys: ['vlans', 'subnets', 'gateways', 'logical_interfaces', 'vlan_access_policies'] },
  transit: { label: 'Transit', keys: ['transit', 'default_routes'] },
  dhcp: { label: 'DHCP', keys: ['dhcp_pools', 'dhcp_reservations', 'dhcp_relays'] },
  egress: { label: 'ISP & NAT', keys: ['tracks', 'isps', 'source_routes', 'snat'] },
  vpn: { label: 'VPN & routing', keys: ['ipsec_tunnels', 'vpn_remote_prefixes', 'static_routes', 'policy_routes', 'nat_exemptions'] },
  topology: { label: 'Devices / Topology', keys: ['physical_devices', 'assignments', 'stacks', 'links'] },
  ports: { label: 'Port Editor', keys: ['physical_interfaces', 'port_channels'] },
}
export const sectionRoute = (section: string) => section === 'topology' ? 'devices' :
  section === 'ports' ? 'ports' : 'planner/' + section
export function get(record: RecordValue, key: string): Value | undefined {
  const [first, ...rest] = key.split('.')
  if (!first) return undefined
  return rest.length ? get(object(record[first]), rest.join('.')) : record[first]
}
export function set(record: RecordValue, key: string, value: Value): RecordValue {
  const [first, ...rest] = key.split('.')
  if (!first) return record
  return { ...record, [first]: rest.length ? set(object(record[first]), rest.join('.'), value) : value }
}
export function defaults(fields: Field[]): RecordValue {
  return fields.reduce((record, item) => item.initial === undefined ||
    item.when && get(record, item.when[0]) !== item.when[1] ? record : set(record, item.key, item.initial), {})
}
export function options(plan: Plan, key: string, include: (record: RecordValue) => boolean = () => true) {
  return records(plan, key).filter(include).flatMap((record) => {
    const id = record.id ?? record.assignment_id
    if (typeof id !== 'string' && typeof id !== 'number') return []
    const label = record.name ?? record.hostname ?? record.network ?? record.target ?? record.model ?? record.vendor ?? id
    const owner = key.endsWith('interfaces') ? records(plan, 'assignments').find((item) => item.id === record.assignment_id)?.hostname : null
    const prefix = key === 'vlans' ? String(id) + ' — ' : owner ? String(owner) + ' / ' : ''
    const suffix = key === 'physical_devices' ? ' · ' + String(record.verified_serial ?? String(id).slice(0, 8)) : ''
    return [{ id, label: prefix + String(label) + suffix }]
  })
}
export function display(plan: Plan, item: Field, value: Value | undefined): string {
  if (item.key === 'capability_status' && value !== 'verified' || item.key === 'verified_serial' && !value) return 'UNVERIFIED'
  if (value == null || value === '') return '—'
  if (item.reference) {
    const choices = options(plan, item.reference)
    return (Array.isArray(value) ? value : [value]).map((id) => choices.find((choice) => choice.id === id)?.label ?? String(id)).join(' / ') || '—'
  }
  if (Array.isArray(value)) return value.length && typeof value[0] === 'object' ? String(value.length) : value.join(', ') || '—'
  return String(value)
}
export function patchPortSettings(previous: RecordValue, patch: RecordValue): RecordValue {
  const settings = { ...previous, ...patch }
  if (settings.mode === previous.mode) return settings
  if (settings.mode !== 'access') delete settings.access_vlan
  if (settings.mode !== 'trunk') {
    delete settings.native_vlan
    delete settings.allowed_vlans
  }
  if (settings.mode !== 'routed') delete settings.address
  return settings
}

export function clean(input: RecordValue, previous?: RecordValue): RecordValue {
  const record = { ...input }
  if (record.family === '') record.family = null
  if (record.kind !== previous?.kind && record.kind && record.kind !== 'svi') record.vlan = null
  if ('settings' in record && get(record, 'settings.mode') !== get(previous ?? {}, 'settings.mode')) {
    record.settings = patchPortSettings(object(previous?.settings), object(record.settings))
  }
  if ('activation' in record) {
    const activation = { ...object(record.activation) }
    if (activation.kind === '' || activation.kind === null) record.activation = null
    else if (activation.kind === 'always' && activation.kind !== get(previous ?? {}, 'activation.kind')) {
      delete activation.track_id
      delete activation.state
      record.activation = { ...activation }
    }
  }
  if ('next_hop' in record) {
    const hop = { ...object(record.next_hop) }
    if (hop.kind !== get(previous ?? {}, 'next_hop.kind')) {
      if (hop.kind !== 'ip') delete hop.address
      if (hop.kind !== 'tunnel') delete hop.tunnel_id
      record.next_hop = hop
    }
  }
  return record
}
