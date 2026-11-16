import { enumLabel } from '../messages'
import type { MessageKey, Translator } from '../messages'
import { object, records } from './model'
import type { Plan, RecordValue, Value } from './model'

export type Field = {
  key: string
  label: MessageKey
  type?: 'number' | 'choice' | 'ref' | 'refs' | 'json' | 'records'
  optional?: boolean
  choices?: (string | number)[]
  preserveEmpty?: boolean
  maxLength?: number
  reference?: string
  initial?: Value
  modelDefault?: Value
  when?: [string, string]
  children?: Field[]
  accepts?: (candidate: RecordValue, record: RecordValue, plan: Plan) => boolean
}
export type Group = { key: string; title: MessageKey; singular: MessageKey; fields: Field[]; columns: string[]; id: boolean; single?: boolean }
const field = (key: string, label: MessageKey, optional = false): Field => ({ key, label, optional })
const number = (key: string, label: MessageKey, initial?: number, optional = false): Field =>
  ({ key, label, initial, optional, type: 'number' })
const choice = (key: string, label: MessageKey, choices: string[]): Field =>
  ({ key, label, choices, initial: choices[0], optional: choices.includes(''), type: 'choice' })
const ref = (key: string, label: MessageKey, reference: string, optional = false): Field =>
  ({ key, label, reference, optional, type: 'ref' })
const refs = (key: string, label: MessageKey, reference: string): Field => ({ key, label, reference, type: 'refs', initial: [] })
const children = (key: string, label: MessageKey, fields: Field[]): Field =>
  ({ key, label, type: 'records', initial: [], children: fields })
const raw = (key: string, label: MessageKey, initial: Value): Field => ({ key, label, initial, optional: true, type: 'json' })
const when = (item: Field, key: string, value: string): Field => ({ ...item, when: [key, value] })
const kind = (value: string) => (candidate: RecordValue) => candidate.kind === value
const owner = (key: string) => (candidate: RecordValue, record: RecordValue) =>
  !record[key] || candidate.assignment_id === record[key]
const accepts = (field: Field, predicate: NonNullable<Field['accepts']>): Field =>
  ({ ...field, accepts: predicate })
const device = ref('assignment_id', 'deviceAssignment', 'assignments')
const subnet = ref('subnet_id', 'subnet', 'subnets')
const svi = accepts(ref('svi_id', 'svi', 'logical_interfaces'), (candidate, record, plan) => {
  const subnet = records(plan, 'subnets').find((item) => item.id === record.subnet_id)
  return candidate.kind === 'svi' && (!subnet || candidate.vlan === subnet.vlan)
})
const source = ref('source_vlan', 'sourceVlan', 'vlans')
const target = field('destination', 'destinationCidr')
const track = ref('track_id', 'track', 'tracks')
const tunnel = accepts(ref('tunnel_id', 'tunnel', 'ipsec_tunnels'), owner('assignment_id'))
const isp = accepts(ref('isp_id', 'isp', 'isps'), owner('assignment_id'))
const pref = number('preference', 'preference', 1)
const priority = number('priority', 'priority', 10)
const defaultLacp = 'active'
const lacpMode = { ...choice('lacp', 'lacpMode', [defaultLacp, 'passive', 'static']), modelDefault: defaultLacp }
const portModeFields = [
  choice('settings.mode', 'mode', ['access', 'trunk', 'routed']),
  when(ref('settings.access_vlan', 'accessVlan', 'vlans'), 'settings.mode', 'access'),
  when(ref('settings.native_vlan', 'nativeVlan', 'vlans', true), 'settings.mode', 'trunk'),
  when({ ...refs('settings.allowed_vlans', 'allowedVlans', 'vlans'), modelDefault: [] }, 'settings.mode', 'trunk'),
  when(field('settings.address', 'ipv4AddressPrefix', true), 'settings.mode', 'routed'),
]
const layer2Fields = [
  { ...choice('settings.portfast', 'portfast', ['edge', 'edge-trunk', 'disabled']), initial: undefined },
  { ...choice('settings.bpdu_guard', 'bpduGuard', ['enabled', 'disabled']), initial: undefined },
]
const portDescription: Field = { ...field('settings.description', 'description', true), preserveEmpty: true, maxLength: 240 }
const adminState = { ...choice('settings.admin_state', 'administrativeState', ['up', 'down']), initial: undefined }
const physicalMedia: Field[] = [
  { key: 'settings.speed', label: 'speedMbps', type: 'choice',
    choices: ['auto', 10, 100, 1000, 2500, 5000, 10000, 25000, 40000, 50000, 100000, 200000, 400000, 800000] },
  { ...choice('settings.duplex', 'duplex', ['auto', 'full', 'half']), initial: undefined },
  { ...choice('settings.poe_mode', 'poeMode', ['auto', 'static', 'never']), initial: undefined },
]
const portFields = [portDescription, adminState, ...portModeFields, ...physicalMedia, ...layer2Fields]
const channelFields = [portDescription, adminState, ...portModeFields, ...layer2Fields]
const group = (key: string, title: MessageKey, singular: MessageKey, fields: Field[], columns: string[], id = false): Group =>
  ({ key, title, singular, fields, columns, id })

export const catalog = [
  group('vlans', 'vlans', 'vlan', [number('id', 'vlanId'), field('name', 'name'),
    choice('purpose', 'purpose', ['ordinary', 'management', 'guest', 'sensitive', 'transit'])], ['id', 'name', 'purpose']),
  group('subnets', 'subnets', 'recordSubnet', [ref('vlan', 'vlan', 'vlans'), field('network', 'ipv4Cidr')], ['network', 'vlan'], true),
  group('gateways', 'gateways', 'gateway', [subnet, field('address', 'ipv4Address'), svi], ['subnet_id', 'address', 'svi_id']),
  group('logical_interfaces', 'logicalInterfaces', 'logicalInterface', [device, field('name', 'interfaceName'),
    choice('kind', 'type', ['svi', 'port-channel', 'loopback']),
    when(ref('vlan', 'vlan', 'vlans'), 'kind', 'svi'),
    field('address', 'ipv4AddressPrefix', true)], ['name', 'assignment_id', 'kind', 'address'], true),
  group('vlan_access_policies', 'vlanPolicies', 'vlanPolicy', [source, ref('destination_vlan', 'destinationVlan', 'vlans'),
    priority, choice('action', 'action', ['deny', 'allow'])], ['source_vlan', 'destination_vlan', 'priority', 'action'], true),
  { ...group('transit', 'coreHillstoneTransit', 'transit', [ref('core_assignment_id', 'ciscoCore', 'assignments'),
    ref('hillstone_assignment_id', 'hillstoneFirewall', 'assignments'),
    accepts(ref('core_port_id', 'corePort', 'physical_interfaces'), owner('core_assignment_id')),
    accepts(ref('hillstone_port_id', 'firewallPort', 'physical_interfaces'), owner('hillstone_assignment_id')),
    accepts(ref('core_svi_id', 'coreSvi', 'logical_interfaces'), (candidate, record) =>
      candidate.kind === 'svi' && owner('core_assignment_id')(candidate, record)),
    { ...ref('vlan', 'transitVlan', 'vlans'), initial: 9 }, field('network', 'transitCidr'), field('core_ip', 'coreIp'),
    field('hillstone_ip', 'hillstoneIp')], ['vlan', 'network', 'core_ip', 'hillstone_ip']), single: true },
  group('dhcp_pools', 'dhcpPools', 'pool', [subnet, field('start', 'startAddress'), field('end', 'endAddress'),
    number('lease_seconds', 'leaseSeconds', 43200)], ['subnet_id', 'start', 'end', 'lease_seconds'], true),
  group('dhcp_reservations', 'dhcpReservations', 'reservation', [subnet, field('address', 'ipv4Address'),
    field('client_mac', 'clientMac')], ['subnet_id', 'address', 'client_mac'], true),
  group('dhcp_relays', 'dhcpRelays', 'relay', [subnet, svi, raw('servers', 'relayServerAddressesJsonArray', [])], ['subnet_id', 'svi_id', 'servers']),
  group('tracks', 'tracks', 'track', [field('target', 'probeTarget'), number('interval_seconds', 'intervalSeconds', 5),
    number('failure_threshold', 'failureThreshold', 3), { ...tunnel, optional: true }], ['target', 'interval_seconds', 'tunnel_id'], true),
  group('isps', 'ispUplinks', 'isp', [field('name', 'name'), device, accepts(ref('interface_id', 'wanInterface', 'physical_interfaces'), (candidate, record) =>
    get(candidate, 'settings.mode') === 'routed' && owner('assignment_id')(candidate, record)),
    field('address', 'ipv4AddressPrefix'), field('gateway', 'recordGateway'), { ...track, optional: true },
    children('routed_public_blocks', 'routedPublicBlocks', [field('network', 'cidr'), field('reason', 'reason')])],
    ['name', 'interface_id', 'address', 'gateway', 'track_id'], true),
  group('source_routes', 'sourceBasedRoutes', 'sbrRule', [device, source, accepts(refs('isp_priority', 'ispFailoverOrder', 'isps'), owner('assignment_id')),
    children('no_nat', 'noNatExceptions', [isp, field('reason', 'reason')])], ['source_vlan', 'isp_priority', 'no_nat'], true),
  group('snat', 'sourceNat', 'snatRule', [device, source, isp, field('translated_ip', 'translatedIpv4Address')],
    ['source_vlan', 'isp_id', 'translated_ip'], true),
  group('ipsec_tunnels', 'ipsecTunnels', 'recordTunnel', [field('name', 'name'), device, isp, field('peer', 'peerIpv4Address'),
    field('inside', 'insideIpv4Prefix'), field('remote_gateway', 'remoteGateway'), track,
    choice('state', 'tunnelState', ['unknown', 'up', 'down'])], ['name', 'isp_id', 'peer', 'inside', 'state'], true),
  group('vpn_remote_prefixes', 'vpnRemotePrefixes', 'vpnPrefix', [tunnel, field('network', 'remoteCidr')], ['tunnel_id', 'network']),
  group('static_routes', 'staticRoutes', 'staticRoute', [device, target, pref,
    choice('next_hop.kind', 'nextHopType', ['ip', 'tunnel', 'discard']),
    when(field('next_hop.address', 'nextHopAddress'), 'next_hop.kind', 'ip'),
    when({ ...tunnel, key: 'next_hop.tunnel_id', label: 'nextHopTunnel' }, 'next_hop.kind', 'tunnel'),
    choice('activation.kind', 'activation', ['', 'always', 'track']),
    when({ ...track, key: 'activation.track_id', label: 'routeTrack' }, 'activation.kind', 'track'),
    when(choice('activation.state', 'requiredTrackState', ['up', 'down']), 'activation.kind', 'track')],
    ['destination', 'assignment_id', 'next_hop.kind', 'preference', 'activation.kind'], true),
  group('default_routes', 'defaultRoutes', 'defaultRoute', [device, choice('next_hop.kind', 'nextHopType', ['ip']),
    field('next_hop.address', 'nextHopAddress'), pref], ['assignment_id', 'next_hop.address', 'preference'], true),
  group('policy_routes', 'policyBasedRoutes', 'pbrRule', [device, source, target, tunnel, priority,
    choice('on_tunnel_down', 'whenTunnelIsDown', ['discard', 'route-table', 'unknown', 'use-sbr'])],
    ['source_vlan', 'destination', 'tunnel_id', 'on_tunnel_down'], true),
  group('nat_exemptions', 'natExemptions', 'natExemption', [device, source, target, tunnel], ['source_vlan', 'destination', 'tunnel_id'], true),
  group('physical_devices', 'physicalChassis', 'chassis', [choice('vendor', 'vendor', ['cisco', 'hillstone', 'other']),
    field('model', 'model', true), field('verified_serial', 'verifiedSerial', true)], ['vendor', 'model', 'verified_serial'], true),
  group('assignments', 'eventAssignments', 'assignment', [field('hostname', 'hostname'),
    choice('role', 'role', ['access', 'core', 'external-distribution']),
    choice('family', 'catalystFamily', ['', 'catalyst-2960x', 'catalyst-3850', 'catalyst-9200', 'catalyst-9300', 'catalyst-c1000']),
    ref('physical_device_id', 'physicalChassis', 'physical_devices', true), field('management_ip', 'managementIpv4Address', true),
    field('location', 'location', true), raw('software', 'softwareProfileJson', null)],
    ['hostname', 'role', 'physical_device_id', 'management_ip', 'location'], true),
  group('stacks', 'stacks', 'stack', [device, children('members', 'stackMembers', [number('number', 'memberNumber'),
    ref('physical_device_id', 'physicalChassis', 'physical_devices'), choice('state', 'state', ['unknown', 'ready', 'missing'])])],
    ['assignment_id', 'members']),
  group('links', 'topologyLinks', 'link', [refs('endpoints', 'linkEndpoints', 'physical_interfaces')], ['endpoints'], true),
  group('physical_interfaces', 'physicalPorts', 'port', [device, ref('physical_device_id', 'physicalChassis', 'physical_devices'),
    field('name', 'interfaceName'), number('stack_member', 'stackMember', undefined, true), ...portFields],
    ['name', 'settings.mode', 'settings.access_vlan', 'settings.native_vlan',
      'settings.allowed_vlans', 'settings.address', 'capability_status'], true),
  group('port_channels', 'portChannels', 'portChannel', [accepts(ref('interface_id', 'portChannelInterface', 'logical_interfaces'), kind('port-channel')),
    number('number', 'channelNumber'), accepts(refs('member_ids', 'memberPorts', 'physical_interfaces'),
      (candidate, record, plan) => {
        const aggregate = records(plan, 'logical_interfaces').find((item) => item.id === record.interface_id)
        return !aggregate || candidate.assignment_id === aggregate.assignment_id
      }),
    lacpMode, ...channelFields], ['number', 'interface_id', 'lacp', 'member_ids', 'settings.mode']),
]

export const sections: Record<string, { label: MessageKey; keys: string[] }> = {
  addressing: { label: 'vlanIp', keys: ['vlans', 'subnets', 'gateways', 'logical_interfaces', 'vlan_access_policies'] },
  transit: { label: 'recordTransit', keys: ['transit', 'default_routes'] },
  dhcp: { label: 'dhcp', keys: ['dhcp_pools', 'dhcp_reservations', 'dhcp_relays'] },
  egress: { label: 'ispNat', keys: ['tracks', 'isps', 'source_routes', 'snat'] },
  vpn: { label: 'vpnRouting', keys: ['ipsec_tunnels', 'vpn_remote_prefixes', 'static_routes', 'policy_routes', 'nat_exemptions'] },
  topology: { label: 'devices', keys: ['physical_devices', 'assignments', 'stacks', 'links'] },
  ports: { label: 'ports', keys: ['physical_interfaces', 'port_channels'] },
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
export function withModelDefault(field: Field, value: Value | undefined) {
  return value === undefined ? field.modelDefault : value
}
export function display(t: Translator, plan: Plan, item: Field, value: Value | undefined): string {
  value = withModelDefault(item, value)
  if (item.key === 'capability_status' && value !== 'verified' || item.key === 'verified_serial' && !value) return t('unverifiedBadge')
  if (value == null || value === '') return '—'
  if (item.reference) {
    const choices = options(plan, item.reference)
    return (Array.isArray(value) ? value : [value]).map((id) => choices.find((choice) => choice.id === id)?.label ?? String(id)).join(' / ') || '—'
  }
  if (Array.isArray(value)) return value.length && typeof value[0] === 'object' ? String(value.length) : value.join(', ') || '—'
  if ((item.choices || item.key === 'capability_status') && typeof value === 'string') return enumLabel(t, value, item.key)
  return String(value)
}
export function clean(input: RecordValue, previous?: RecordValue): RecordValue {
  const record = { ...input }
  if (record.family === '') record.family = null
  if (record.kind !== previous?.kind && record.kind && record.kind !== 'svi') record.vlan = null
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
