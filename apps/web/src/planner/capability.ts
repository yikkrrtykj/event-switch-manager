import { json, request } from '../api'
import { enumLabel } from '../messages'
import type { MessageKey, Translator } from '../messages'
import { fingerprint, records } from './model'
import type { Plan, RecordValue, Value } from './model'

export type CapabilityId =
  | 'identity' | 'stack' | 'port-layout' | 'port-media' | 'speed' | 'duplex' | 'poe' | 'poe-plus'
  | 'vlan' | 'access' | 'trunk' | 'routed-port' | 'lacp' | 'port-channel' | 'portfast'
  | 'bpdu-guard' | 'vtp-transparent' | 'svi' | 'ipv4-routing' | 'dhcp-server' | 'dhcp-relay'
  | 'dhcp-client' | 'static-route' | 'default-route' | 'ssh-v2' | 'aaa' | 'boot' | 'storage'
  | 'rapid-pvst'

export type CapabilityVerdict = 'supported' | 'unsupported' | 'unknown'

export type CapabilityEvidence = {
  url: string
  section: string
  family: string
  sku: string
  version_scope: string | null
  licenses: string[]
  conditions: string
  status: 'vendor-documentation'
}

export type PortGroup = {
  medium: string
  slot: number
  first: number
  count: number
  prefix: string
  rates: number[]
  poe_plus: boolean
}

export type CapabilityTargetRecord = {
  event_id: string
  assignment_id: string
  physical_device_id: string | null
  interface_id: string | null
  interface_name: string | null
  stack_member: number | null
  sku: string | null
  software: string | null
  license: string | null
}

export type CapabilityDecision = {
  capability_id: CapabilityId
  verdict: CapabilityVerdict
  reason_code: string
  reason: string
  evidence: CapabilityEvidence[]
  affected: CapabilityTargetRecord
  port_groups: PortGroup[]
  verification: 'not-verified'
  deployment_status: 'blocked'
  blocks_deployment: true
  deployment_blockers: string[]
}

export type DraftCapabilityPreview = {
  source: 'unsaved-draft'
  draft_fingerprint: string
  input_fingerprint: string
  decisions: CapabilityDecision[]
}

export type CapabilityRequest = {
  plan: Plan
  assignment_id: string
  capabilities: CapabilityId[]
  interface_id?: string | null
  stack_member?: number | null
}

export type CapabilityStatus = 'idle' | 'loading' | 'current' | 'stale' | 'error'

export type CapabilityState = {
  status: CapabilityStatus
  preview?: DraftCapabilityPreview
  error?: string
  requestKey: string
}

export type CapabilityTarget = {
  key: string
  assignmentId: string
  interfaceId?: string
  stackMember?: number
  device: string
  member: string
  name: string
  item: RecordValue
  channel?: RecordValue
}

export const PORT_CAPABILITIES: readonly CapabilityId[] = [
  'port-layout', 'port-media', 'poe', 'speed', 'duplex', 'stack',
  'access', 'trunk', 'routed-port', 'portfast', 'bpdu-guard', 'lacp', 'port-channel',
  'svi', 'ipv4-routing', 'dhcp-relay',
]

export const CHANNEL_CAPABILITIES: readonly CapabilityId[] = [
  'port-media', 'poe', 'speed', 'duplex', 'stack',
  'access', 'trunk', 'routed-port', 'portfast', 'bpdu-guard', 'lacp', 'port-channel',
  'svi', 'ipv4-routing', 'dhcp-relay',
]

export const capabilityGroups: readonly { key: string; label: MessageKey; ids: readonly CapabilityId[] }[] = [
  { key: 'hardware', label: 'capabilityGroupHardware',
    ids: ['port-layout', 'port-media', 'poe', 'speed', 'duplex', 'stack'] },
  { key: 'layer2', label: 'capabilityGroupLayer2',
    ids: ['access', 'trunk', 'portfast', 'bpdu-guard', 'lacp', 'port-channel'] },
  { key: 'layer3', label: 'capabilityGroupLayer3',
    ids: ['routed-port', 'svi', 'ipv4-routing', 'dhcp-relay'] },
]

export const capabilityLabels: Readonly<Record<CapabilityId, MessageKey>> = {
  'identity': 'capabilityNameIdentity',
  'stack': 'capabilityNameStack',
  'port-layout': 'capabilityNamePortLayout',
  'port-media': 'capabilityNamePortMedia',
  'speed': 'capabilityNameSpeed',
  'duplex': 'capabilityNameDuplex',
  'poe': 'capabilityNamePoe',
  'poe-plus': 'capabilityNamePoePlus',
  'vlan': 'capabilityNameVlan',
  'access': 'capabilityNameAccess',
  'trunk': 'capabilityNameTrunk',
  'routed-port': 'capabilityNameRoutedPort',
  'lacp': 'capabilityNameLacp',
  'port-channel': 'capabilityNamePortChannel',
  'portfast': 'capabilityNamePortfast',
  'bpdu-guard': 'capabilityNameBpduGuard',
  'vtp-transparent': 'capabilityNameVtpTransparent',
  'svi': 'capabilityNameSvi',
  'ipv4-routing': 'capabilityNameIpv4Routing',
  'dhcp-server': 'capabilityNameDhcpServer',
  'dhcp-relay': 'capabilityNameDhcpRelay',
  'dhcp-client': 'capabilityNameDhcpClient',
  'static-route': 'capabilityNameStaticRoute',
  'default-route': 'capabilityNameDefaultRoute',
  'ssh-v2': 'capabilityNameSshV2',
  'aaa': 'capabilityNameAaa',
  'boot': 'capabilityNameBoot',
  'storage': 'capabilityNameStorage',
  'rapid-pvst': 'capabilityNameRapidPvst',
}

const reasonLabels: Readonly<Record<string, MessageKey>> = {
  'pid-documented': 'capabilityReasonPidDocumented',
  'feature-documented': 'capabilityReasonFeatureDocumented',
  'speed-documented': 'capabilityReasonSpeedDocumented',
  'duplex-documented': 'capabilityReasonDuplexDocumented',
  'poe-documented': 'capabilityReasonPoeDocumented',
  'port-documented': 'capabilityReasonPortDocumented',
  'layout-documented': 'capabilityReasonLayoutDocumented',
  'stack-capable': 'capabilityReasonStackCapable',
  'stack-layout-documented': 'capabilityReasonStackLayoutDocumented',
  'software-missing': 'capabilityReasonSoftwareMissing',
  'software-is-rommon': 'capabilityReasonSoftwareIsRommon',
  'release-unmatched': 'capabilityReasonReleaseUnmatched',
  'release-evidence-missing': 'capabilityReasonReleaseEvidenceMissing',
  'license-unmatched': 'capabilityReasonLicenseUnmatched',
  'feature-evidence-missing': 'capabilityReasonFeatureEvidenceMissing',
  'identity-incomplete': 'capabilityReasonIdentityIncomplete',
  'pid-unlisted': 'capabilityReasonPidUnlisted',
  'family-mismatch': 'capabilityReasonFamilyMismatch',
  'port-required': 'capabilityReasonPortRequired',
  'port-layout-unknown': 'capabilityReasonPortLayoutUnknown',
  'optic-unknown': 'capabilityReasonOpticUnknown',
  'speed-required': 'capabilityReasonSpeedRequired',
  'duplex-required': 'capabilityReasonDuplexRequired',
  'speed-outside-port-range': 'capabilityReasonSpeedOutsidePortRange',
  'speed-unsupported': 'capabilityReasonSpeedUnsupported',
  'duplex-unsupported': 'capabilityReasonDuplexUnsupported',
  'duplex-speed-required': 'capabilityReasonDuplexSpeedRequired',
  'poe-unsupported': 'capabilityReasonPoeUnsupported',
  'stack-unsupported': 'capabilityReasonStackUnsupported',
  'stack-evidence-missing': 'capabilityReasonStackEvidenceMissing',
  'stack-member-limit': 'capabilityReasonStackMemberLimit',
  'stack-identities-unresolved': 'capabilityReasonStackIdentitiesUnresolved',
  'stack-layout-unresolved': 'capabilityReasonStackLayoutUnresolved',
  'target-binding-unknown': 'capabilityReasonTargetBindingUnknown',
  'stack-binding-unknown': 'capabilityReasonStackBindingUnknown',
  'uplink-module-unknown': 'capabilityReasonUplinkModuleUnknown',
  'prerequisites-unobserved': 'capabilityReasonPrerequisitesUnobserved',
  'feature-license-unverified': 'capabilityReasonFeatureLicenseUnverified',
  'plan-invalid': 'capabilityReasonPlanInvalid',
}

const blockerLabels: Readonly<Record<string, MessageKey>> = {
  'deployment-generation-disabled': 'capabilityBlockerDeploymentDisabled',
  'hardware-not-verified': 'capabilityBlockerHardwareNotVerified',
  'draft-not-persisted': 'capabilityBlockerDraftNotPersisted',
  'plan-invalid': 'capabilityReasonPlanInvalid',
}

export function capabilityName(t: Translator, capability: CapabilityId) {
  return t(capabilityLabels[capability] ?? 'capabilityNameUnknown')
}

export function capabilityReason(t: Translator, code: string, fallback: string) {
  const key = reasonLabels[code]
  return key ? t(key) : fallback
}

export function blockerLabel(t: Translator, code: string) {
  const blocker = blockerLabels[code]
  if (blocker) return t(blocker)
  const reason = reasonLabels[code]
  return reason ? t(reason) : code
}

export function verdictLabel(t: Translator, verdict: CapabilityVerdict) {
  return t(verdict === 'supported' ? 'capabilityVerdictSupported'
    : verdict === 'unsupported' ? 'capabilityVerdictUnsupported' : 'capabilityVerdictUnknown')
}

export function verdictTone(verdict: CapabilityVerdict) {
  return verdict === 'supported' ? 'success' : verdict === 'unsupported' ? 'danger' : 'warning'
}

export function previewCapability(requestBody: CapabilityRequest, signal?: AbortSignal) {
  return request<DraftCapabilityPreview>(
    '/events/' + encodeURIComponent(requestBody.plan.event_id) + '/plan/capability-preview',
    { ...json(requestBody), signal },
  )
}

export function capabilityKey(
  plan: Plan, targets: CapabilityTarget[], capabilities: readonly CapabilityId[],
) {
  return fingerprint({
    plan,
    targets: targets.map(({ assignmentId, interfaceId, stackMember }) =>
      ({ assignmentId, interfaceId: interfaceId ?? null, stackMember: stackMember ?? null })),
    capabilities: [...capabilities],
  })
}

export function applyProposedPorts(
  plan: Plan, proposed: readonly { index: number; next: RecordValue }[],
) {
  const interfaces = records(plan, 'physical_interfaces').slice()
  for (const { index, next } of proposed) {
    if (index >= 0 && index < interfaces.length) interfaces[index] = next
    else if (index === interfaces.length) interfaces.push(next)
  }
  return { ...plan, physical_interfaces: interfaces }
}

export function applyProposedChannel(plan: Plan, channel: RecordValue) {
  const interfaceId = channel.interface_id
  if (typeof interfaceId !== 'string') return plan
  const channels = records(plan, 'port_channels')
  const index = channels.findIndex((item) => item.interface_id === interfaceId)
  if (index < 0) return { ...plan, port_channels: [...channels, channel] }
  return { ...plan, port_channels: channels.map((item, position) => position === index ? channel : item) }
}

export function targetKey(assignmentId: string, interfaceId?: string | null, stackMember?: number | null) {
  return [assignmentId, interfaceId ?? 'none', stackMember ?? 'standalone'].join(':')
}

export function summarizeCapabilities(states: Record<string, CapabilityState>) {
  const summary = { supported: 0, unsupported: 0, unknown: 0, pending: 0, stale: 0, error: 0 }
  for (const state of Object.values(states)) {
    if (state.status === 'loading' || state.status === 'idle') {
      summary.pending += 1
      continue
    }
    if (state.status === 'error') {
      summary.error += 1
      continue
    }
    if (state.status === 'stale') {
      summary.stale += 1
      continue
    }
    for (const decision of state.preview?.decisions ?? []) {
      if (decision.verdict === 'supported') summary.supported += 1
      else if (decision.verdict === 'unsupported') summary.unsupported += 1
      else summary.unknown += 1
    }
  }
  return summary
}

const changeCapabilities: Readonly<Record<string, readonly CapabilityId[]>> = {
  'settings.speed': ['speed', 'port-media'],
  'settings.duplex': ['duplex'],
  'settings.poe_mode': ['poe'],
  'settings.mode': ['access', 'trunk', 'routed-port'],
  'settings.access_vlan': ['access'],
  'settings.native_vlan': ['trunk'],
  'settings.allowed_vlans': ['trunk'],
  'settings.address': ['routed-port', 'svi', 'ipv4-routing'],
  'settings.portfast': ['portfast'],
  'settings.bpdu_guard': ['bpdu-guard'],
  'lacp': ['lacp', 'port-channel'],
  'member_ids': ['lacp', 'port-channel', 'port-media', 'poe'],
  'name': ['port-layout', 'port-media', 'poe', 'speed', 'duplex'],
  'physical_device_id': ['identity', 'port-media', 'poe', 'stack'],
  'stack_member': ['stack', 'port-media', 'poe'],
  'assignment_id': ['identity', 'port-media', 'poe', 'stack'],
}

export function capabilitiesForChange(field: string): readonly CapabilityId[] {
  return changeCapabilities[field] ?? []
}

export function settingLabel(
  t: Translator, capability: CapabilityId, item: RecordValue, channel?: RecordValue,
) {
  const source = channel && ['access', 'trunk', 'routed-port', 'portfast', 'bpdu-guard', 'lacp', 'port-channel'].includes(capability)
    ? channel : item
  const settings = (source.settings && typeof source.settings === 'object' && !Array.isArray(source.settings))
    ? source.settings : {}
  const value = (key: string): Value | undefined => settings[key] ?? item[key]
  const choice = (value_: Value | undefined, fallback: string) =>
    enumLabel(t, typeof value_ === 'string' || typeof value_ === 'number' ? value_ : fallback)
  switch (capability) {
    case 'speed': return t('capabilitySettingSpeed', { value: choice(value('speed'), 'auto') })
    case 'duplex': return t('capabilitySettingDuplex', { value: choice(value('duplex'), 'auto') })
    case 'poe': case 'poe-plus':
      return t('capabilitySettingPoe', { value: choice(value('poe_mode'), 'auto') })
    case 'access': case 'trunk': case 'routed-port':
      return t('capabilitySettingMode', { value: choice(value('mode'), 'access') })
    case 'portfast': {
      const portfast = value('portfast')
      return t('capabilitySettingPortfast', {
        value: portfast == null ? t('platformDefault') : enumLabel(t, String(portfast)),
      })
    }
    case 'bpdu-guard': {
      const bpduGuard = value('bpdu_guard')
      return t('capabilitySettingBpduGuard', {
        value: bpduGuard == null ? t('platformDefault') : enumLabel(t, String(bpduGuard)),
      })
    }
    case 'lacp':
      return channel
        ? t('capabilitySettingLacp', { value: choice(source.lacp, 'active') })
        : t('capabilitySettingSoftware')
    case 'port-channel':
      return channel && typeof source.number === 'number'
        ? t('capabilitySettingChannel', { value: String(source.number) })
        : t('capabilitySettingSoftware')
    case 'stack':
      return typeof item.stack_member === 'number'
        ? t('capabilitySettingStack', { value: t('stackMemberNumber', { number: item.stack_member }) })
        : t('capabilitySettingStack', { value: t('standalone') })
    case 'port-media': return t('capabilitySettingMedia')
    case 'port-layout': return t('capabilitySettingLayout')
    case 'identity': return t('capabilitySettingIdentity')
    default: return t('capabilitySettingSoftware')
  }
}
