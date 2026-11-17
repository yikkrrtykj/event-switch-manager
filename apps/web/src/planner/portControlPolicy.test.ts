import { describe, expect, it } from 'vitest'
import { catalog } from './catalog'
import type { Field } from './catalog'
import { evaluateControlPolicy } from './portControlPolicy'
import type { MembershipChange } from './portControlPolicy'
import { isPortSetting } from './portSettings'
import type { Operations } from './portSettings'
import type {
  CapabilityDecision, CapabilityId, CapabilityState, CapabilityTarget, CapabilityVerdict, PortGroup,
} from './capability'
import type { Plan, RecordValue, Value } from './model'

const plan: Plan = { schema_version: 1, event_id: 'event-1', management_vlan: 10 }

const portFields = catalog.find((group) => group.key === 'physical_interfaces')!
  .fields.filter(isPortSetting)
const channelFields = catalog.find((group) => group.key === 'port_channels')!
  .fields.filter(isPortSetting)

function copper(poe: boolean): PortGroup {
  return { medium: 'copper-rj45', slot: 0, first: 1, count: 24, prefix: 'gi', rates: [10, 100, 1000], poe_plus: poe }
}

const sfp: PortGroup = { medium: 'sfp', slot: 1, first: 1, count: 4, prefix: 'gi', rates: [1000], poe_plus: false }

function decision(
  capability_id: CapabilityId,
  verdict: CapabilityVerdict,
  options: { reason?: string; reasonCode?: string; groups?: PortGroup[] } = {},
): CapabilityDecision {
  const reasonCode = options.reasonCode ?? (verdict === 'supported' ? 'feature-documented'
    : verdict === 'unsupported' ? 'poe-unsupported' : 'release-unmatched')
  return {
    capability_id,
    verdict,
    reason_code: reasonCode,
    reason: options.reason ?? 'Synthetic test evidence.',
    evidence: [],
    affected: {
      event_id: 'event-1', assignment_id: 'assignment-1', physical_device_id: 'device-1',
      interface_id: 'interface-1', interface_name: 'Gi1/0/1', stack_member: null,
      sku: 'C9300L-24T-4G', software: '17.12.4', license: 'Network Advantage',
    },
    port_groups: options.groups ?? [],
    verification: 'not-verified',
    deployment_status: 'blocked',
    blocks_deployment: true,
    deployment_blockers: ['deployment-generation-disabled', 'hardware-not-verified',
      'draft-not-persisted'],
  }
}

function state(decisions: CapabilityDecision[], status: CapabilityState['status'] = 'current'): CapabilityState {
  if (status !== 'current') return { status, requestKey: 'k' }
  return {
    status: 'current',
    requestKey: 'k',
    preview: {
      source: 'unsaved-draft',
      draft_fingerprint: 'a'.repeat(64),
      input_fingerprint: 'b'.repeat(64),
      decisions,
    },
  }
}

function portTarget(key: string, record: RecordValue, options: {
  device?: string; name?: string; channel?: RecordValue
} = {}): CapabilityTarget {
  return {
    key,
    assignmentId: String(record.assignment_id ?? 'assignment-1'),
    interfaceId: String(record.id ?? key),
    device: options.device ?? 'Synthetic-Access',
    member: 'Standalone',
    name: options.name ?? String(record.name ?? 'Gi1/0/1'),
    item: record,
    channel: options.channel,
  }
}

function port(key: string, settings: RecordValue, extra: RecordValue = {}): RecordValue {
  return {
    id: key, assignment_id: 'assignment-1', physical_device_id: 'device-1',
    name: extra.name ?? 'Gi1/0/1', settings, ...extra,
  }
}

function evaluate(options: {
  targets: CapabilityTarget[]
  states: Record<string, CapabilityState>
  operations?: Operations
  fields?: Field[]
  aggregate?: boolean
  membership?: MembershipChange
}) {
  return evaluateControlPolicy({
    plan,
    targets: options.targets,
    states: options.states,
    operations: options.operations ?? {},
    fields: options.fields ?? portFields,
    aggregate: options.aggregate,
    membership: options.membership,
  })
}

function channelRecord(members: string[], lacp = 'active'): RecordValue {
  return {
    interface_id: 'logical-1', number: 1, member_ids: members, lacp,
    settings: { mode: 'trunk', native_vlan: 10, allowed_vlans: [10] },
  }
}

function memberTargets(members: string[], channel: RecordValue): CapabilityTarget[] {
  return members.map((id, index) => portTarget(
    `assignment-1:${id}:standalone`,
    port(id, { mode: 'trunk' }),
    { name: `Gi1/0/${index + 1}`, channel },
  ))
}

function memberState(portChannel: CapabilityVerdict, lacp: CapabilityVerdict = 'supported') {
  return state([
    decision('port-channel', portChannel, {
      reasonCode: portChannel === 'supported' ? 'feature-documented'
        : portChannel === 'unknown' ? 'release-unmatched' : 'feature-license-unverified',
    }),
    decision('lacp', lacp, {
      reasonCode: lacp === 'supported' ? 'feature-documented'
        : lacp === 'unknown' ? 'release-unmatched' : 'feature-license-unverified',
    }),
  ])
}

function channelPolicy(options: {
  original: string[]
  proposed: string[]
  lacp?: string
  verdicts?: Record<string, {
    pc: CapabilityVerdict; lacp?: CapabilityVerdict; stale?: boolean
  }>
}) {
  const channel = channelRecord(options.proposed, options.lacp ?? 'static')
  const targets = memberTargets(options.proposed, channel)
  const states: Record<string, CapabilityState> = {}
  for (const target of targets) {
    const entry = options.verdicts?.[target.interfaceId!]
    states[target.key] = entry?.stale ? state([], 'stale')
      : entry ? memberState(entry.pc, entry.lacp) : memberState('supported')
  }
  return evaluate({
    targets,
    states,
    fields: channelFields,
    aggregate: true,
    membership: {
      original: options.original,
      proposed: options.proposed,
      lacp: options.lacp ?? 'static',
    },
  })
}

function poeState(verdict: CapabilityVerdict) {
  const key = 'assignment-1:interface-1:standalone'
  return {
    targets: [portTarget(key, port('interface-1', { mode: 'access', access_vlan: 10 }))],
    states: { [key]: state([decision('poe', verdict)]) },
  }
}

describe('capability-driven control policy', () => {
  it('hard-blocks static PoE on hardware that documents no PoE and keeps never safe', () => {
    const { targets, states } = poeState('unsupported')
    const policy = evaluate({ targets, states, operations: { 'settings.poe_mode': { kind: 'set', value: 'static' } } })
    const field = policy.fields['settings.poe_mode']!
    expect(field.candidate?.outcome).toBe('blocked')
    expect(field.candidate?.verdicts[0]?.reasonCode).toBe('poe-unsupported')
    expect(policy.hasBlocked).toBe(true)
    const staticCandidate = field.candidates.find((candidate) => candidate.value === 'static')!
    expect(staticCandidate.outcome).toBe('blocked')
    expect(field.candidates.find((candidate) => candidate.value === 'auto')!.outcome).toBe('warning')
    expect(field.candidates.find((candidate) => candidate.value === 'never')!.outcome).toBe('allowed')
    expect(field.setAllowed).toBe(true)
  })

  it('allows documented PoE candidates on PoE-capable hardware', () => {
    const { targets, states } = poeState('supported')
    const policy = evaluate({ targets, states, operations: { 'settings.poe_mode': { kind: 'set', value: 'static' } } })
    expect(policy.fields['settings.poe_mode']!.candidate?.outcome).toBe('allowed')
    expect(policy.hasBlocked).toBe(false)
  })

  it('judges speed candidates against the documented port range instead of the current verdict', () => {
    const key = 'assignment-1:interface-1:standalone'
    const targets = [portTarget(key, port('interface-1', { mode: 'access', speed: 1000 }))]
    const states = {
      [key]: state([decision('speed', 'supported', { groups: [copper(false)], reasonCode: 'speed-documented' })]),
    }
    const policy = evaluate({ targets, states })
    const speed = policy.fields['settings.speed']!
    const outcome = (value: Value) => speed.candidates.find((candidate) => candidate.value === value)!.outcome
    expect(outcome(1000)).toBe('allowed')
    expect(outcome('auto')).toBe('allowed')
    expect(outcome(2500)).toBe('blocked')
    expect(outcome(10000)).toBe('blocked')
    expect(speed.setAllowed).toBe(true)
  })

  it('hard-blocks a copper candidate than the documented rates without using the whole device maximum', () => {
    const key = 'assignment-1:interface-1:standalone'
    const targets = [portTarget(key, port('interface-1', { mode: 'access' }))]
    const states = {
      [key]: state([decision('speed', 'supported', {
        groups: [copper(false)], reasonCode: 'speed-documented',
      })]),
    }
    const policy = evaluate({ targets, states, operations: { 'settings.speed': { kind: 'set', value: 500 } } })
    const candidate = policy.fields['settings.speed']!.candidate!
    expect(candidate.outcome).toBe('blocked')
    expect(candidate.verdicts[0]?.reasonCode).toBe('speed-unsupported')
  })

  it('keeps optical media UNKNOWN instead of unsupported', () => {
    const key = 'assignment-1:interface-1:standalone'
    const targets = [portTarget(key, port('interface-1', { mode: 'access' }))]
    const states = {
      [key]: state([
        decision('speed', 'unknown', { groups: [sfp], reasonCode: 'optic-unknown' }),
        decision('duplex', 'unknown', { groups: [sfp], reasonCode: 'optic-unknown' }),
        decision('poe', 'unsupported'),
      ]),
    }
    const policy = evaluate({ targets, states })
    const speed = policy.fields['settings.speed']!
    expect(speed.candidates.find((candidate) => candidate.value === 1000)!.outcome).toBe('warning')
    expect(speed.candidates.find((candidate) => candidate.value === 2500)!.outcome).toBe('blocked')
    expect(speed.candidates.find((candidate) => candidate.value === 10)!.outcome).toBe('warning')
    const duplex = policy.fields['settings.duplex']!
    expect(duplex.candidates.every((candidate) => candidate.outcome !== 'blocked')).toBe(true)
    expect(policy.fields['settings.poe_mode']!.candidates
      .find((candidate) => candidate.value === 'static')!.outcome).toBe('blocked')
  })

  it('links duplex candidates to the proposed speed and documented copper media', () => {
    const key = 'assignment-1:interface-1:standalone'
    const states = {
      [key]: state([decision('duplex', 'supported', {
        groups: [copper(false)], reasonCode: 'duplex-documented',
      })]),
    }
    const halfAtGigabit = evaluate({
      targets: [portTarget(key, port('interface-1', { mode: 'access', speed: 1000 }))],
      states: {
        [key]: state([decision('duplex', 'unsupported', {
          groups: [copper(false)], reasonCode: 'duplex-unsupported',
        })]),
      },
      operations: { 'settings.duplex': { kind: 'set', value: 'half' } },
    })
    expect(halfAtGigabit.fields['settings.duplex']!.candidate?.outcome).toBe('blocked')
    expect(halfAtGigabit.fields['settings.duplex']!.candidate?.verdicts[0]?.reasonCode)
      .toBe('duplex-unsupported')

    const halfAtFastEthernet = evaluate({
      targets: [portTarget(key, port('interface-1', { mode: 'access', speed: 100 }))],
      states,
    })
    expect(halfAtFastEthernet.fields['settings.duplex']!.candidates
      .find((candidate) => candidate.value === 'half')!.outcome).toBe('allowed')

    const halfWithAutoSpeed = evaluate({
      targets: [portTarget(key, port('interface-1', { mode: 'access', speed: 'auto' }))],
      states,
    })
    expect(halfWithAutoSpeed.fields['settings.duplex']!.candidates
      .find((candidate) => candidate.value === 'half')!.outcome).toBe('warning')
  })

  it('blocks explicitly unsupported modes and features but leaves disabling safe', () => {
    const key = 'assignment-1:interface-1:standalone'
    const targets = [portTarget(key, port('interface-1', { mode: 'access' }))]
    const states = {
      [key]: state([
        decision('access', 'unsupported', { reasonCode: 'feature-license-unverified' }),
        decision('trunk', 'supported'),
        decision('routed-port', 'unknown'),
        decision('portfast', 'unsupported'),
        decision('bpdu-guard', 'unknown'),
      ]),
    }
    const policy = evaluate({ targets, states })
    expect(policy.fields['settings.mode']!.candidates.find((candidate) => candidate.value === 'access')!.outcome)
      .toBe('blocked')
    expect(policy.fields['settings.mode']!.candidates.find((candidate) => candidate.value === 'trunk')!.outcome)
      .toBe('allowed')
    expect(policy.fields['settings.mode']!.candidates.find((candidate) => candidate.value === 'routed')!.outcome)
      .toBe('warning')
    expect(policy.fields['settings.portfast']!.candidates.find((candidate) => candidate.value === 'edge')!.outcome)
      .toBe('blocked')
    expect(policy.fields['settings.portfast']!.candidates.find((candidate) => candidate.value === 'disabled')!.outcome)
      .toBe('allowed')
    expect(policy.fields['settings.bpdu_guard']!.candidates.find((candidate) => candidate.value === 'disabled')!.outcome)
      .toBe('allowed')
    expect(policy.fields['settings.bpdu_guard']!.candidates.find((candidate) => candidate.value === 'enabled')!.outcome)
      .toBe('warning')
  })

  it('combines Port-Channel and LACP required capabilities for negotiation modes', () => {
    const key = 'assignment-1:interface-1:standalone'
    const channel: RecordValue = {
      interface_id: 'logical-1', number: 1, member_ids: ['interface-1'], lacp: 'static',
      settings: { mode: 'trunk', native_vlan: 10, allowed_vlans: [10] },
    }
    const targets = [portTarget(key, port('interface-1', { mode: 'trunk' }), { channel })]
    const negotiation = (portChannel: CapabilityVerdict, lacp: CapabilityVerdict) => {
      const policy = evaluate({
        targets,
        states: {
          [key]: state([
            decision('port-channel', portChannel),
            decision('lacp', lacp),
          ]),
        },
        fields: channelFields,
        aggregate: true,
      })
      const field = policy.fields.lacp!
      return (value: string) => field.candidates.find((candidate) => candidate.value === value)!.outcome
    }

    const bothSupported = negotiation('supported', 'supported')
    expect(bothSupported('active')).toBe('allowed')
    expect(bothSupported('passive')).toBe('allowed')
    expect(bothSupported('static')).toBe('allowed')

    const unsupportedLacp = negotiation('supported', 'unsupported')
    expect(unsupportedLacp('static')).toBe('allowed')
    expect(unsupportedLacp('active')).toBe('blocked')
    expect(unsupportedLacp('passive')).toBe('blocked')

    // Active/passive also require Port-Channel aggregation, not only LACP.
    const unsupportedChannel = negotiation('unsupported', 'supported')
    expect(unsupportedChannel('static')).toBe('blocked')
    expect(unsupportedChannel('active')).toBe('blocked')
    expect(unsupportedChannel('passive')).toBe('blocked')

    const unknownChannel = negotiation('unknown', 'supported')
    expect(unknownChannel('static')).toBe('warning')
    expect(unknownChannel('active')).toBe('warning')
  })

  it('judges only added members and records a membership row', () => {
    const policy = channelPolicy({
      original: ['interface-1', 'interface-2'],
      proposed: ['interface-1', 'interface-2', 'interface-3'],
    })
    const membership = policy.membership!
    expect(membership.added).toEqual(['interface-3'])
    expect(membership.removed).toEqual([])
    expect(membership.kept).toEqual(['interface-1', 'interface-2'])
    expect(membership.outcome).toBe('allowed')
    expect(membership.rows).toHaveLength(1)
    expect(membership.rows[0]?.verdict.outcome).toBe('allowed')
    const row = policy.review.find((entry) => entry.fieldKey === 'member_ids')!
    expect(row.targetKey).toBe(membership.rows[0]!.targetKey)
    expect(row.candidateLabel).toBe('Gi1/0/3')
    expect(policy.hasBlocked).toBe(false)
  })

  it('warns for an UNKNOWN added member and never claims support', () => {
    const policy = channelPolicy({
      original: ['interface-1', 'interface-2'],
      proposed: ['interface-1', 'interface-2', 'interface-3'],
      verdicts: { 'interface-3': { pc: 'unknown' } },
    })
    const membership = policy.membership!
    expect(membership.outcome).toBe('warning')
    expect(membership.rows[0]?.verdict.reasonCode).toBe('release-unmatched')
    expect(policy.hasBlocked).toBe(false)
    expect(policy.hasWarning).toBe(true)
  })

  // CIS-01A currently cannot produce Port-Channel UNSUPPORTED through the real
  // API; this synthetic state covers the hard-block branch explicitly.
  it('synthetic UNSUPPORTED Port-Channel evidence hard-blocks an added member', () => {
    const policy = channelPolicy({
      original: ['interface-1', 'interface-2'],
      proposed: ['interface-1', 'interface-2', 'interface-3'],
      verdicts: { 'interface-3': { pc: 'unsupported' } },
    })
    const membership = policy.membership!
    expect(membership.outcome).toBe('blocked')
    expect(policy.hasBlocked).toBe(true)
    expect(membership.rows[0]?.verdict.reasonCode).toBe('feature-license-unverified')
    expect(policy.blocked.some((row) => row.fieldKey === 'member_ids')).toBe(true)
  })

  it('treats member removal as a repair even when the removed member is unsupported', () => {
    const policy = channelPolicy({
      original: ['interface-1', 'interface-2'],
      proposed: ['interface-1'],
      verdicts: { 'interface-2': { pc: 'unsupported' } },
    })
    const membership = policy.membership!
    expect(membership.removed).toEqual(['interface-2'])
    expect(membership.added).toEqual([])
    expect(membership.rows).toEqual([])
    expect(membership.outcome).toBe('allowed')
    expect(policy.hasBlocked).toBe(false)
    expect(policy.review.some((row) => row.fieldKey === 'member_ids')).toBe(false)
  })

  it('keeps an unchanged historical UNSUPPORTED member without blocking or clearing it', () => {
    const policy = channelPolicy({
      original: ['interface-1', 'interface-2'],
      proposed: ['interface-1', 'interface-2', 'interface-3'],
      verdicts: { 'interface-1': { pc: 'unsupported' }, 'interface-3': { pc: 'supported' } },
    })
    const membership = policy.membership!
    expect(membership.kept).toEqual(['interface-1', 'interface-2'])
    expect(membership.added).toEqual(['interface-3'])
    expect(membership.outcome).toBe('allowed')
    expect(policy.hasBlocked).toBe(false)
    expect(policy.blocked).toEqual([])
  })

  it('replacement judges the new member, not the removed member evidence', () => {
    const repaired = channelPolicy({
      original: ['interface-1', 'interface-2'],
      proposed: ['interface-1', 'interface-3'],
      verdicts: { 'interface-2': { pc: 'unsupported' }, 'interface-3': { pc: 'supported' } },
    })
    expect(repaired.membership!.removed).toEqual(['interface-2'])
    expect(repaired.membership!.added).toEqual(['interface-3'])
    expect(repaired.membership!.outcome).toBe('allowed')

    // Synthetic negative: the replacement target's own UNSUPPORTED evidence blocks.
    const blocked = channelPolicy({
      original: ['interface-1', 'interface-2'],
      proposed: ['interface-1', 'interface-3'],
      verdicts: { 'interface-2': { pc: 'supported' }, 'interface-3': { pc: 'unsupported' } },
    })
    expect(blocked.membership!.outcome).toBe('blocked')
    expect(blocked.membership!.rows[0]?.targetKey).toContain('interface-3')
  })

  it('allows a pure member order change without capability evidence', () => {
    const policy = channelPolicy({
      original: ['interface-1', 'interface-2'],
      proposed: ['interface-2', 'interface-1'],
      verdicts: { 'interface-1': { pc: 'unsupported' }, 'interface-2': { pc: 'unsupported' } },
    })
    const membership = policy.membership!
    expect(membership.added).toEqual([])
    expect(membership.removed).toEqual([])
    expect(membership.reordered).toBe(true)
    expect(membership.outcome).toBe('allowed')
    expect(policy.hasBlocked).toBe(false)
  })

  it('judges mixed added members individually instead of reusing the first result', () => {
    const policy = channelPolicy({
      original: ['interface-1'],
      proposed: ['interface-1', 'interface-2', 'interface-3'],
      verdicts: { 'interface-2': { pc: 'supported' }, 'interface-3': { pc: 'unsupported' } },
    })
    const membership = policy.membership!
    expect(membership.rows).toHaveLength(2)
    expect(membership.rows.find((row) => row.interfaceId === 'interface-2')?.verdict.outcome)
      .toBe('allowed')
    expect(membership.rows.find((row) => row.interfaceId === 'interface-3')?.verdict.outcome)
      .toBe('blocked')
    expect(membership.outcome).toBe('blocked')
  })

  it('requires LACP evidence for added members only when the proposed mode negotiates', () => {
    const activeUnknownLacp = channelPolicy({
      original: ['interface-1'],
      proposed: ['interface-1', 'interface-3'],
      lacp: 'active',
      verdicts: { 'interface-3': { pc: 'supported', lacp: 'unknown' } },
    })
    expect(activeUnknownLacp.membership!.requiredLacp).toBe(true)
    expect(activeUnknownLacp.membership!.outcome).toBe('warning')

    const activeUnsupportedLacp = channelPolicy({
      original: ['interface-1'],
      proposed: ['interface-1', 'interface-3'],
      lacp: 'passive',
      verdicts: { 'interface-3': { pc: 'supported', lacp: 'unsupported' } },
    })
    expect(activeUnsupportedLacp.membership!.outcome).toBe('blocked')

    const staticWithUnsupportedLacp = channelPolicy({
      original: ['interface-1'],
      proposed: ['interface-1', 'interface-3'],
      lacp: 'static',
      verdicts: { 'interface-3': { pc: 'supported', lacp: 'unsupported' } },
    })
    expect(staticWithUnsupportedLacp.membership!.requiredLacp).toBe(false)
    expect(staticWithUnsupportedLacp.membership!.outcome).toBe('allowed')
  })

  it('does not reuse a stale member verdict', () => {
    const policy = channelPolicy({
      original: ['interface-1'],
      proposed: ['interface-1', 'interface-3'],
      verdicts: { 'interface-3': { pc: 'unsupported', stale: true } },
    })
    const membership = policy.membership!
    expect(membership.outcome).toBe('pending')
    expect(policy.hasBlocked).toBe(false)
    expect(policy.hasPending).toBe(true)
  })

  it('keeps an unselected PoE candidate neutral instead of claiming an intent', () => {    const { targets, states } = poeState('unsupported')
    const policy = evaluate({
      targets, states,
      operations: { 'settings.poe_mode': { kind: 'set', value: null } },
    })
    const candidate = policy.fields['settings.poe_mode']!.candidate!
    expect(candidate.outcome).toBe('warning')
    expect(candidate.verdicts[0]?.reasonCode).toBe('candidate-unavailable')
  })

  it('treats reset by documented default behaviour and never hard-blocks repair', () => {
    const { targets, states } = poeState('unsupported')
    const policy = evaluate({ targets, states, operations: { 'settings.poe_mode': { kind: 'reset' } } })
    const field = policy.fields['settings.poe_mode']!
    expect(field.resetCandidate?.outcome).toBe('warning')
    expect(field.resetBlocked).toBe(false)
    expect(policy.hasBlocked).toBe(false)
  })

  it('does not reuse results that are loading, stale or unavailable', () => {
    const key = 'assignment-1:interface-1:standalone'
    const targets = [portTarget(key, port('interface-1', { mode: 'access' }))]
    for (const status of ['loading', 'stale', 'error'] as const) {
      const policy = evaluate({
        targets,
        states: { [key]: state([decision('poe', 'unsupported')], status) },
        operations: { 'settings.poe_mode': { kind: 'set', value: 'static' } },
      })
      const field = policy.fields['settings.poe_mode']!
      expect(field.candidate?.outcome).toBe('pending')
      expect(policy.hasBlocked).toBe(false)
      expect(field.setAllowed).toBe(true)
    }
  })

  it('judges a batch target by target and never reports the batch as supported', () => {
    const a = 'assignment-a:interface-a:standalone'
    const b = 'assignment-b:interface-b:standalone'
    const targets = [
      portTarget(a, port('interface-a', { mode: 'access' }), { device: 'PoE-A' }),
      portTarget(b, port('interface-b', { mode: 'access' }), { device: 'Copper-B' }),
    ]
    const policy = evaluate({
      targets,
      states: {
        [a]: state([decision('poe', 'supported')]),
        [b]: state([decision('poe', 'unsupported')]),
      },
      operations: { 'settings.poe_mode': { kind: 'set', value: 'static' } },
    })
    const candidate = policy.fields['settings.poe_mode']!.candidate!
    expect(candidate.outcome).toBe('blocked')
    expect(candidate.blockedKeys).toEqual([b])
    expect(candidate.allowedKeys).toEqual([a])
    expect(policy.hasBlocked).toBe(true)
    const matrix = policy.fields['settings.poe_mode']!.candidates
      .find((entry) => entry.value === 'static')!
    expect(matrix.warningKeys).toEqual([])
    expect(matrix.allowedKeys).toEqual([a])
  })

  it('reports preserved historical values without blocking other changes', () => {
    const key = 'assignment-1:interface-1:standalone'
    const targets = [portTarget(key, port('interface-1', {
      mode: 'access', poe_mode: 'static', description: 'Players',
    }))]
    const policy = evaluate({
      targets,
      states: { [key]: state([decision('poe', 'unsupported')]) },
      operations: { 'settings.description': { kind: 'set', value: 'Players 7' } },
    })
    expect(policy.fields['settings.poe_mode']!.preserved?.blockedKeys).toEqual([key])
    expect(policy.hasBlocked).toBe(false)
    expect(policy.fields['settings.description']!.candidate?.outcome).toBe('allowed')
  })

  it('exposes advisory capabilities without turning them into controls', () => {
    const { targets, states } = poeState('unsupported')
    const policy = evaluate({ targets, states })
    const related = new Map(policy.related.map((entry) => [entry.capability, entry]))
    expect(related.get('poe')).toBeUndefined()
    expect(related.get('port-media')?.targets[0]?.status).toBe('current')
    expect(related.get('stack')?.targets[0]?.verdict).toBeNull()
  })

  it('keeps every status consistent and never claims support for pending evidence', () => {
    const { targets, states } = poeState('unsupported')
    const policy = evaluate({ targets, states })
    for (const field of Object.values(policy.fields)) {
      for (const candidate of field.candidates) {
        for (const verdict of candidate.verdicts) {
          if (verdict.outcome !== 'pending') continue
          expect(verdict.status).not.toBe('current')
        }
      }
    }
    expect(policy.review).toEqual([])
  })
})
