import { afterEach, describe, expect, it, vi } from 'vitest'
import { translator } from '../messages'
import { records } from './model'
import type { Plan } from './model'
import {
  applyProposedChannel, applyProposedPorts, blockerLabel, capabilityKey, capabilityReason,
  capabilitiesForChange, previewCapability, settingLabel, summarizeCapabilities, verdictLabel,
  verdictTone,
} from './capability'
import type { CapabilityState, CapabilityTarget, DraftCapabilityPreview } from './capability'

const plan: Plan = {
  schema_version: 1,
  event_id: 'event-1',
  management_vlan: 10,
  physical_interfaces: [
    { id: 'port-1', assignment_id: 'a-1', physical_device_id: 'd-1', name: 'Gi1/0/1',
      settings: { mode: 'access', access_vlan: 10 } },
    { id: 'port-2', assignment_id: 'a-2', physical_device_id: 'd-2', name: 'Gi1/0/2',
      settings: { mode: 'access', access_vlan: 10 } },
  ],
}

const target = (id: string, assignment: string): CapabilityTarget => ({
  key: `${assignment}:${id}:standalone`,
  assignmentId: assignment,
  interfaceId: id,
  device: assignment,
  member: 'standalone',
  name: 'Gi1/0/1',
  item: { id, assignment_id: assignment, physical_device_id: 'd-1', settings: { mode: 'access' } },
})

const preview = (verdicts: ('supported' | 'unsupported' | 'unknown')[]): DraftCapabilityPreview => ({
  source: 'unsaved-draft',
  draft_fingerprint: 'a'.repeat(64),
  input_fingerprint: 'b'.repeat(64),
  decisions: verdicts.map((verdict, index) => ({
    capability_id: index === 0 ? 'poe' : 'speed',
    verdict,
    reason_code: verdict === 'supported' ? 'poe-documented' : 'speed-required',
    reason: 'Vendor evidence.',
    evidence: [],
    affected: {
      event_id: 'event-1', assignment_id: 'a-1', physical_device_id: 'd-1',
      interface_id: 'port-1', interface_name: 'Gi1/0/1', stack_member: null,
      sku: 'C9300L-24P-4X', software: '17.12.4', license: 'Network Advantage',
    },
    port_groups: [],
    verification: 'not-verified',
    deployment_status: 'blocked',
    blocks_deployment: true,
    deployment_blockers: ['deployment-generation-disabled', 'hardware-not-verified'],
  })),
})

afterEach(() => { vi.unstubAllGlobals() })

describe('draft capability helpers', () => {
  it('replaces proposed ports without mutating the draft', () => {
    const next = { ...records(plan, 'physical_interfaces')[0]!, name: 'Te1/1/4' }
    const applied = applyProposedPorts(plan, [{ index: 0, next }])
    expect(records(applied, 'physical_interfaces')[0]).toMatchObject({ name: 'Te1/1/4' })
    expect(records(plan, 'physical_interfaces')[0]).toMatchObject({ name: 'Gi1/0/1' })
  })

  it('appends a newly created port', () => {
    const applied = applyProposedPorts(plan, [{
      index: 2,
      next: { id: 'port-3', assignment_id: 'a-1', physical_device_id: 'd-1', name: 'Gi1/0/3',
        settings: { mode: 'access', access_vlan: 10 } },
    }])
    expect(applied.physical_interfaces).toHaveLength(3)
  })

  it('applies a proposed Port-Channel record without mutating the draft', () => {
    const aggregate = { ...plan, port_channels: [{ interface_id: 'channel-1', number: 1,
      member_ids: ['port-1'], settings: { mode: 'trunk', allowed_vlans: [10] }, lacp: 'active' }] }
    const proposed = { ...records(aggregate, 'port_channels')[0]!, lacp: 'passive' }
    const applied = applyProposedChannel(aggregate, proposed)
    expect(records(applied, 'port_channels')[0]).toMatchObject({ lacp: 'passive' })
    expect(records(aggregate, 'port_channels')[0]).toMatchObject({ lacp: 'active' })
  })

  it('changes only when the plan, target or capability query changes', () => {
    const first = target('port-1', 'a-1')
    const key = capabilityKey(plan, [first], ['poe'])
    expect(capabilityKey(plan, [first], ['poe'])).toBe(key)
    expect(capabilityKey({ ...plan, management_vlan: 20 }, [first], ['poe'])).not.toBe(key)
    expect(capabilityKey(plan, [{ ...first, stackMember: 2 }], ['poe'])).not.toBe(key)
    expect(capabilityKey(plan, [first], ['poe', 'speed'])).not.toBe(key)
  })

  it('counts per-target states without collapsing mixed results', () => {
    const states: Record<string, CapabilityState> = {
      one: { status: 'current', requestKey: 'k', preview: preview(['supported', 'unknown']) },
      two: { status: 'stale', requestKey: 'k', preview: preview(['unsupported']) },
      three: { status: 'error', requestKey: 'k' },
    }
    expect(summarizeCapabilities(states)).toEqual({
      supported: 1, unsupported: 0, unknown: 1, pending: 0, stale: 1, error: 1,
    })
  })

  it('maps changed fields to the capabilities that must be rechecked', () => {
    expect(capabilitiesForChange('settings.speed')).toEqual(['speed', 'port-media'])
    expect(capabilitiesForChange('settings.mode')).toEqual(['access', 'trunk', 'routed-port'])
    expect(capabilitiesForChange('lacp')).toEqual(['lacp', 'port-channel'])
    expect(capabilitiesForChange('unknown')).toEqual([])
  })

  it('localizes reasons, settings and verdicts', () => {
    const zh = translator('zh-CN')
    expect(capabilityReason(zh, 'software-is-rommon', 'fallback')).toContain('ROMMON')
    expect(capabilityReason(zh, 'future-code', 'fallback')).toBe('fallback')
    expect(blockerLabel(zh, 'poe-unsupported')).toBe(capabilityReason(zh, 'poe-unsupported', ''))
    expect(blockerLabel(zh, 'future-blocker')).toBe('future-blocker')
    expect(settingLabel(zh, 'speed', { settings: { speed: 1000 } })).toBe('速率 1000')
    expect(settingLabel(zh, 'access', { settings: { mode: 'access' } })).toBe('模式 接入')
    expect(verdictLabel(zh, 'unsupported')).toBe('不支持')
    expect(verdictTone('unsupported')).toBe('danger')
  })

  it('posts the exact draft and query to the preview endpoint', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json(preview(['supported'])))
    vi.stubGlobal('fetch', fetch)
    const result = await previewCapability({
      plan, assignment_id: 'a-1', capabilities: ['poe'], interface_id: 'port-1', stack_member: 2,
    })
    expect(result.source).toBe('unsaved-draft')
    expect(fetch).toHaveBeenCalledWith('/api/v1/events/event-1/plan/capability-preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        plan, assignment_id: 'a-1', capabilities: ['poe'], interface_id: 'port-1', stack_member: 2,
      }),
      signal: undefined,
    })
  })
})
