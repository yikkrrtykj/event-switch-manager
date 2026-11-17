import { get } from './catalog'
import type { Field } from './catalog'
import { hasPortValue, portFieldApplies } from './portSettings'
import type { Operations } from './portSettings'
import type {
  CapabilityDecision, CapabilityEvidence, CapabilityId, CapabilityState, CapabilityTarget,
  PortGroup,
} from './capability'
import type { Plan, RecordValue, Value } from './model'

/**
 * Maps CIS-01A capability evidence to concrete Port Editor candidates.
 *
 * The browser does not hold a vendor rule set: it only consumes the verdicts,
 * reason codes and documented port groups returned by the draft-aware
 * capability preview for the current plan, target and candidate.
 *
 * Only an applicable UNSUPPORTED verdict from a *current* preview can hard-block
 * a candidate. UNKNOWN, NOT VERIFIED, loading, stale and error results are
 * warning-only, so planning intent stays editable while every result keeps the
 * deployment block.
 */
export type ControlOutcome = 'allowed' | 'warning' | 'pending' | 'blocked'
export type EvidenceStatus = 'current' | 'loading' | 'idle' | 'stale' | 'error'
export type FieldOperation = 'keep' | 'set' | 'reset'

export type ControlVerdict = {
  targetKey: string
  outcome: ControlOutcome
  capability: CapabilityId | null
  reasonCode: string | null
  reason: string | null
  evidence: CapabilityEvidence[]
  status: EvidenceStatus
}

export type CandidateControl = {
  key: string
  value: Value | undefined
  reset: boolean
  verdicts: ControlVerdict[]
  outcome: ControlOutcome
  blockedKeys: string[]
  warningKeys: string[]
  pendingKeys: string[]
  allowedKeys: string[]
}

export type FieldControl = {
  field: Field
  operation: FieldOperation
  candidates: CandidateControl[]
  candidate?: CandidateControl
  resetCandidate?: CandidateControl
  verdicts: ControlVerdict[]
  outcome: ControlOutcome
  setAllowed: boolean
  resetBlocked: boolean
  preserved?: CandidateControl
}

export type ControlReviewRow = {
  targetKey: string
  fieldKey: string
  operation: 'set' | 'reset'
  value: Value | undefined
  verdict: ControlVerdict
}

export type RelatedCapability = {
  capability: CapabilityId
  targets: {
    targetKey: string
    status: EvidenceStatus
    verdict: CapabilityDecision['verdict'] | null
  }[]
}

export type PortControlPolicy = {
  fields: Record<string, FieldControl>
  review: ControlReviewRow[]
  blocked: ControlReviewRow[]
  warnings: ControlReviewRow[]
  pending: ControlReviewRow[]
  preserved: { fieldKey: string; value: Value | undefined; verdicts: ControlVerdict[] }[]
  related: RelatedCapability[]
  hasBlocked: boolean
  hasWarning: boolean
  hasPending: boolean
}

export type ControlPolicyInput = {
  plan: Plan
  targets: CapabilityTarget[]
  states: Record<string, CapabilityState>
  operations: Operations
  fields: Field[]
  aggregate?: boolean
}

type TargetEvidence = {
  key: string
  status: EvidenceStatus
  current: boolean
  record: RecordValue
  decisions: Map<CapabilityId, CapabilityDecision>
}

const COPPER = 'copper-rj45'
const MODE_CAPABILITIES: Readonly<Record<string, CapabilityId>> = {
  access: 'access',
  trunk: 'trunk',
  routed: 'routed-port',
}

/** Capabilities that inform the operator but have no direct Port Editor control. */
export const RELATED_CAPABILITIES: readonly CapabilityId[] = [
  'port-media', 'stack', 'svi', 'ipv4-routing', 'dhcp-relay',
]

const outcomeRank: Readonly<Record<ControlOutcome, number>> = {
  allowed: 0, pending: 1, warning: 2, blocked: 3,
}

function worst(outcomes: ControlOutcome[]): ControlOutcome {
  return outcomes.reduce<ControlOutcome>(
    (result, outcome) => outcomeRank[outcome] > outcomeRank[result] ? outcome : result,
    'allowed',
  )
}

function stateStatus(state?: CapabilityState): EvidenceStatus {
  if (!state) return 'idle'
  if (state.status === 'current') return 'current'
  if (state.status === 'loading') return 'loading'
  if (state.status === 'stale') return 'stale'
  if (state.status === 'error') return 'error'
  return 'idle'
}

function evidenceFor(input: ControlPolicyInput): TargetEvidence[] {
  const records = input.aggregate
    ? input.targets.map((target) => target.channel ?? {})
    : input.targets.map((target) => target.item)
  return input.targets.map((target, index) => {
    const state = input.states[target.key]
    const status = stateStatus(state)
    const current = status === 'current'
    return {
      key: target.key,
      status,
      current,
      record: records[index] ?? {},
      decisions: current && state?.preview
        ? new Map(state.preview.decisions.map((decision) => [decision.capability_id, decision]))
        : new Map(),
    }
  })
}

function verdict(
  target: TargetEvidence, outcome: ControlOutcome, capability: CapabilityId | null,
  reasonCode: string | null, reason: string | null = null,
  evidence: CapabilityEvidence[] = [], status: EvidenceStatus = 'current',
): ControlVerdict {
  return {
    targetKey: target.key, outcome, capability, reasonCode, reason, evidence,
    status: outcome === 'pending' ? status : 'current',
  }
}

function pending(target: TargetEvidence, capability: CapabilityId | null): ControlVerdict {
  return verdict(target, 'pending', capability, 'control-evidence-pending',
    null, [], target.status === 'current' ? 'loading' : target.status)
}

function missing(target: TargetEvidence, capability: CapabilityId | null): ControlVerdict {
  return verdict(target, 'warning', capability, 'control-evidence-missing')
}

/** Feature evidence: SUPPORTED allows, UNSUPPORTED hard-blocks, UNKNOWN warns. */
function decisionVerdict(target: TargetEvidence, capability: CapabilityId): ControlVerdict {
  if (!target.current) return pending(target, capability)
  const decision = target.decisions.get(capability)
  if (!decision) return missing(target, capability)
  const outcome: ControlOutcome = decision.verdict === 'supported' ? 'allowed'
    : decision.verdict === 'unsupported' ? 'blocked' : 'warning'
  return verdict(target, outcome, capability, decision.reason_code, decision.reason,
    decision.evidence)
}

function documentedMax(group: PortGroup) {
  return Math.max(...group.rates)
}

function speedFor(target: TargetEvidence) {
  return get(target.record, 'settings.speed')
}

function speedCandidate(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  if (!target.current) return pending(target, 'speed')
  const decision = target.decisions.get('speed')
  if (!decision) return missing(target, 'speed')
  const group = decision.port_groups[0]
  const cite = (reasonCode: string, reason: string | null = null) =>
    verdict(target, 'allowed', 'speed', reasonCode, reason, decision.evidence)
  if (!group) {
    return verdict(target, 'warning', 'speed', decision.reason_code, decision.reason,
      decision.evidence)
  }
  if (value == null || value === '') {
    return verdict(target, 'warning', 'speed', 'speed-required', null, decision.evidence)
  }
  if (value === 'auto') {
    return group.medium === COPPER
      ? cite('speed-documented')
      : verdict(target, 'warning', 'speed', 'optic-unknown', null, decision.evidence)
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return verdict(target, 'warning', 'speed', 'speed-required', null, decision.evidence)
  }
  if (value > documentedMax(group)) {
    return verdict(target, 'blocked', 'speed', 'speed-outside-port-range', null,
      decision.evidence)
  }
  if (group.medium === COPPER) {
    return group.rates.includes(value)
      ? cite('speed-documented')
      : verdict(target, 'blocked', 'speed', 'speed-unsupported', null, decision.evidence)
  }
  // Optical ports need the installed transceiver before a rate can be claimed.
  return verdict(target, 'warning', 'speed', 'optic-unknown', null, decision.evidence)
}

function duplexCandidate(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  if (!target.current) return pending(target, 'duplex')
  const decision = target.decisions.get('duplex')
  if (!decision) return missing(target, 'duplex')
  const cite = (outcome: ControlOutcome, reasonCode: string) =>
    verdict(target, outcome, 'duplex', reasonCode, null, decision.evidence)
  const group = decision.port_groups[0]
  if (!group) {
    return verdict(target, 'warning', 'duplex', decision.reason_code, decision.reason,
      decision.evidence)
  }
  const speed = speedFor(target)
  if (typeof speed === 'number') {
    if (speed > documentedMax(group)) return cite('blocked', 'speed-outside-port-range')
    if (group.medium === COPPER && !group.rates.includes(speed)) {
      return cite('blocked', 'speed-unsupported')
    }
  }
  if (group.medium !== COPPER) return cite('warning', 'optic-unknown')
  if (value === 'auto' || value === 'full') return cite('allowed', 'duplex-documented')
  if (value === 'half') {
    if (speed === 1000) return cite('blocked', 'duplex-unsupported')
    if (speed === 10 || speed === 100) return cite('allowed', 'duplex-documented')
    return cite('warning', 'duplex-speed-required')
  }
  return cite('warning', 'duplex-required')
}

function poeCandidate(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  // Turning PoE off is an explicit, safe planning intent that needs no power budget.
  if (value === 'never') {
    return verdict(target, 'allowed', 'poe', 'poe-disabled', null, [], target.status)
  }
  if (value == null || value === '') {
    return verdict(target, 'warning', 'poe', 'candidate-unavailable', null,
      [], target.status)
  }
  if (!target.current) return pending(target, 'poe')
  const decision = target.decisions.get('poe')
  if (!decision) return missing(target, 'poe')
  if (decision.verdict === 'supported') {
    return verdict(target, 'allowed', 'poe', 'poe-documented', null, decision.evidence)
  }
  if (decision.verdict === 'unsupported') {
    // `static` always requires the port to supply power. `auto` only negotiates
    // when a powered device asks, so it stays a warning-only planning intent.
    return value === 'static'
      ? verdict(target, 'blocked', 'poe', 'poe-unsupported', null, decision.evidence)
      : verdict(target, 'warning', 'poe', 'poe-negotiation-unverified', null,
        decision.evidence)
  }
  return verdict(target, 'warning', 'poe', decision.reason_code, decision.reason,
    decision.evidence)
}

function modeCandidate(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  const capability = typeof value === 'string' ? MODE_CAPABILITIES[value] : undefined
  if (!capability) return warningCandidate(target, value)
  return decisionVerdict(target, capability)
}

function cannotJudge(target: TargetEvidence, value: Value | undefined, capability: CapabilityId | null) {
  return verdict(target, 'warning', capability, 'candidate-unavailable',
    value == null ? null : String(value))
}

function portfastCandidate(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  if (value === 'disabled') return disabledFeature(target, 'portfast')
  return decisionVerdict(target, 'portfast')
}

function bpduGuardCandidate(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  if (value === 'disabled') return disabledFeature(target, 'bpdu-guard')
  return decisionVerdict(target, 'bpdu-guard')
}

function disabledFeature(target: TargetEvidence, capability: CapabilityId): ControlVerdict {
  return verdict(target, 'allowed', capability, 'feature-disabled', null, [], target.status)
}

function lacpCandidate(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  // Static aggregation needs Port-Channel support, not LACP negotiation.
  if (value === 'static') return decisionVerdict(target, 'port-channel')
  if (value === 'active' || value === 'passive') return decisionVerdict(target, 'lacp')
  return warningCandidate(target, value)
}

/** Settings that have no hardware-capability candidate rule. */
function unrestricted(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  void value
  return verdict(target, 'allowed', null, 'control-not-restricted', null, [], target.status)
}

function warningCandidate(target: TargetEvidence, value: Value | undefined): ControlVerdict {
  return cannotJudge(target, value, null)
}

function addressCandidate(target: TargetEvidence, _value: Value | undefined): ControlVerdict {
  const part = [decisionVerdict(target, 'routed-port'), decisionVerdict(target, 'ipv4-routing')]
  const blocked = part.find((entry) => entry.outcome === 'blocked')
  if (blocked) return blocked
  const warning = part.find((entry) => entry.outcome === 'warning')
  if (warning) return warning
  const pending = part.find((entry) => entry.outcome === 'pending')
  if (pending) return pending
  return verdict(target, 'allowed', 'routed-port', 'feature-documented', null,
    part.flatMap((entry) => entry.evidence))
}

function candidateVerdict(
  target: TargetEvidence, field: Field, value: Value | undefined,
): ControlVerdict {
  switch (field.key) {
    case 'settings.speed': return speedCandidate(target, value)
    case 'settings.duplex': return duplexCandidate(target, value)
    case 'settings.poe_mode': return poeCandidate(target, value)
    case 'settings.mode': return modeCandidate(target, value)
    case 'settings.portfast': return portfastCandidate(target, value)
    case 'settings.bpdu_guard': return bpduGuardCandidate(target, value)
    case 'settings.address': return addressCandidate(target, value)
    case 'lacp': return lacpCandidate(target, value)
    case 'member_ids': return decisionVerdict(target, 'port-channel')
    default: return unrestricted(target, value)
  }
}

/** Reset is judged by the documented default behaviour, but never hard-blocks repair. */
function resetVerdict(target: TargetEvidence, field: Field): ControlVerdict {
  switch (field.key) {
    case 'settings.speed': return speedCandidate(target, 'auto')
    case 'settings.duplex': return duplexCandidate(target, 'auto')
    case 'settings.poe_mode': {
      if (!target.current) return pending(target, 'poe')
      const decision = target.decisions.get('poe')
      if (!decision) return missing(target, 'poe')
      if (decision.verdict === 'supported') {
        return verdict(target, 'allowed', 'poe', 'poe-documented', null, decision.evidence)
      }
      return verdict(target, 'warning', 'poe', 'poe-default-unverified', null, decision.evidence)
    }
    case 'settings.portfast': return disabledFeature(target, 'portfast')
    case 'settings.bpdu_guard': return disabledFeature(target, 'bpdu-guard')
    case 'lacp': return lacpCandidate(target, 'active')
    case 'member_ids': return verdict(target, 'allowed', 'port-channel',
      'control-not-restricted', null, [], target.status)
    default:
      return verdict(target, 'allowed', null, 'control-default', null, [], target.status)
  }
}

function choiceValues(field: Field, targets: TargetEvidence[]): Value[] {
  if (field.key === 'settings.portfast') {
    const modes = targets.map((target) => get(target.record, 'settings.mode'))
    const allowEdge = modes.length > 0 && modes.every((mode) => mode === 'access')
    const allowEdgeTrunk = modes.length > 0 && modes.every((mode) => mode === 'trunk')
    return ['edge', 'edge-trunk', 'disabled'].filter((value) =>
      value === 'disabled' || (value === 'edge' && allowEdge) ||
      (value === 'edge-trunk' && allowEdgeTrunk))
  }
  return (field.choices ?? []).slice()
}

function candidateKey(field: Field, value: Value | undefined, reset: boolean) {
  if (reset) return field.key + ':reset'
  if (typeof value === 'string') return field.key + ':' + value
  if (typeof value === 'number') return field.key + ':' + String(value)
  return field.key + ':' + JSON.stringify(value ?? null)
}

function makeCandidate(
  field: Field, value: Value | undefined, reset: boolean, targets: TargetEvidence[],
): CandidateControl {
  const verdicts = targets.map((target) => reset
    ? resetVerdict(target, field)
    : candidateVerdict(target, field, value))
  const outcomes = verdicts.map((entry) => entry.outcome)
  const pick = (outcome: ControlOutcome) =>
    verdicts.filter((entry) => entry.outcome === outcome).map((entry) => entry.targetKey)
  return {
    key: candidateKey(field, value, reset),
    value,
    reset,
    verdicts,
    outcome: worst(outcomes),
    blockedKeys: pick('blocked'),
    warningKeys: pick('warning'),
    pendingKeys: pick('pending'),
    allowedKeys: pick('allowed'),
  }
}

function keptCandidate(targets: TargetEvidence[], field: Field): CandidateControl | undefined {
  const relevant = targets.filter((target) =>
    portFieldApplies(field, get(target.record, 'settings.mode')))
  if (!relevant.length) return undefined
  const values = relevant.map((target) => get(target.record, field.key))
  if (!values.some(hasPortValue)) return undefined
  const verdicts = relevant.map((target) => candidateVerdict(target, field, get(target.record, field.key)))
  if (!verdicts.some((entry) => entry.outcome === 'blocked')) return undefined
  const outcomes = verdicts.map((entry) => entry.outcome)
  const pick = (outcome: ControlOutcome) =>
    verdicts.filter((entry) => entry.outcome === outcome).map((entry) => entry.targetKey)
  return {
    key: field.key + ':kept',
    value: values[0],
    reset: false,
    verdicts,
    outcome: worst(outcomes),
    blockedKeys: pick('blocked'),
    warningKeys: pick('warning'),
    pendingKeys: pick('pending'),
    allowedKeys: pick('allowed'),
  }
}

export function evaluateControlPolicy(input: ControlPolicyInput): PortControlPolicy {
  const targets = evidenceFor(input)
  const fields: Record<string, FieldControl> = {}
  const review: ControlReviewRow[] = []
  const preserved: PortControlPolicy['preserved'] = []
  let hasBlocked = false
  let hasWarning = false
  let hasPending = false

  for (const field of input.fields) {
    const operation = input.operations[field.key]
    const kind: FieldOperation = operation?.kind === 'set' ? 'set'
      : operation?.kind === 'reset' ? 'reset' : 'keep'
    const choices = choiceValues(field, targets)
    const candidates = choices.map((value) => makeCandidate(field, value, false, targets))
    const candidate = kind === 'set'
      ? makeCandidate(field, operation?.kind === 'set' ? operation.value : undefined, false, targets)
      : undefined
    // A reset removes an override; report its default evidence, but never make
    // resetting a historical value impossible.
    const resetCandidate = kind === 'reset' ? makeCandidate(field, undefined, true, targets) : undefined
    if (resetCandidate && resetCandidate.outcome === 'blocked') {
      resetCandidate.outcome = 'warning'
      for (const entry of resetCandidate.verdicts) {
        if (entry.outcome === 'blocked') entry.outcome = 'warning'
      }
      resetCandidate.warningKeys = [
        ...resetCandidate.warningKeys, ...resetCandidate.blockedKeys,
      ]
      resetCandidate.blockedKeys = []
    }
    const verdicts = candidate ? candidate.verdicts
      : resetCandidate ? resetCandidate.verdicts : []
    const outcome = kind === 'keep' ? 'allowed'
      : (candidate ?? resetCandidate)?.outcome ?? 'allowed'
    const preservedCandidate = kind === 'keep' ? keptCandidate(targets, field) : undefined
    fields[field.key] = {
      field,
      operation: kind,
      candidates,
      candidate,
      resetCandidate,
      verdicts,
      outcome,
      setAllowed: !candidates.length || candidates.some((entry) => entry.outcome !== 'blocked'),
      resetBlocked: Boolean(resetCandidate?.verdicts.some((entry) => entry.outcome === 'blocked')),
      preserved: preservedCandidate,
    }
    if (outcome === 'blocked') hasBlocked = true
    if (outcome === 'warning') hasWarning = true
    if (outcome === 'pending') hasPending = true
    if (preservedCandidate) {
      preserved.push({ fieldKey: field.key, value: preservedCandidate.value, verdicts: preservedCandidate.verdicts })
    }
    if ((kind === 'set' || kind === 'reset') && verdicts.length) {
      for (const entry of verdicts) {
        review.push({
          targetKey: entry.targetKey,
          fieldKey: field.key,
          operation: kind,
          value: kind === 'set' && operation?.kind === 'set' ? operation.value : undefined,
          verdict: entry,
        })
      }
    }
  }

  const related = RELATED_CAPABILITIES.map((capability) => ({
    capability,
    targets: targets.map((target) => {
      const decision = target.decisions.get(capability)
      return {
        targetKey: target.key,
        status: target.status,
        verdict: decision?.verdict ?? null,
      }
    }),
  }))

  return {
    fields,
    review,
    blocked: review.filter((row) => row.verdict.outcome === 'blocked'),
    warnings: review.filter((row) => row.verdict.outcome === 'warning'),
    pending: review.filter((row) => row.verdict.outcome === 'pending'),
    preserved,
    related,
    hasBlocked,
    hasWarning,
    hasPending,
  }
}
