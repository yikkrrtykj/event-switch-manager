import { Badge, Table } from '../components/ui'
import { useMessages } from '../locale'
import { enumLabel } from '../messages'
import type { Translator } from '../messages'
import { capabilityName, capabilityReason } from './capability'
import type { CapabilityTarget } from './capability'
import type {
  CandidateControl, ControlOutcome, ControlReviewRow, ControlVerdict, FieldControl,
  PortControlPolicy, RelatedCapability,
} from './portControlPolicy'

const outcomeKeys = {
  allowed: 'controlOutcomeAllowed',
  warning: 'controlOutcomeWarning',
  pending: 'controlOutcomePending',
  blocked: 'controlOutcomeBlocked',
} as const

const outcomeTones: Record<ControlOutcome, string> = {
  allowed: 'neutral', warning: 'warning', pending: 'warning', blocked: 'danger',
}

export function ControlOutcomeBadge({ outcome }: { outcome: ControlOutcome }) {
  const { t } = useMessages()
  return <Badge tone={outcomeTones[outcome]}>{t(outcomeKeys[outcome])}</Badge>
}

export function controlTargetLabel(target: CapabilityTarget) {
  return [target.device, target.member, target.name].filter(Boolean).join(' · ')
}

function targetLabels(targets: CapabilityTarget[], keys: string[]) {
  const labels = new Map(targets.map((target) => [target.key, controlTargetLabel(target)]))
  return keys.map((key) => labels.get(key) ?? key).join(' · ')
}

function uniqueReasons(t: Translator, verdicts: ControlVerdict[]) {
  const reasons: string[] = []
  for (const verdict of verdicts) {
    if (verdict.outcome === 'allowed') continue
    const text = verdict.reasonCode
      ? capabilityReason(t, verdict.reasonCode, verdict.reason ?? '')
      : verdict.reason ?? ''
    if (text && !reasons.includes(text)) reasons.push(text)
  }
  return reasons
}

function candidateLabel(t: Translator, field: FieldControl, candidate: CandidateControl) {
  if (candidate.reset) return t('controlPolicyResetCandidate')
  if (candidate.value == null || candidate.value === '') return t('controlPolicyCandidateRequired')
  if (Array.isArray(candidate.value)) return candidate.value.map(String).join(', ')
  if (field.field.key === 'settings.speed' && typeof candidate.value === 'number') {
    return t('controlPolicySpeedCandidate', { value: String(candidate.value) })
  }
  if (typeof candidate.value === 'string' || typeof candidate.value === 'number') {
    return enumLabel(t, candidate.value, field.field.key)
  }
  return JSON.stringify(candidate.value)
}

function CandidateLine({ field, candidate, targets }: {
  field: FieldControl; candidate: CandidateControl; targets: CapabilityTarget[]
}) {
  const { t } = useMessages()
  const reasons = uniqueReasons(t, candidate.verdicts)
  const rows: string[] = []
  if (candidate.blockedKeys.length) {
    rows.push(t('controlBlockedFor', { targets: targetLabels(targets, candidate.blockedKeys) }))
  }
  if (candidate.warningKeys.length) {
    rows.push(t('controlNotVerifiedFor', { targets: targetLabels(targets, candidate.warningKeys) }))
  }
  if (candidate.pendingKeys.length) {
    rows.push(t('controlNotCurrentFor', { targets: targetLabels(targets, candidate.pendingKeys) }))
  }
  if (candidate.allowedKeys.length && candidate.outcome !== 'allowed') {
    rows.push(t('controlDocumentedFor', { targets: targetLabels(targets, candidate.allowedKeys) }))
  }
  return <li className="port-control-candidate" data-control-candidate={candidate.key}
    data-control-outcome={candidate.outcome}>
    <div className="port-control-candidate-head">
      <strong>{candidateLabel(t, field, candidate)}</strong>
      <ControlOutcomeBadge outcome={candidate.outcome} />
    </div>
    <ul className="port-control-targets">
      {rows.map((row) => <li key={row}>{row}</li>)}
    </ul>
    {reasons.length > 0 && <p className="port-control-reason">{reasons.join(' · ')}</p>}
  </li>
}

export function ControlCandidateMatrix({ field, targets }: {
  field: FieldControl; targets: CapabilityTarget[]
}) {
  const { t } = useMessages()
  const visible = field.candidates.filter((candidate) => candidate.outcome !== 'allowed')
  if (!visible.length) return null
  const outcome = visible.some((candidate) => candidate.outcome === 'blocked') ? 'blocked'
    : visible.some((candidate) => candidate.outcome === 'warning') ? 'warning' : 'pending'
  return <div className="port-control-matrix" data-control-matrix={field.field.key}
    data-control-field={field.field.key} data-control-outcome={outcome}>
    <p className="port-control-matrix-title">{t('controlMatrixTitle')}</p>
    <p className="muted">{t('controlMatrixHint')}</p>
    <ul>{visible.map((candidate) => <CandidateLine key={candidate.key} field={field}
      candidate={candidate} targets={targets} />)}</ul>
  </div>
}

export function FieldControlNotice({ field, targets }: {
  field: FieldControl; targets: CapabilityTarget[]
}) {
  const { t } = useMessages()
  const current = field.candidate ?? field.resetCandidate
  const reasons = current ? uniqueReasons(t, current.verdicts) : []
  return <div className="port-control-notice" data-control-notice={field.field.key}>
    {current && current.outcome === 'blocked' && <p className="port-control-blocked" role="alert">
      {t('controlFieldBlocked', { targets: targetLabels(targets, current.blockedKeys) })}
      {reasons.length > 0 && <span className="port-control-reason"> {reasons.join(' · ')}</span>}
    </p>}
    {current && current.outcome === 'warning' && <p className="port-control-warning" role="status">
      {t('controlFieldWarning', { targets: targetLabels(targets, current.warningKeys) })}
      {reasons.length > 0 && <span className="port-control-reason"> {reasons.join(' · ')}</span>}
    </p>}
    {current && current.outcome === 'pending' && <p className="port-control-pending" role="status">
      {t('controlFieldPending', { targets: targetLabels(targets, current.pendingKeys) })}
    </p>}
    {field.preserved && <p className="port-control-preserved" role="status">
      {t('controlFieldPreserved', { targets: targetLabels(targets, field.preserved.blockedKeys) })}
    </p>}
    <ControlCandidateMatrix field={field} targets={targets} />
  </div>
}

function reviewRows(policy: PortControlPolicy, rows: ControlReviewRow[], targets: CapabilityTarget[]) {
  const { t } = useMessages()
  return rows.map((row, index) => {
    const target = targets.find((item) => item.key === row.targetKey)
    const field = policy.fields[row.fieldKey]?.field
    const reason = row.verdict.reasonCode
      ? capabilityReason(t, row.verdict.reasonCode, row.verdict.reason ?? '')
      : row.verdict.reason ?? ''
    return <tr key={index} data-control-outcome={row.verdict.outcome}
      data-control-field={row.fieldKey}>
      <td>{target ? controlTargetLabel(target) : row.targetKey}</td>
      <td>{field ? t(field.label) : row.fieldKey}</td>
      <td>{row.operation === 'reset' ? t('controlPolicyResetCandidate')
        : reviewValue(t, policy, row)}</td>
      <td><ControlOutcomeBadge outcome={row.verdict.outcome} /></td>
      <td>{reason}</td>
    </tr>
  })
}

function reviewValue(t: Translator, policy: PortControlPolicy, row: ControlReviewRow) {
  const field = policy.fields[row.fieldKey]
  const candidate = field?.candidate
  if (candidate) return candidateLabel(t, field!, candidate)
  return row.value == null ? '—' : String(row.value)
}

function Summary({ policy }: { policy: PortControlPolicy }) {
  const { t } = useMessages()
  return <div className="port-control-summary" role="status">
    <Badge tone={policy.blocked.length ? 'danger' : 'neutral'}>
      {t('controlPolicyBlockedCount', { count: policy.blocked.length })}
    </Badge>
    <Badge tone={policy.warnings.length ? 'warning' : 'neutral'}>
      {t('controlPolicyWarningCount', { count: policy.warnings.length })}
    </Badge>
    <Badge tone={policy.pending.length ? 'warning' : 'neutral'}>
      {t('controlPolicyPendingCount', { count: policy.pending.length })}
    </Badge>
  </div>
}

function Preserved({ policy, targets }: { policy: PortControlPolicy; targets: CapabilityTarget[] }) {
  const { t } = useMessages()
  if (!policy.preserved.length) return null
  return <ul className="port-control-preserved-list">
    {policy.preserved.map((entry) => {
      const field = policy.fields[entry.fieldKey]?.field
      const value = entry.value == null ? '—'
        : Array.isArray(entry.value) ? entry.value.map(String).join(', ')
          : typeof entry.value === 'string' || typeof entry.value === 'number'
            ? field ? enumLabel(t, entry.value, field.key) : String(entry.value)
            : JSON.stringify(entry.value)
      const blockKeys = entry.verdicts.filter((verdict) => verdict.outcome === 'blocked')
        .map((verdict) => verdict.targetKey)
      return <li key={entry.fieldKey}>{t('controlPolicyPreserved', {
        field: field ? t(field.label) : entry.fieldKey,
        value: String(value),
        targets: blockKeys.length ? targetLabels(targets, blockKeys) : '—',
      })}</li>
    })}
  </ul>
}

function Related({ related, targets }: {
  related: RelatedCapability[]; targets: CapabilityTarget[]
}) {
  const { t } = useMessages()
  const visible = related.filter((entry) =>
    entry.targets.some((target) => target.verdict !== null || target.status !== 'idle'))
  if (!visible.length) return null
  return <details className="port-control-related">
    <summary>{t('controlPolicyRelated')}</summary>
    <p className="muted">{t('controlPolicyRelatedNote')}</p>
    <dl>{visible.map((entry) => <div key={entry.capability}>
      <dt>{capabilityName(t, entry.capability)}</dt>
      <dd>{entry.targets.map((target) => {
        const label = targets.find((item) => item.key === target.targetKey)
        const status = target.verdict
          ? t(target.verdict === 'supported' ? 'capabilityVerdictSupported'
            : target.verdict === 'unsupported' ? 'capabilityVerdictUnsupported'
              : 'capabilityVerdictUnknown')
          : t('capabilityLoadingBadge')
        return <span key={target.targetKey} className="port-control-related-target"
          data-control-related={entry.capability}>
          {label ? controlTargetLabel(label) : target.targetKey}: {status}
        </span>
      })}</dd>
    </div>)}</dl>
  </details>
}

export function ControlPolicyPanel({ policy, targets }: {
  policy: PortControlPolicy; targets: CapabilityTarget[]
}) {
  const { t } = useMessages()
  return <section className="port-control-panel" aria-label={t('controlPolicyTitle')}
    data-control-policy="editor">
    <div className="capability-panel-head">
      <div><h3>{t('controlPolicyTitle')}</h3>
        <p className="muted">{t('controlPolicyScope')}</p></div>
      <Badge tone="warning">{t('capabilityNotVerified')}</Badge>
    </div>
    <Summary policy={policy} />
    {policy.hasBlocked && <p className="port-control-blocked" role="alert">
      {t('controlPolicyApplyBlocked')}
    </p>}
    {policy.hasWarning && <p className="port-control-warning" role="status">
      {t('controlPolicyWarningNote')}
    </p>}
    {policy.hasPending && <p className="port-control-pending" role="status">
      {t('controlPolicyPendingNote')}
    </p>}
    {policy.review.length
      ? <Table label={t('controlPolicyTable')}><thead><tr>
        <th scope="col">{t('controlPolicyTarget')}</th>
        <th scope="col">{t('controlPolicyField')}</th>
        <th scope="col">{t('controlPolicyCandidate')}</th>
        <th scope="col">{t('controlPolicyControl')}</th>
        <th scope="col">{t('controlPolicyReason')}</th>
      </tr></thead><tbody>{reviewRows(policy, policy.review, targets)}</tbody></Table>
      : <p className="muted">{t('controlPolicyEmpty')}</p>}
    <Preserved policy={policy} targets={targets} />
    <p className="port-control-note">{t('controlPolicyBlockedNote')}</p>
    <Related related={policy.related} targets={targets} />
  </section>
}

export function ControlReview({ policy, targets }: {
  policy: PortControlPolicy; targets: CapabilityTarget[]
}) {
  const { t } = useMessages()
  return <section className="port-control-review" aria-label={t('controlReviewTable')}>
    <div className="capability-panel-head">
      <div><h3>{t('controlPolicyTitle')}</h3>
        <p className="muted">{t('controlReviewNote')}</p></div>
      <Badge tone="warning">{t('capabilityNotVerified')}</Badge>
    </div>
    <Summary policy={policy} />
    {policy.hasBlocked && <p className="port-control-blocked" role="alert">
      {t('controlPolicyApplyBlocked')}
    </p>}
    {policy.hasWarning && <p className="port-control-warning" role="status">
      {t('controlPolicyWarningNote')}
    </p>}
    {policy.hasPending && <p className="port-control-pending" role="status">
      {t('controlPolicyPendingNote')}
    </p>}
    {policy.review.length
      ? <Table label={t('controlReviewTable')}><thead><tr>
        <th scope="col">{t('controlPolicyTarget')}</th>
        <th scope="col">{t('controlPolicyField')}</th>
        <th scope="col">{t('controlPolicyCandidate')}</th>
        <th scope="col">{t('controlPolicyControl')}</th>
        <th scope="col">{t('controlPolicyReason')}</th>
      </tr></thead><tbody>{reviewRows(policy, policy.review, targets)}</tbody></Table>
      : <p className="muted">{t('controlReviewEmpty')}</p>}
    <Preserved policy={policy} targets={targets} />
    <p className="port-control-note">{t('controlPolicyPreservedNote')}</p>
  </section>
}
