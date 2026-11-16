import { Badge, Table } from '../components/ui'
import { useMessages } from '../locale'
import {
  blockerLabel, capabilityGroups, capabilityName, capabilityReason, settingLabel,
  summarizeCapabilities, verdictLabel, verdictTone,
} from './capability'
import type {
  CapabilityDecision, CapabilityId, CapabilityState, CapabilityTarget,
} from './capability'

function StateBadge({ state }: { state?: CapabilityState }) {
  const { t } = useMessages()
  if (!state || state.status === 'idle' || state.status === 'loading') {
    return <Badge>{t('capabilityLoadingBadge')}</Badge>
  }
  if (state.status === 'stale') return <Badge tone="warning">{t('capabilityStale')}</Badge>
  if (state.status === 'error') return <Badge tone="warning">{t('capabilityVerdictUnknown')}</Badge>
  return <Badge tone="neutral">{t('capabilityDraftSource')}</Badge>
}

function Summary({ states, targetCount }: {
  states: Record<string, CapabilityState>; targetCount: number
}) {
  const { t } = useMessages()
  const summary = summarizeCapabilities(states)
  return <div className="capability-summary" role="status">
    <strong>{t('capabilitySummary')}</strong>
    <Badge tone="success">{t('capabilitySupportedCount', { count: summary.supported })}</Badge>
    <Badge tone={summary.unsupported ? 'danger' : 'neutral'}>
      {t('capabilityUnsupportedCount', { count: summary.unsupported })}
    </Badge>
    <Badge tone={summary.unknown ? 'warning' : 'neutral'}>
      {t('capabilityUnknownCount', { count: summary.unknown })}
    </Badge>
    {summary.stale > 0 && <Badge tone="warning">
      {t('capabilityStaleCount', { count: summary.stale })}
    </Badge>}
    {summary.error > 0 && <Badge tone="warning">
      {t('capabilityErrorCount', { count: summary.error })}
    </Badge>}
    <span className="muted">{t('capabilityTargetCount', { count: targetCount })}</span>
    <span className="muted">{t('capabilityDocumentedOnly')}</span>
  </div>
}

function Evidence({ decision }: { decision: CapabilityDecision }) {
  const { t } = useMessages()
  if (!decision.evidence.length) return <p className="muted">{t('capabilityNoEvidence')}</p>
  return <details className="capability-evidence">
    <summary>{t('capabilityEvidenceCount', { count: decision.evidence.length })}</summary>
    <ul>{decision.evidence.map((row, index) => <li key={index}>
      <a href={row.url} target="_blank" rel="noreferrer"
        aria-label={t('capabilityOpenEvidenceFor', {
          capability: capabilityName(t, decision.capability_id), section: row.section,
        })}>{row.section}</a>
      <span className="muted"> · {row.version_scope ?? t('capabilityNoReleaseScope')}</span>
      {row.licenses.length > 0 && <span className="capability-chip">{row.licenses.join(', ')}</span>}
      <div className="muted">{row.conditions}</div>
    </li>)}</ul>
  </details>
}

function Scope({ decisions }: { decisions: CapabilityDecision[] }) {
  const { t } = useMessages()
  const releases = [...new Set(decisions.flatMap((decision) =>
    decision.evidence.flatMap((row) => row.version_scope ? [row.version_scope] : [])))]
  const licenses = [...new Set(decisions.flatMap((decision) =>
    decision.evidence.flatMap((row) => row.licenses)))]
  if (!releases.length && !licenses.length) {
    return <p className="muted capability-scope">{t('capabilityNoScopeLimits')}</p>
  }
  return <p className="capability-scope">
    <span>{t('capabilityReleaseScope')}: {releases.join(', ') || t('capabilityNoReleaseScope')}</span>
    <span>{t('capabilityLicenseScope')}: {licenses.join(', ') || t('capabilityNoLicenseScope')}</span>
  </p>
}

function Blockers({ decisions }: { decisions: CapabilityDecision[] }) {
  const { t } = useMessages()
  const blockers = [...new Set(decisions.flatMap((decision) => decision.deployment_blockers))]
  return <div className="capability-blockers">
    <Badge tone="danger">{t('capabilityDeploymentBlocked')}</Badge>
    <span className="muted">{t('capabilityBlockedReasons', {
      reasons: blockers.map((code) => blockerLabel(t, code)).join(' · '),
    })}</span>
  </div>
}

function Groups({ decisions, stale }: { decisions: CapabilityDecision[]; stale: boolean }) {
  const { t } = useMessages()
  const byId = new Map(decisions.map((decision) => [decision.capability_id, decision]))
  return <div className="capability-groups">
    {capabilityGroups.map((group) => {
      const rows = group.ids.flatMap((id) => byId.get(id) ? [byId.get(id)!] : [])
      if (!rows.length) return null
      return <section className="capability-group" key={group.key}>
        <h5>{t(group.label)}</h5>
        <dl className="capability-list">{rows.map((decision) => <div className="capability-item"
          key={decision.capability_id} data-verdict={decision.verdict}>
          <dt>{capabilityName(t, decision.capability_id)}</dt>
          <dd>
            <p className="capability-verdict">
              <Badge tone={stale ? 'warning' : verdictTone(decision.verdict)}>
                {stale ? t('capabilityStale') : verdictLabel(t, decision.verdict)}
              </Badge>
            </p>
            <p className="capability-reason">
              {capabilityReason(t, decision.reason_code, decision.reason)}
            </p>
            <Evidence decision={decision} />
          </dd>
        </div>)}</dl>
      </section>
    })}
  </div>
}

function TargetPanel({ target, state }: { target: CapabilityTarget; state?: CapabilityState }) {
  const { t } = useMessages()
  const stale = state?.status === 'stale'
  const preview = state?.preview
  return <section className="capability-target" data-capability-status={state?.status ?? 'idle'}
    aria-busy={state?.status === 'loading' || stale}>
    <div className="capability-target-head">
      <h4>{target.device} <span aria-hidden="true">·</span> {target.member}
        {' · '}<span className="data-mono">{target.name}</span></h4>
      <div className="capability-target-meta">
        {preview && <code title={t('capabilityFingerprint')}>{preview.draft_fingerprint.slice(0, 12)}</code>}
        <StateBadge state={state} />
      </div>
    </div>
    {stale && <p className="capability-stale-note" role="status">{t('capabilityStaleRechecking')}</p>}
    {state?.status === 'error' && <div className="capability-error" role="alert">
      <p>{t('capabilityUnavailable')}</p>
      <Badge tone="warning">{t('capabilityVerdictUnknown')}</Badge>
    </div>}
    {(!state || state.status === 'idle' || state.status === 'loading') && !preview &&
      <p className="muted" role="status">{t('capabilityLoading')}</p>}
    {preview && <>
      <Groups decisions={preview.decisions} stale={stale} />
      <Scope decisions={preview.decisions} />
      <Blockers decisions={preview.decisions} />
    </>}
  </section>
}

export function CapabilityPanel({ states, targets }: {
  states: Record<string, CapabilityState>; targets: CapabilityTarget[]
}) {
  const { t } = useMessages()
  return <section className="capability-panel" aria-label={t('capabilityTitle')}>
    <div className="capability-panel-head">
      <div>
        <h3>{t('capabilityTitle')}</h3>
        <p className="muted">{t('capabilityScopeNote')}</p>
      </div>
      <Badge tone="warning">{t('capabilityNotVerified')}</Badge>
    </div>
    <Summary states={states} targetCount={targets.length} />
    {!targets.length && <p className="muted">{t('capabilityNoTarget')}</p>}
    {targets.map((target) => <TargetPanel key={target.key} target={target}
      state={states[target.key]} />)}
  </section>
}

function ReviewRow({ target, decision, state, stale }: {
  target: CapabilityTarget; decision?: CapabilityDecision
  state?: CapabilityState; stale: boolean
}) {
  const { t } = useMessages()
  if (!decision) {
    return <tr>
      <td>{target.device}</td><td className="data-mono">{target.name}</td><td>{target.member}</td>
      <td>{t('capabilityNotAvailable')}</td>
      <td><Badge tone="warning">{t('capabilityVerdictUnknown')}</Badge></td>
      <td>{state?.status === 'error' ? t('capabilityUnavailable') : t('capabilityLoading')}</td>
      <td>{t('capabilityNoEvidence')}</td>
      <td><Badge tone="warning">{t('capabilityNotVerified')}</Badge></td>
    </tr>
  }
  const evidence = decision.evidence[0]
  return <tr data-capability-verdict={decision.verdict}>
    <td>{target.device}</td><td className="data-mono">{target.name}</td><td>{target.member}</td>
    <td>{settingLabel(t, decision.capability_id, target.item, target.channel)}</td>
    <td><Badge tone={stale ? 'warning' : verdictTone(decision.verdict)}>
      {stale ? t('capabilityStale') : verdictLabel(t, decision.verdict)}
    </Badge></td>
    <td>{capabilityReason(t, decision.reason_code, decision.reason)}</td>
    <td>{evidence ? <a href={evidence.url} target="_blank" rel="noreferrer">
      {evidence.section}{decision.evidence.length > 1 ? ' +' + (decision.evidence.length - 1) : ''}
    </a> : t('capabilityNoEvidence')}</td>
    <td><Badge tone="warning">{t('capabilityNotVerified')}</Badge></td>
  </tr>
}

export function CapabilityReview({ states, targets, changed }: {
  states: Record<string, CapabilityState>; targets: CapabilityTarget[]
  changed: Record<string, readonly CapabilityId[]>
}) {
  const { t } = useMessages()
  const rows: { target: CapabilityTarget; decision?: CapabilityDecision; state?: CapabilityState;
    stale: boolean }[] = []
  for (const target of targets) {
    const state = states[target.key]
    const stale = state?.status === 'stale'
    const preview = state?.preview
    if (!preview) {
      rows.push({ target, state, stale })
      continue
    }
    const relevant = changed[target.key] ?? []
    const filtered = relevant.length
      ? preview.decisions.filter((decision) => relevant.includes(decision.capability_id))
      : preview.decisions
    const decisions = filtered.length ? filtered : preview.decisions
    for (const decision of decisions) rows.push({ target, decision, state, stale })
  }
  return <section className="capability-review" aria-label={t('capabilityReviewTitle')}>
    <div className="capability-panel-head">
      <div><h3>{t('capabilityReviewTitle')}</h3>
        <p className="muted">{t('capabilityDocumentedOnly')}</p></div>
      <Badge tone="warning">{t('capabilityNotVerified')}</Badge>
    </div>
    <Summary states={states} targetCount={targets.length} />
    {rows.length ? <Table label={t('capabilityReviewTable')}><thead><tr>
      <th scope="col">{t('device')}</th><th scope="col">{t('interface')}</th>
      <th scope="col">{t('stackMember')}</th><th scope="col">{t('capabilityIntendedSetting')}</th>
      <th scope="col">{t('capabilityVerdict')}</th><th scope="col">{t('capabilityReason')}</th>
      <th scope="col">{t('capabilityEvidence')}</th><th scope="col">{t('capabilityVerification')}</th>
    </tr></thead><tbody>{rows.map((row, index) => <ReviewRow key={index} {...row} />)}</tbody></Table>
      : <p className="muted">{t('capabilityReviewEmpty')}</p>}
    <p className="capability-blocked-note">{t('capabilityDeploymentBlockedNote')}</p>
  </section>
}
