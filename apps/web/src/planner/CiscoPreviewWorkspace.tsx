import { useEffect, useRef, useState } from 'react'
import type { EventRecord } from '../api'
import { Badge, Button, Loading, Select, Table } from '../components/ui'
import { useMessages } from '../locale'
import type { MessageKey } from '../messages'
import { list as listRevisions, read as readRevision } from './model'
import type { Revision, Summary } from './model'
import {
  canLoadL2Candidates,
  ciscoAssignments,
  fetchL2Candidates,
  fetchL2Intent,
  fetchL2Validation,
  isAbort,
  l2ErrorFields,
  l2ProblemKeys,
  l2ReviewRows,
  l2Status,
  overallStatus,
  parsePreviewError,
  previewErrorKey,
  validateL2Document,
  validateL2Intent,
  validateL2Report,
} from './ciscoPreview'
import type {
  CiscoAssignment,
  L2CandidateDocument,
  L2Intent,
  L2Problem,
  L2ReviewRow,
  L2ValidationReport,
  PreviewBinding,
  PreviewError,
  SubsystemStatus,
} from './ciscoPreview'
import {
  CONFIG_ASSEMBLY_PROBLEM_KEYS,
  fetchConfigAssembly,
  parseAssemblyError,
  validateAssembly,
} from './configAssembly'
import type {
  AssemblyL2Trust,
  AssemblyL3Trust,
  AssemblySectionStatus,
  AssemblyTrustInputs,
  ConfigurationAssembly,
} from './configAssembly'
import {
  fetchManagementReview,
  parseManagementError,
  validateManagementReview,
} from './managementAuth'
import type { ManagementReview } from './managementAuth'
import {
  canLoadCandidates as canLoadL3Candidates,
  fetchCandidates as fetchL3Candidates,
  fetchValidation as fetchL3Validation,
  isReviewedC9200Registry as isReviewedC9200L3Registry,
  isUnreviewedRegistry as isUnreviewedL3Registry,
  reviewRows as l3ReviewRows,
  validateDocument as validateL3Document,
  validateReport as validateL3Report,
} from './l3Review'
import type {
  L3CandidateDocument,
  L3ValidationReport,
  ReviewBinding,
  ReviewProblem,
  ReviewRow,
} from './l3Review'

type L2View =
  | { kind: 'loading' }
  | { kind: 'invalid'; problems: L2Problem[]; error?: PreviewError; report?: L2ValidationReport }
  | { kind: 'error'; error: PreviewError }
  | {
    kind: 'ready'; report: L2ValidationReport; document: L2CandidateDocument | null;
    intent: L2Intent | null; intentError: L2Problem[]; intentFailure?: PreviewError;
    rows: L2ReviewRow[]; status: SubsystemStatus; candidateError?: PreviewError;
  }

type L3View =
  | { kind: 'loading' }
  | { kind: 'na'; reason: 'non-core' }
  | { kind: 'invalid'; problems: ReviewProblem[]; error?: PreviewError; report?: L3ValidationReport }
  | { kind: 'error'; error: PreviewError }
  | {
    kind: 'ready'; report: L3ValidationReport; document: L3CandidateDocument | null;
    rows: ReviewRow[]; status: SubsystemStatus; candidateError?: PreviewError;
  }

type AssemblyView =
  | { kind: 'loading' }
  | { kind: 'invalid'; problems: string[]; assembly?: ConfigurationAssembly }
  | { kind: 'error'; error: PreviewError }
  | { kind: 'ready'; assembly: ConfigurationAssembly }

type ManagementView =
  | { kind: 'loading' }
  | { kind: 'invalid'; problems: string[]; review?: ManagementReview }
  | { kind: 'error'; error: PreviewError }
  | { kind: 'ready'; review: ManagementReview }

const statusKey: Record<SubsystemStatus, MessageKey> = {
  pass: 'overallPass',
  partial: 'overallPartial',
  fail: 'overallFail',
  na: 'ciscoStatusNotApplicable',
}

function statusTone(status: SubsystemStatus | 'loading'): string {
  if (status === 'loading') return 'neutral'
  return status === 'pass' ? 'success' : status === 'partial' ? 'warning' : status === 'fail' ? 'danger' : 'neutral'
}

interface DeviceIdentity {
  hostname: string
  family: string | null
  exact_pid: string | null
  release: string | null
  license: string | null
  role: string
  stack_identity: string
}

function statusOfL2(view: L2View): SubsystemStatus | 'loading' {
  if (view.kind === 'loading') return 'loading'
  if (view.kind === 'invalid' || view.kind === 'error') return 'fail'
  return view.status
}

function statusOfL3(view: L3View): SubsystemStatus | 'loading' {
  if (view.kind === 'loading') return 'loading'
  if (view.kind === 'na') return 'na'
  if (view.kind === 'invalid' || view.kind === 'error') return 'fail'
  return view.status
}

function previewStatus(left: L2View, right: L3View): SubsystemStatus | 'loading' {
  const leftStatus = statusOfL2(left)
  const rightStatus = statusOfL3(right)
  if (leftStatus === 'loading' || rightStatus === 'loading') return 'loading'
  return overallStatus(leftStatus, rightStatus)
}

function statusLabel(t: (key: MessageKey) => string, status: SubsystemStatus | 'loading') {
  return status === 'loading' ? t('ciscoLoading') : t(statusKey[status])
}

function candidateStatusKey(value: string): MessageKey {
  if (value === 'candidate') return 'candidateStatusCandidate'
  if (value === 'blocked') return 'candidateStatusBlocked'
  return 'candidateStatusUnsupported'
}

function verdictKey(value: string): MessageKey {
  if (value === 'pass') return 'verdictPass'
  if (value === 'fail') return 'verdictFail'
  if (value === 'blocked') return 'verdictBlocked'
  return 'verdictNotRun'
}

function candidateTone(value: string | null) {
  return value === 'candidate' ? 'success' : value === 'blocked' ? 'danger' : 'warning'
}

function L2Row({ row }: { row: L2ReviewRow }) {
  const { t } = useMessages()
  return <tr>
    <td>{row.category}</td>
    <td>{row.targetName || t('ciscoNotAvailable')}</td>
    <td>{row.status ? <Badge tone={candidateTone(row.status)}>{t(candidateStatusKey(row.status))}</Badge>
      : <span className="muted">{t('ciscoNotAvailable')}</span>}</td>
    <td><Badge tone={row.verdict === 'pass' ? 'success' : row.verdict === 'fail' ? 'danger' : 'warning'}>{t(verdictKey(row.verdict))}</Badge></td>
    <td>{row.risk || t('ciscoNotAvailable')}</td>
    <td>{row.blockingReasons.length
      ? row.blockingReasons.map((reason) => <code className="cisco-reason" key={reason}>{reason}</code>)
      : <span className="muted">{t('ciscoNotAvailable')}</span>}</td>
    <td><CandidateDetails row={row} /></td>
  </tr>
}

function L3Row({ row }: { row: ReviewRow }) {
  const { t } = useMessages()
  return <tr>
    <td>{row.category}</td>
    <td>{row.targetName || t('ciscoNotAvailable')}</td>
    <td>{row.status ? <Badge tone={candidateTone(row.status)}>{t(candidateStatusKey(row.status))}</Badge>
      : <span className="muted">{t('ciscoNotAvailable')}</span>}</td>
    <td><Badge tone={row.verdict === 'pass' ? 'success' : row.verdict === 'fail' || row.verdict === 'blocked' ? 'danger' : 'warning'}>{t(verdictKey(row.verdict))}</Badge></td>
    <td>{row.risk || t('ciscoNotAvailable')}</td>
    <td>{row.blockingReasons.length
      ? row.blockingReasons.map((reason) => <code className="cisco-reason" key={reason}>{reason}</code>)
      : <span className="muted">{t('ciscoNotAvailable')}</span>}</td>
    <td><CandidateDetails row={row} /></td>
  </tr>
}

function CandidateDetails({ row }: { row: L2ReviewRow | ReviewRow }) {
  const { t } = useMessages()
  return <details className="cisco-candidate-details">
    <summary>{t('ciscoDetails')}</summary>
    <dl className="cisco-details-list">
      <div><dt>{t('ciscoTargetKind')}</dt><dd>{row.targetKind || t('ciscoNotAvailable')}</dd></div>
      {row.commandContext && <div>
        <dt>{t('ciscoCommandContext')}</dt>
        <dd><code>{row.commandContext.mode_header}</code> · {row.commandContext.target_name}</dd>
      </div>}
      {row.text
        ? <div><dt>{t('ciscoCandidateText')}</dt><dd><pre className="cisco-command"><code>{row.text}</code></pre></dd></div>
        : <div><dt>{t('ciscoCandidateText')}</dt><dd>{t('ciscoTextWithheld')}</dd></div>}
    </dl>
  </details>
}

function ProblemList({ problems, keys }: { problems: string[]; keys: Record<string, MessageKey> }) {
  const { t } = useMessages()
  return <ul className="cisco-problem-list">
    {[...new Set(problems)].map((problem) => <li key={problem}>{t(keys[problem] ?? 'ciscoDataInconsistent')} <code>{problem}</code></li>)}
  </ul>
}

export function CiscoPreviewWorkspace({ event, navigate }: { event: EventRecord; navigate: (route: string) => void }) {
  const { t } = useMessages()
  const [revisions, setRevisions] = useState<Summary[] | null>(null)
  const [revisionId, setRevisionId] = useState('')
  const [revision, setRevision] = useState<Revision | null>(null)
  const [assignments, setAssignments] = useState<CiscoAssignment[]>([])
  const [assignmentId, setAssignmentId] = useState('')
  const [l2, setL2] = useState<L2View>({ kind: 'loading' })
  const [l3, setL3] = useState<L3View>({ kind: 'loading' })
  const [assembly, setAssembly] = useState<AssemblyView>({ kind: 'loading' })
  const [management, setManagement] = useState<ManagementView>({ kind: 'loading' })
  const [error, setError] = useState<PreviewError | null>(null)
  const [stage, setStage] = useState<'loading-revisions' | 'loading-revision' | 'ready'>('loading-revisions')
  const [bootAttempt, setBootAttempt] = useState(0)
  const [revisionAttempt, setRevisionAttempt] = useState(0)
  const [previewAttempt, setPreviewAttempt] = useState(0)
  const requestSequence = useRef(0)

  useEffect(() => {
    const controller = new AbortController()
    const sequence = ++requestSequence.current
    setStage('loading-revisions')
    setRevisions(null)
    setRevisionId('')
    setRevision(null)
    setAssignments([])
    setAssignmentId('')
    setL2({ kind: 'loading' })
    setL3({ kind: 'loading' })
    setAssembly({ kind: 'loading' })
    setManagement({ kind: 'loading' })
    setError(null)
    void (async () => {
      try {
        const entries = await listRevisions(event.id, controller.signal)
        if (controller.signal.aborted || sequence !== requestSequence.current) return
        setRevisions(entries)
        setRevisionId(entries.at(-1)?.id ?? '')
        setStage(entries.length ? 'loading-revision' : 'ready')
      } catch (failure) {
        if (controller.signal.aborted || isAbort(failure)) return
        setError(parsePreviewError(failure))
        setStage('ready')
      }
    })()
    return () => controller.abort()
  }, [event.id, bootAttempt])

  useEffect(() => {
    if (!revisionId) return
    const controller = new AbortController()
    const sequence = ++requestSequence.current
    setStage('loading-revision')
    setRevision(null)
    setAssignments([])
    setAssignmentId('')
    setL2({ kind: 'loading' })
    setL3({ kind: 'loading' })
    setAssembly({ kind: 'loading' })
    setManagement({ kind: 'loading' })
    setError(null)
    void (async () => {
      try {
        const detail = await readRevision(event.id, revisionId, controller.signal)
        if (controller.signal.aborted || sequence !== requestSequence.current) return
        const options = ciscoAssignments(detail.plan)
        setRevision(detail)
        setAssignments(options)
        setAssignmentId((options.find((item) => item.isCore) ?? options[0])?.assignmentId ?? '')
        setStage('ready')
      } catch (failure) {
        if (controller.signal.aborted || isAbort(failure)) return
        setError(parsePreviewError(failure))
        setStage('ready')
      }
    })()
    return () => controller.abort()
  }, [event.id, revisionId, revisionAttempt])

  useEffect(() => {
    const assignment = assignments.find((item) => item.assignmentId === assignmentId)
    if (!revision || !assignment) return
    const controller = new AbortController()
    const sequence = ++requestSequence.current
    const binding: PreviewBinding = { eventId: event.id, revision, assignment }
    setL2({ kind: 'loading' })
    setL3(assignment.isCore ? { kind: 'loading' } : { kind: 'na', reason: 'non-core' })
    setAssembly({ kind: 'loading' })
    setManagement({ kind: 'loading' })
    void (async () => {
      const [l2Result, l3Result] = await Promise.allSettled([
        loadL2(binding, controller.signal),
        assignment.isCore ? loadL3(binding, controller.signal) : Promise.resolve<L3View>({ kind: 'na', reason: 'non-core' }),
      ])
      if (controller.signal.aborted || sequence !== requestSequence.current) return
      if (l2Result.status === 'fulfilled' && l2Result.value) setL2(l2Result.value)
      else if (l2Result.status === 'rejected' && !isAbort(l2Result.reason)) {
        setL2({ kind: 'error', error: parsePreviewError(l2Result.reason) })
      }
      if (l3Result.status === 'fulfilled' && l3Result.value) setL3(l3Result.value)
      else if (l3Result.status === 'rejected' && !isAbort(l3Result.reason)) {
        setL3({ kind: 'error', error: parsePreviewError(l3Result.reason) })
      }
      const [assemblyResult, managementResult] = await Promise.allSettled([
        fetchConfigAssembly(
          binding.eventId, binding.revision.id, binding.assignment.assignmentId,
          controller.signal,
        ),
        fetchManagementReview(
          binding.eventId, binding.revision.id, binding.assignment.assignmentId,
          controller.signal,
        ),
      ])
      if (controller.signal.aborted || sequence !== requestSequence.current) return
      if (assemblyResult.status === 'fulfilled') {
        const value = assemblyResult.value
        const l2View = l2Result.status === 'fulfilled' ? l2Result.value : null
        const l3View = l3Result.status === 'fulfilled' ? l3Result.value : null
        const trust: AssemblyTrustInputs = {
          l2: trustedL2(l2View),
          l3: trustedL3(l3View),
          l3Applicable: assignment.isCore,
        }
        const problems = validateAssembly(value, binding, trust)
        setAssembly(problems.length
          ? { kind: 'invalid', problems, assembly: value }
          : { kind: 'ready', assembly: value })
      } else if (!isAbort(assemblyResult.reason)) {
        setAssembly({
          kind: 'error',
          error: parseAssemblyError(assemblyResult.reason) as PreviewError,
        })
      }
      if (managementResult.status === 'fulfilled') {
        const review = managementResult.value
        const problems = validateManagementReview(review, binding)
        setManagement(problems.length
          ? { kind: 'invalid', problems }
          : { kind: 'ready', review })
      } else if (!isAbort(managementResult.reason)) {
        setManagement({
          kind: 'error',
          error: parseManagementError(managementResult.reason) as PreviewError,
        })
      }
    })().catch((failure: unknown) => {
      if (controller.signal.aborted || isAbort(failure) || sequence !== requestSequence.current) return
      const error = parsePreviewError(failure)
      setL2({ kind: 'error', error })
      setL3({ kind: 'error', error })
    })
    return () => controller.abort()
  }, [event.id, revision, assignments, assignmentId, previewAttempt])

  const selectedAssignment = assignments.find((item) => item.assignmentId === assignmentId)
  const loading = stage.startsWith('loading') || l2.kind === 'loading' || l3.kind === 'loading'
  const overall = revision && selectedAssignment ? previewStatus(l2, l3) : null
  const device: DeviceIdentity | null = l2.kind === 'ready'
    ? {
      hostname: l2.report.device.hostname, family: l2.report.device.family,
      exact_pid: l2.report.device.exact_pid, release: l2.report.device.release,
      license: l2.report.device.license, role: l2.report.device.role,
      stack_identity: l2.report.device.stack_identity,
    }
    : l3.kind === 'ready'
      ? {
        hostname: l3.report.device.hostname, family: l3.report.device.family,
        exact_pid: l3.report.device.exact_pid, release: l3.report.device.software_image,
        license: l3.report.device.software_license, role: l3.report.device.role,
        stack_identity: l3.report.device.stack_identity,
      }
      : null

  function invalidatePreview() {
    requestSequence.current += 1
    setL2({ kind: 'loading' })
    setL3({ kind: 'loading' })
    setAssembly({ kind: 'loading' })
    setManagement({ kind: 'loading' })
    setError(null)
  }

  function chooseRevision(next: string) {
    invalidatePreview()
    setRevisionId(next)
    setRevision(null)
    setAssignments([])
    setAssignmentId('')
    setStage('loading-revision')
  }

  function chooseAssignment(next: string) {
    invalidatePreview()
    setAssignmentId(next)
  }

  function retry() {
    invalidatePreview()
    if (stage !== 'ready' || !revisions) setBootAttempt((value) => value + 1)
    else if (!revision) setRevisionAttempt((value) => value + 1)
    else setPreviewAttempt((value) => value + 1)
  }

  return <main id="main" className="shell screen cisco-preview">
    <div className="page-head">
      <div>
        <p className="breadcrumb">{event.name} <span aria-hidden="true">/</span> {t('ciscoPreview')}</p>
        <h1>{t('ciscoPreview')}</h1>
        <div className="status-strip">
          <Badge tone="neutral">{t('ciscoReadOnly')}</Badge>
          <Badge tone="warning">{t('hardwareNotVerified')}</Badge>
          <Badge tone="danger">{t('ciscoDeploymentNotAllowed')}</Badge>
          {overall && <Badge tone={overall === 'loading' ? 'neutral' : statusTone(overall)}>
            {statusLabel(t, overall)}
          </Badge>}
        </div>
      </div>
      <div className="actions">
        <Button onClick={() => navigate('planner/addressing')}>{t('ciscoBackToPlanner')}</Button>
        <Button onClick={retry} disabled={loading}>{t('ciscoRetry')}</Button>
      </div>
    </div>
    <p className="cisco-scope-note" role="note">{t('ciscoScopeNote')}</p>

    {stage === 'loading-revisions' && <Loading>{t('ciscoLoadingRevisions')}</Loading>}
    {stage === 'loading-revision' && revisions !== null && revisions.length > 0 &&
      <Loading>{t('ciscoLoadingReview')}</Loading>}
    {revisions && revisions.length > 0 && <section className="panel cisco-controls" aria-label={t('ciscoPreviewControls')}>
      <label className="field" htmlFor="cisco-revision">{t('ciscoSelectRevision')}
        <Select id="cisco-revision" value={revisionId} disabled={!revisions.length} onChange={(input) => chooseRevision(input.target.value)}>
          {revisions.map((item) => <option value={item.id} key={item.id}>#{item.number}: {item.content_hash.slice(0, 12)}</option>)}
        </Select>
      </label>
      <label className="field" htmlFor="cisco-assignment">{t('ciscoSelectAssignment')}
        <Select id="cisco-assignment" value={assignmentId} disabled={!assignments.length}
          onChange={(input) => chooseAssignment(input.target.value)}>
          {assignments.length
            ? assignments.map((item) => <option value={item.assignmentId} key={item.assignmentId}>
              {item.hostname} ({item.role}){item.pid ? ' · ' + item.pid : ''}
            </option>)
            : <option value="">{t('ciscoNoCiscoAssignment')}</option>}
        </Select>
      </label>
    </section>}

    {stage === 'ready' && revisions !== null && revisions.length === 0 && <section className="panel cisco-empty">
      <h2>{t('ciscoNoSavedRevisions')}</h2>
      <p>{t('ciscoNoSavedRevisionsHelp')}</p>
      <Button primary onClick={() => navigate('planner/addressing')}>{t('ciscoBackToPlanner')}</Button>
    </section>}

    {revision && <section className="panel cisco-revision" aria-label={t('ciscoSavedRevision')}>
      <div className="section-head"><h2>{t('ciscoSavedRevision')} #{revision.number}</h2>
        <span className="muted">{t('ciscoRevisionReadOnly')}</span></div>
      <dl className="cisco-metadata">
        <div><dt>{t('event')}</dt><dd>{event.name}</dd></div>
        <div><dt>{t('revision')}</dt><dd>#{revision.number}</dd></div>
        <div><dt>{t('revisionId')}</dt><dd><code>{revision.id}</code></dd></div>
        <div><dt>{t('ciscoCanonicalHash')}</dt><dd><code>{revision.content_hash}</code></dd></div>
        <div><dt>{t('ciscoDevice')}</dt><dd>{device?.hostname ?? selectedAssignment?.hostname ?? t('ciscoNotAvailable')}</dd></div>
        <div><dt>{t('ciscoAssignmentId')}</dt><dd><code>{assignmentId || t('ciscoNotAvailable')}</code></dd></div>
        <div><dt>{t('ciscoFamily')}</dt><dd>{device?.family ?? selectedAssignment?.family ?? t('ciscoNotAvailable')}</dd></div>
        <div><dt>{t('ciscoRole')}</dt><dd>{device?.role ?? selectedAssignment?.role ?? t('ciscoNotAvailable')}</dd></div>
        <div><dt>{t('ciscoExactPid')}</dt><dd><code>{device?.exact_pid ?? selectedAssignment?.pid ?? t('ciscoNotAvailable')}</code></dd></div>
        <div><dt>{t('ciscoSoftwareImage')}</dt><dd>{device?.release ?? selectedAssignment?.image ?? t('ciscoNotAvailable')}</dd></div>
        <div><dt>{t('ciscoSoftwareLicense')}</dt><dd>{device?.license ?? selectedAssignment?.license ?? t('ciscoNotAvailable')}</dd></div>
        <div><dt>{t('ciscoStackIdentity')}</dt><dd>{device?.stack_identity ?? selectedAssignment?.stackIdentity ?? t('ciscoNotAvailable')}</dd></div>
        <div><dt>{t('ciscoHardwareVerification')}</dt><dd><Badge tone="warning">{t('hardwareNotVerified')}</Badge></dd></div>
      </dl>
    </section>}

    {revision && assignments.length === 0 && <section className="panel cisco-empty" role="status">
      <h2>{t('ciscoNoCiscoAssignment')}</h2>
      <p>{t('ciscoNoCiscoAssignmentHelp')}</p>
    </section>}

    {error && <section className="panel cisco-error" role="alert">
      <h2>{t('ciscoLoadPreviewError')}</h2>
      <p>{t(previewErrorKey(error))}</p>
      {l2ErrorFields(error).map((field) => <p key={field}><span className="muted">{t('ciscoReasonCode')}</span> <code>{field}</code></p>)}
      <Button onClick={retry}>{t('ciscoRetry')}</Button>
    </section>}

    {revision && selectedAssignment && overall && <section className="cisco-overview" aria-label={t('ciscoOverview')}>
      <div className="panel cisco-status-card">
        <span className="cisco-eyebrow">{t('ciscoOverallStatus')}</span>
        <Badge tone={overall === 'loading' ? 'neutral' : statusTone(overall)}>{statusLabel(t, overall)}</Badge>
        <p>{t('ciscoOverviewNote')}</p>
      </div>
      <div className="panel cisco-status-card">
        <span className="cisco-eyebrow">{t('ciscoL2Status')}</span>
        <Badge tone={statusTone(statusOfL2(l2))}>
          {statusLabel(t, statusOfL2(l2))}
        </Badge>
        <p>{t('ciscoL2OverviewNote')}</p>
      </div>
      <div className="panel cisco-status-card">
        <span className="cisco-eyebrow">{t('ciscoL3Status')}</span>
        <Badge tone={statusTone(statusOfL3(l3))}>
          {statusLabel(t, statusOfL3(l3))}
        </Badge>
        <p>{l3.kind === 'na' ? t('ciscoNotApplicableL3') : t('ciscoL3OverviewNote')}</p>
      </div>
    </section>}

    {revision && selectedAssignment && <div className="cisco-subsystems">
      <section className="panel cisco-subsystem" aria-label={t('ciscoL2Review')}>
        <div className="section-head">
          <h2>{t('ciscoL2Review')}</h2>
          <Badge tone={statusTone(statusOfL2(l2))}>
            {statusLabel(t, statusOfL2(l2))}
          </Badge>
        </div>
        <p className="muted">{t('ciscoL2ScopeNote')}</p>
        <L2Section view={l2} />
      </section>
      <section className="panel cisco-subsystem" aria-label={t('ciscoL3Review')}>
        <div className="section-head">
          <h2>{t('ciscoL3Review')}</h2>
          <Badge tone={statusTone(statusOfL3(l3))}>
            {statusLabel(t, statusOfL3(l3))}
          </Badge>
        </div>
        <p className="muted">{t('ciscoL3ScopeNote')}</p>
        <L3Section view={l3} />
      </section>
    </div>}

    {revision && selectedAssignment && <ManagementPanel view={management} />}

    {revision && selectedAssignment && <AssemblyPanel view={assembly} />}

    {revision && selectedAssignment && <SourcePanel l2={l2} l3={l3} />}
  </main>
}

function trustedL2(view: L2View | null | undefined): AssemblyL2Trust | null {
  return view?.kind === 'ready' && view.document
    ? { report: view.report, document: view.document }
    : null
}

function trustedL3(view: L3View | null | undefined): AssemblyL3Trust | null {
  return view?.kind === 'ready' && view.document
    ? { report: view.report, document: view.document }
    : null
}

async function loadL2(binding: PreviewBinding, signal: AbortSignal): Promise<L2View | null> {
  try {
    const report = await fetchL2Validation(binding.eventId, binding.revision.id, binding.assignment.assignmentId, signal)
    const problems = validateL2Report(report, binding)
    if (problems.length) return { kind: 'invalid', problems, report }
    let document: L2CandidateDocument | null = null
    let candidateError: PreviewError | undefined
    let intent: L2Intent | null = null
    let intentError: L2Problem[] = []
    let intentFailure: PreviewError | undefined
    try {
      const preview = await fetchL2Intent(binding.eventId, binding.revision.id, binding.assignment.assignmentId, signal)
      intentError = validateL2Intent(preview, report, binding)
      if (!intentError.length) intent = preview
    } catch (failure) {
      if (isAbort(failure)) return null
      intentFailure = parsePreviewError(failure)
    }
    if (canLoadL2Candidates(report)) {
      try {
        const rendered = await fetchL2Candidates(binding.eventId, binding.revision.id, binding.assignment.assignmentId, signal)
        const documentProblems = validateL2Document(report, rendered, binding)
        if (documentProblems.length) return { kind: 'invalid', problems: documentProblems, report }
        document = rendered
      } catch (failure) {
        if (isAbort(failure)) return null
        candidateError = parsePreviewError(failure)
      }
    }
    const rows = l2ReviewRows(report, document)
    let status = l2Status(report, rows, document, candidateError ?? null)
    if ((intentError.length || intentFailure) && status === 'pass') status = 'partial'
    return {
      kind: 'ready', report, document, intent, intentError, intentFailure, rows, status, candidateError,
    }
  } catch (failure) {
    if (isAbort(failure)) return null
    return { kind: 'error', error: parsePreviewError(failure) }
  }
}

async function loadL3(binding: PreviewBinding, signal: AbortSignal): Promise<L3View | null> {
  try {
    const report = await fetchL3Validation(binding.eventId, binding.revision.id, binding.assignment.assignmentId, signal)
    const reviewBinding: ReviewBinding = {
      eventId: binding.eventId, revision: binding.revision, assignmentId: binding.assignment.assignmentId,
    }
    const problems = validateL3Report(report, reviewBinding)
    if (problems.length) return { kind: 'invalid', problems, report }
    let document: L3CandidateDocument | null = null
    let candidateError: PreviewError | undefined
    if (canLoadL3Candidates(report) && report.overall_status !== 'fail') {
      try {
        const rendered = await fetchL3Candidates(binding.eventId, binding.revision.id, binding.assignment.assignmentId, signal)
        const documentProblems = validateL3Document(report, rendered, reviewBinding)
        if (documentProblems.length) return { kind: 'invalid', problems: documentProblems, report }
        document = rendered
      } catch (failure) {
        if (isAbort(failure)) return null
        candidateError = parsePreviewError(failure)
      }
    }
    const rows = l3ReviewRows(report, document)
    const status: SubsystemStatus = report.overall_status === 'fail'
      ? 'fail' : candidateError || !document ? 'partial' : report.overall_status
    return { kind: 'ready', report, document, rows, status, candidateError }
  } catch (failure) {
    if (isAbort(failure)) return null
    return { kind: 'error', error: parsePreviewError(failure) }
  }
}

function IntentPanel({ view }: { view: Extract<L2View, { kind: 'ready' }> }) {
  const { t } = useMessages()
  if (view.intent) return <section className="cisco-intent" aria-label={t('ciscoL2Intent')}>
    <div className="section-head"><h3>{t('ciscoL2Intent')}</h3>
      <Badge tone="neutral">{t('ciscoDisplayOnly')}</Badge></div>
    <p>{view.intent.device.human_readable.headline}</p>
    <dl className="cisco-counts">
      <div><dt>{t('ciscoIntentItems')}</dt><dd>{view.intent.device.summary.config_items}</dd></div>
      <div><dt>{t('ciscoIntentChanges')}</dt><dd>{view.intent.device.summary.changed_items}</dd></div>
      <div><dt>{t('ciscoIntentEvidencePass')}</dt><dd>{view.intent.device.summary.evidence_pass_items}</dd></div>
    </dl>
    <ul className="cisco-intent-statements">
      {view.intent.device.human_readable.statements.slice(0, 6).map((statement) => <li key={statement}>{statement}</li>)}
    </ul>
    {view.intent.device.human_readable.statements.length > 6 && <details className="cisco-intent-more">
      <summary>{t('ciscoIntentMore')}</summary>
      <ul className="cisco-intent-statements">
        {view.intent.device.human_readable.statements.slice(6).map((statement) => <li key={statement}>{statement}</li>)}
      </ul>
    </details>}
    <p className="cisco-source-note">{t('ciscoIntentDisplayOnly')}</p>
  </section>
  if (view.intentError.length) return <div className="cisco-error" role="alert">
    <h3>{t('ciscoIntentUnavailable')}</h3>
    <p>{t('ciscoDataInconsistentHelp')}</p>
    <ProblemList problems={view.intentError} keys={l2ProblemKeys as Record<string, MessageKey>} />
  </div>
  if (view.intentFailure) return <p className="cisco-candidate-error" role="alert">
    {t('ciscoIntentUnavailable')} <code>{view.intentFailure.reasonCode || view.intentFailure.detail}</code>
  </p>
  return null
}

function L2Section({ view }: { view: L2View }) {
  const { t } = useMessages()
  if (view.kind === 'loading') return <Loading>{t('ciscoLoadingL2')}</Loading>
  if (view.kind === 'error') return <div className="cisco-error" role="alert">
    <h3>{t('ciscoValidationFailed')}</h3>
    <p>{t(previewErrorKey(view.error))}</p>
    {view.error.reasonCode === 'assignment-not-found' &&
      <p>{t('ciscoSelectedIdentityConflict')}</p>}
    {l2ErrorFields(view.error).map((field) => <p key={field}><span className="muted">{t('ciscoReasonCode')}</span> <code>{field}</code></p>)}
  </div>
  if (view.kind === 'invalid') return <div className="cisco-error" role="alert">
    <h3>{t('ciscoDataInconsistent')}</h3>
    <p>{t('ciscoDataInconsistentHelp')}</p>
    <ProblemList problems={view.problems} keys={l2ProblemKeys as Record<string, MessageKey>} />
    {view.error && <p>{t(previewErrorKey(view.error))}</p>}
  </div>
  return <>
    <IntentPanel view={view} />
    <dl className="cisco-counts">
      <div><dt>{t('ciscoTotal')}</dt><dd>{view.report.summary.total_candidates}</dd></div>
      <div><dt>{t('ciscoCandidatesCount')}</dt><dd>{view.document?.summary.candidates ?? view.rows.filter((row) => row.status === 'candidate').length}</dd></div>
      <div><dt>{t('ciscoBlockedCount')}</dt><dd>{view.rows.filter((row) => row.status === 'blocked' || row.verdict !== 'pass').length}</dd></div>
      <div><dt>{t('ciscoUnsupportedCount')}</dt><dd>{view.rows.filter((row) => row.status === 'unsupported').length}</dd></div>
    </dl>
    {view.status !== 'pass' && <p className="cisco-partial-note" role="status">{t('ciscoPartialNote')}</p>}
    {view.candidateError && <p className="cisco-candidate-error" role="alert">{t('ciscoCandidateDocumentUnavailable')} <code>{view.candidateError.reasonCode || view.candidateError.detail}</code></p>}
    {!view.rows.length ? <p className="empty">{t('ciscoNoCandidates')}</p> : <>
      <p className="cisco-table-hint muted">{t('ciscoScrollTable')}</p>
      <Table label={t('ciscoL2Candidates')}>
      <thead><tr>
        <th scope="col">{t('ciscoCategory')}</th><th scope="col">{t('ciscoTarget')}</th>
        <th scope="col">{t('ciscoCandidateStatus')}</th><th scope="col">{t('ciscoIndependentVerdict')}</th>
        <th scope="col">{t('ciscoRiskClass')}</th><th scope="col">{t('ciscoBlockingReasons')}</th>
        <th scope="col">{t('ciscoDetails')}</th>
      </tr></thead><tbody>{view.rows.map((row) => <L2Row row={row} key={row.candidateId} />)}</tbody>
      </Table>
    </>}
  </>
}

function L3Section({ view }: { view: L3View }) {
  const { t } = useMessages()
  if (view.kind === 'loading') return <Loading>{t('ciscoLoadingL3')}</Loading>
  if (view.kind === 'na') return <p className="cisco-na" role="status">{t('ciscoNotApplicableL3')}</p>
  if (view.kind === 'error') return <div className="cisco-error" role="alert">
    <h3>{t('ciscoValidationFailed')}</h3>
    <p>{t(previewErrorKey(view.error))}</p>
    {view.error.reasonCode === 'assignment-not-eligible-for-l3-cli' &&
      <p>{t('ciscoBackendIdentityConflict')}</p>}
    {l2ErrorFields(view.error).map((field) => <p key={field}><span className="muted">{t('ciscoReasonCode')}</span> <code>{field}</code></p>)}
  </div>
  if (view.kind === 'invalid') return <div className="cisco-error" role="alert">
    <h3>{t('ciscoDataInconsistent')}</h3>
    <p>{t('ciscoDataInconsistentHelp')}</p>
    <ProblemList problems={view.problems} keys={{
      ...l2ProblemKeys as Record<string, MessageKey>,
      ...(Object.fromEntries(Object.entries({
        'validation-scope': 'l3DataScopeMismatch', 'validation-contract': 'l3DataContractMismatch',
        'source-binding': 'l3DataSourceMismatch', 'expected-source': 'l3DataExpectedSourceMismatch',
        'actual-source': 'l3DataActualSourceMismatch', 'report-integrity': 'l3DataIntegrityMismatch',
        'report-safety': 'l3DataSafetyMismatch', 'report-fingerprint': 'l3DataFingerprintMismatch',
        'report-assignment': 'l3DataAssignmentMismatch', 'report-device': 'l3DataDeviceMismatch',
        'report-summary': 'l3DataSummaryMismatch', 'report-candidates': 'l3DataCandidateMismatch',
        'document-contract': 'l3DataContractMismatch', 'document-source': 'l3DataSourceMismatch',
        'document-fingerprint': 'l3DataFingerprintMismatch', 'document-assignment': 'l3DataAssignmentMismatch',
        'document-device': 'l3DataDeviceMismatch', 'document-candidates': 'l3DataCandidateMismatch',
        'candidate-text': 'l3DataCandidateTextMismatch',
      })) as Record<string, MessageKey>),
    }} />
  </div>
  return <>
    <dl className="cisco-counts">
      <div><dt>{t('ciscoTotal')}</dt><dd>{view.report.summary.total}</dd></div>
      <div><dt>{t('ciscoPassed')}</dt><dd>{view.report.summary.passed}</dd></div>
      <div><dt>{t('ciscoFailed')}</dt><dd>{view.report.summary.failed}</dd></div>
      <div><dt>{t('ciscoBlockedCount')}</dt><dd>{view.report.summary.blocked}</dd></div>
      <div><dt>{t('ciscoNotRun')}</dt><dd>{view.report.summary.not_run}</dd></div>
    </dl>
    {view.status !== 'pass' && <p className="cisco-partial-note" role="status">{t('ciscoPartialNote')}</p>}
    {isUnreviewedL3Registry(view.report) && <p className="cisco-partial-note cisco-unreviewed-note" role="note">
      {t('ciscoL3UnreviewedRegistryNote')}
    </p>}
    {isReviewedC9200L3Registry(view.report) && <p className="cisco-partial-note cisco-reviewed-note" role="note">
      {t('ciscoL3ReviewedC9200')}
    </p>}
    {view.report.summary.dhcp_helper_blocked && <p className="cisco-dhcp-blocked" role="note">
      <Badge tone="danger">{t('ciscoDhcpHelperBlocked')}</Badge> {t('ciscoDhcpHelperBlockedDetail')}
    </p>}
    {view.candidateError && <p className="cisco-candidate-error" role="alert">{t('ciscoCandidateDocumentUnavailable')} <code>{view.candidateError.reasonCode || view.candidateError.detail}</code></p>}
    {!view.rows.length ? <p className="empty">{t('ciscoNoCandidates')}</p> : <>
      <p className="cisco-table-hint muted">{t('ciscoScrollTable')}</p>
      <Table label={t('ciscoL3Candidates')}>
      <thead><tr>
        <th scope="col">{t('ciscoCategory')}</th><th scope="col">{t('ciscoTarget')}</th>
        <th scope="col">{t('ciscoCandidateStatus')}</th><th scope="col">{t('ciscoIndependentVerdict')}</th>
        <th scope="col">{t('ciscoRiskClass')}</th><th scope="col">{t('ciscoBlockingReasons')}</th>
        <th scope="col">{t('ciscoDetails')}</th>
      </tr></thead><tbody>{view.rows.map((row) => <L3Row row={row} key={row.candidateId} />)}</tbody>
      </Table>
    </>}
  </>
}

function assemblyStatusKey(status: AssemblySectionStatus): MessageKey {
  if (status === 'VALIDATED_SECTION') return 'ciscoAssemblyValidated'
  if (status === 'PARTIAL') return 'ciscoAssemblyPartial'
  if (status === 'BLOCKED') return 'ciscoAssemblyBlocked'
  if (status === 'NOT_APPLICABLE') return 'ciscoAssemblyNotApplicable'
  return 'ciscoAssemblyNotImplemented'
}

function assemblyStatusTone(status: AssemblySectionStatus): string {
  if (status === 'VALIDATED_SECTION') return 'success'
  if (status === 'PARTIAL') return 'warning'
  if (status === 'BLOCKED') return 'danger'
  return 'neutral'
}

function assemblyCheckTone(status: string): string {
  if (status === 'PASS') return 'success'
  if (status === 'FAIL') return 'danger'
  if (status === 'BLOCKED') return 'warning'
  return 'neutral'
}

function managementTone(status: string): string {
  if (status === 'PLANNED' || status === 'PARTIAL') return 'warning'
  if (status === 'VALIDATED' || status === 'PASS') return 'success'
  if (status === 'BLOCKED' || status === 'FAIL') return 'danger'
  return 'neutral'
}

function ManagementFacts({ review }: { review: ManagementReview }) {
  const { t } = useMessages()
  const intent = review.intent
  const credential = intent.authentication.credential_reference
  return <>
    <dl className="cisco-metadata">
      <div><dt>{t('ciscoManagementVlan')}</dt><dd>{intent.management_vlan}</dd></div>
      <div><dt>{t('ciscoManagementIp')}</dt><dd>{intent.reachability.management_ip ?? t('ciscoNotAvailable')}</dd></div>
      <div><dt>{t('ciscoManagementDomain')}</dt><dd>{intent.management_domain ?? t('ciscoNotAvailable')}</dd></div>
      <div><dt>{t('ciscoManagementReachability')}</dt><dd>
        <Badge tone={managementTone(intent.reachability.status)}>{intent.reachability.status}</Badge>
        {intent.reachability.management_subnet && <span className="muted"> · {intent.reachability.management_subnet}</span>}
      </dd></div>
      <div><dt>{t('ciscoManagementSoftwareStatus')}</dt><dd>
        <Badge tone={managementTone(intent.software_validation_status)}>{intent.software_validation_status}</Badge>
        <span className="muted"> · {intent.validation_scope} · {t('ciscoManagementHardwareStatus')}: {intent.hardware_status}</span>
      </dd></div>
      <div><dt>{t('ciscoManagementSsh')}</dt><dd>
        <Badge tone={managementTone(intent.ssh_policy.status)}>{intent.ssh_policy.status}</Badge>
        <span className="muted"> · {t('ciscoManagementSshV2')} · {t('ciscoManagementTelnetOff')} · {t('ciscoManagementPlaintextOff')}</span>
      </dd></div>
      <div><dt>{t('ciscoManagementLocalAuth')}</dt><dd>
        <Badge tone={managementTone(intent.authentication.status)}>{intent.authentication.status}</Badge>
        <span className="muted"> · {intent.authentication.method}</span>
      </dd></div>
      <div><dt>{t('ciscoManagementAaa')}</dt><dd>
        <Badge tone={managementTone(intent.aaa.status)}>{intent.aaa.status}</Badge>
        <span className="muted"> · {intent.aaa.mode} · {t('ciscoManagementSecretNotAvailable')}</span>
      </dd></div>
      <div><dt>{t('ciscoManagementConsole')}</dt><dd>
        <Badge tone={managementTone(intent.console_recovery.status)}>{intent.console_recovery.status}</Badge>
        <span className="muted"> · {t('ciscoManagementConsoleNotExecuted')}</span>
      </dd></div>
      <div><dt>{t('ciscoManagementCredential')}</dt><dd>
        {credential.present ? t('ciscoManagementCredentialPresent') : t('ciscoManagementCredentialMissing')}
        {' · '}
        {credential.event_scoped ? t('ciscoManagementCredentialEventScoped') : t('ciscoManagementCredentialCrossEvent')}
        <span className="muted"> · {t('ciscoManagementSecretNotAvailable')} · {t('ciscoManagementProvider')}</span>
      </dd></div>
      <div><dt>{t('ciscoManagementEvidence')}</dt><dd>{t('ciscoManagementEvidencePending')} · <code>{intent.evidence_registry_id}</code></dd></div>
    </dl>
    <p className="cisco-partial-note" role="status">
      {t('ciscoManagementSafety')} {t('ciscoManagementCredentialMetadataOnly')}
    </p>
    <h3>{t('ciscoManagementCandidates')}</h3>
    <p className="cisco-table-hint muted">{t('ciscoManagementNoCli')}</p>
    <div className="table-region">
      <Table label={t('ciscoManagementCandidates')}>
        <thead><tr>
          <th scope="col">{t('ciscoManagementTopic')}</th>
          <th scope="col">{t('ciscoCandidateStatus')}</th>
          <th scope="col">{t('ciscoIndependentVerdict')}</th>
          <th scope="col">{t('ciscoManagementEvidenceReview')}</th>
          <th scope="col">{t('ciscoManagementSecretBearing')}</th>
          <th scope="col">{t('ciscoBlockingReasons')}</th>
        </tr></thead>
        <tbody>{review.report.candidates.map((candidate) => <tr key={candidate.candidate_id}>
          <th scope="row"><code>{candidate.topic}</code></th>
          <td>{candidate.status}</td>
          <td>{candidate.independent_verdict}</td>
          <td>{candidate.evidence_review_state}</td>
          <td>{candidate.secret_bearing ? t('ciscoValueYes') : t('ciscoValueNo')}</td>
          <td>{candidate.blocking_reasons.length
            ? candidate.blocking_reasons.map((reason) => <code className="cisco-reason" key={reason}>{reason}</code>)
            : <span className="muted">{t('ciscoNotAvailable')}</span>}</td>
        </tr>)}</tbody>
      </Table>
    </div>
    <h3>{t('ciscoManagementBlockers')}</h3>
    <ul className="cisco-assembly-list">{intent.reason_codes.map((reason) => <li key={reason}><code>{reason}</code></li>)}</ul>
  </>
}

function ManagementPanel({ view }: { view: ManagementView }) {
  const { t } = useMessages()
  if (view.kind === 'loading') return <Loading>{t('ciscoLoadingReview')}</Loading>
  if (view.kind === 'error') return <section className="panel cisco-error" aria-label={t('ciscoManagementTitle')} role="alert">
    <h2>{t('ciscoManagementTitle')}</h2>
    <p>{t(previewErrorKey(view.error))}</p>
    {view.error.reasonCode && <p><span className="muted">{t('ciscoReasonCode')}</span> <code>{view.error.reasonCode}</code></p>}
    {view.error.failures.map((failure) => <p key={failure}><code>{failure}</code></p>)}
  </section>
  if (view.kind === 'invalid') return <section className="panel cisco-error" aria-label={t('ciscoManagementTitle')} role="region">
    <h2>{t('ciscoManagementTitle')}</h2>
    <h3>{t('ciscoDataInconsistent')}</h3>
    <p>{t('ciscoDataInconsistentHelp')}</p>
    <ProblemList problems={view.problems} keys={{}} />
    {view.review && <ManagementFacts review={view.review} />}
  </section>
  return <section className="panel cisco-management" aria-label={t('ciscoManagementTitle')}>
    <div className="section-head">
      <h2>{t('ciscoManagementTitle')}</h2>
      <Badge tone={managementTone(view.review.intent.status)}>{view.review.intent.status}</Badge>
    </div>
    <p className="cisco-scope-note">{t('ciscoManagementScopeNote')}</p>
    <ManagementFacts review={view.review} />
  </section>
}

function AssemblyPanel({ view }: { view: AssemblyView }) {
  const { t } = useMessages()
  if (view.kind === 'loading') return <Loading>{t('ciscoLoadingReview')}</Loading>
  if (view.kind === 'error') return <section className="panel cisco-assembly cisco-error" aria-label={t('ciscoAssemblyTitle')} role="alert">
    <h2>{t('ciscoAssemblyTitle')}</h2>
    <p>{t(previewErrorKey(view.error))}</p>
    {view.error.reasonCode && <p><span className="muted">{t('ciscoReasonCode')}</span> <code>{view.error.reasonCode}</code></p>}
    {view.error.failures.map((failure) => <p key={failure}><code>{failure}</code></p>)}
  </section>
  if (view.kind === 'invalid') return <section className="panel cisco-assembly cisco-error" aria-label={t('ciscoAssemblyTitle')} role="region">
    <h2>{t('ciscoAssemblyTitle')}</h2>
    <h3>{t('ciscoDataInconsistent')}</h3>
    <p>{t('ciscoDataInconsistentHelp')}</p>
    <ProblemList
      problems={view.problems}
      keys={CONFIG_ASSEMBLY_PROBLEM_KEYS as Record<string, MessageKey>}
    />
    <h3>{t('ciscoAssemblyRestrictedTitle')}</h3>
    <p>{t('ciscoAssemblyRestrictedHelp')}</p>
    {view.assembly && <AssemblyRestrictedSummary assembly={view.assembly} />}
  </section>
  const a = view.assembly
  return <section className="panel cisco-assembly" aria-label={t('ciscoAssemblyTitle')}>
    <div className="section-head">
      <h2>{t('ciscoAssemblyTitle')}</h2>
      <Badge tone={assemblyStatusTone(a.completeness.status)}>
        {t(assemblyStatusKey(a.completeness.status))}
      </Badge>
    </div>
    <p className="cisco-scope-note">{t('ciscoAssemblyScopeNote')}</p>
    <p className={a.completeness.complete ? 'cisco-assembly-complete' : 'cisco-partial-note'} role="status">
      <strong>{a.completeness.complete ? t('ciscoAssemblyStatus') : t('ciscoAssemblyNotComplete')}</strong>{' '}
      {a.completeness.complete ? '' : t('ciscoAssemblyIncomplete')}
    </p>
    <dl className="cisco-counts">
      <div><dt>{t('ciscoAssemblyRequiredSections')}</dt><dd>{a.completeness.required_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyValidatedSections')}</dt><dd>{a.completeness.validated_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyPartialSections')}</dt><dd>{a.completeness.partial_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyBlockedSections')}</dt><dd>{a.completeness.blocked_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyNotImplementedSections')}</dt><dd>{a.completeness.not_implemented_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyNotApplicableSections')}</dt><dd>{a.completeness.not_applicable_sections}</dd></div>
    </dl>
    <p className="cisco-table-hint muted">{t('ciscoScrollTable')}</p>
    <div className="table-region">
      <Table label={t('ciscoAssemblySections')}>
        <thead><tr>
          <th scope="col">{t('ciscoAssemblySection')}</th>
          <th scope="col">{t('ciscoAssemblyRequired')}</th>
          <th scope="col">{t('ciscoAssemblyApplicability')}</th>
          <th scope="col">{t('ciscoAssemblyStatus')}</th>
          <th scope="col">{t('ciscoAssemblyCandidates')}</th>
          <th scope="col">{t('ciscoAssemblyPassed')}</th>
          <th scope="col">{t('ciscoAssemblyBlocked')}</th>
          <th scope="col">{t('ciscoAssemblyMissing')}</th>
          <th scope="col">{t('ciscoAssemblyReasons')}</th>
        </tr></thead>
        <tbody>{a.sections.map((section) => <tr key={section.section_id}>
          <th scope="row"><code>{section.section_id}</code></th>
          <td>{section.required ? t('ciscoAssemblyRequired') : t('ciscoAssemblyNotApplicable')}</td>
          <td><Badge tone={section.applicability === 'APPLICABLE' ? 'neutral' : 'warning'}>{section.applicability}</Badge></td>
          <td><Badge tone={assemblyStatusTone(section.status)}>{t(assemblyStatusKey(section.status))}</Badge></td>
          <td>{section.candidate_count}</td>
          <td>{section.passed_count}</td>
          <td>{section.blocked_count + section.failed_count}</td>
          <td>{section.missing_count}</td>
          <td>{section.reason_codes.length
            ? section.reason_codes.map((reason) => <code className="cisco-reason" key={reason}>{reason}</code>)
            : <span className="muted">{t('ciscoNotAvailable')}</span>}</td>
        </tr>)}</tbody>
      </Table>
    </div>

    <h3>{t('ciscoAssemblySection')} · {t('ciscoDetails')}</h3>
    <div className="cisco-assembly-chapters">
      {a.sections.map((section) => <details className="cisco-assembly-chapter" key={section.section_id}>
        <summary>
          <code>{section.section_id}</code>
          <Badge tone={assemblyStatusTone(section.status)}>{t(assemblyStatusKey(section.status))}</Badge>
          <span className="muted">{section.candidate_count} {t('ciscoAssemblyCandidates')}</span>
        </summary>
        <p className="cisco-assembly-chapter-note">{t('ciscoAssemblyChapterCommands')}</p>
        {section.candidates.some((candidate) => candidate.candidate_text)
          ? section.candidates.filter((candidate) => candidate.candidate_text).map((candidate) => <div key={candidate.candidate_id} className="cisco-assembly-command">
            <p><span className="muted">{candidate.category}</span> · <code>{candidate.target_name}</code></p>
            <pre className="cisco-command"><code>{candidate.candidate_text}</code></pre>
          </div>)
          : <p className="empty">{t('ciscoAssemblyNoCandidates')}</p>}
        {section.reason_codes.length > 0 && <ul className="cisco-assembly-list">
          {section.reason_codes.map((reason) => <li key={reason}><code>{reason}</code></li>)}
        </ul>}
      </details>)}
    </div>

    <h3>{t('ciscoAssemblyCrossChecks')}</h3>
    <p className="cisco-table-hint muted">{t('ciscoScrollTable')}</p>
    <div className="table-region">
      <Table label={t('ciscoAssemblyCrossChecks')}>
        <thead><tr>
          <th scope="col">{t('ciscoAssemblyCheck')}</th>
          <th scope="col">{t('ciscoAssemblyCheckStatus')}</th>
          <th scope="col">{t('ciscoAssemblyReasons')}</th>
          <th scope="col">{t('ciscoAssemblyCheckDetails')}</th>
        </tr></thead>
        <tbody>{a.cross_layer_checks.map((check) => <tr key={check.check_id}>
          <th scope="row"><code>{check.check_id}</code></th>
          <td><Badge tone={assemblyCheckTone(check.status)}>{check.status}</Badge></td>
          <td>{check.reason_codes.length
            ? check.reason_codes.map((reason) => <code className="cisco-reason" key={reason}>{reason}</code>)
            : <span className="muted">{t('ciscoNotAvailable')}</span>}</td>
          <td>{check.detail}</td>
        </tr>)}</tbody>
      </Table>
    </div>

    <div className="cisco-assembly-lists">
      <section aria-label={t('ciscoAssemblyMissingFeatures')}>
        <h3>{t('ciscoAssemblyMissingFeatures')}</h3>
        {a.completeness.missing_features.length
          ? <ul className="cisco-assembly-list">{a.completeness.missing_features.map((item) => <li key={item}><code>{item}</code></li>)}</ul>
          : <p className="empty">{t('ciscoNoCandidates')}</p>}
      </section>
      <section aria-label={t('ciscoAssemblyBlockers')}>
        <h3>{t('ciscoAssemblyBlockers')}</h3>
        {a.completeness.blockers.length
          ? <ul className="cisco-assembly-list">{a.completeness.blockers.map((item) => <li key={item}><code>{item}</code></li>)}</ul>
          : <p className="empty">{t('ciscoAssemblyNoBlockers')}</p>}
      </section>
    </div>

    <h3>{t('ciscoAssemblySourceFingerprints')}</h3>
    <dl className="cisco-source-grid cisco-assembly-source">
      <div><dt>{t('ciscoL2RenderFingerprint')}</dt><dd><code>{a.source.l2_render_fingerprint}</code></dd></div>
      <div><dt>{t('ciscoL2ReportFingerprint')}</dt><dd><code>{a.source.l2_validation_fingerprint}</code></dd></div>
      <div><dt>{t('ciscoL3RenderFingerprint')}</dt><dd><code>{a.source.l3_render_fingerprint}</code></dd></div>
      <div><dt>{t('ciscoL3ReportFingerprint')}</dt><dd><code>{a.source.l3_validation_fingerprint}</code></dd></div>
    </dl>
    <p className="cisco-source-note">{t('ciscoAssemblyFullConfigNote')} {t('ciscoAssemblyNoFullScript')}</p>
    <p className="cisco-source-note">{t('ciscoAssemblyHardwareNote')}</p>
  </section>
}

function AssemblyRestrictedSummary({ assembly }: { assembly: ConfigurationAssembly }) {
  const { t } = useMessages()
  const a = assembly
  return <>
    <p className="cisco-partial-note" role="status">
      <strong>{t('ciscoAssemblyNotComplete')}</strong> {t('ciscoAssemblyIncomplete')}
    </p>
    <dl className="cisco-counts">
      <div><dt>{t('ciscoAssemblyRequiredSections')}</dt><dd>{a.completeness.required_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyValidatedSections')}</dt><dd>{a.completeness.validated_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyPartialSections')}</dt><dd>{a.completeness.partial_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyBlockedSections')}</dt><dd>{a.completeness.blocked_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyNotImplementedSections')}</dt><dd>{a.completeness.not_implemented_sections}</dd></div>
      <div><dt>{t('ciscoAssemblyNotApplicableSections')}</dt><dd>{a.completeness.not_applicable_sections}</dd></div>
    </dl>
    <div className="table-region">
      <Table label={t('ciscoAssemblySections')}>
        <thead><tr>
          <th scope="col">{t('ciscoAssemblySection')}</th>
          <th scope="col">{t('ciscoAssemblyRequired')}</th>
          <th scope="col">{t('ciscoAssemblyApplicability')}</th>
          <th scope="col">{t('ciscoAssemblyStatus')}</th>
          <th scope="col">{t('ciscoAssemblyCandidates')}</th>
          <th scope="col">{t('ciscoAssemblyMissing')}</th>
        </tr></thead>
        <tbody>{a.sections.map((section) => <tr key={section.section_id}>
          <th scope="row"><code>{section.section_id}</code></th>
          <td>{section.required ? t('ciscoAssemblyRequired') : t('ciscoAssemblyNotApplicable')}</td>
          <td>{section.applicability}</td>
          <td><Badge tone={assemblyStatusTone(section.status)}>{t(assemblyStatusKey(section.status))}</Badge></td>
          <td>{section.candidate_count}</td>
          <td>{section.missing_count}</td>
        </tr>)}</tbody>
      </Table>
    </div>
    <h3>{t('ciscoAssemblyCrossChecks')}</h3>
    <div className="table-region">
      <Table label={t('ciscoAssemblyCrossChecks')}>
        <thead><tr>
          <th scope="col">{t('ciscoAssemblyCheck')}</th>
          <th scope="col">{t('ciscoAssemblyCheckStatus')}</th>
          <th scope="col">{t('ciscoAssemblyCheckDetails')}</th>
        </tr></thead>
        <tbody>{a.cross_layer_checks.map((check) => <tr key={check.check_id}>
          <th scope="row"><code>{check.check_id}</code></th>
          <td><Badge tone={assemblyCheckTone(check.status)}>{check.status}</Badge></td>
          <td>{check.detail}</td>
        </tr>)}</tbody>
      </Table>
    </div>
    <div className="cisco-assembly-lists">
      <section aria-label={t('ciscoAssemblyMissingFeatures')}>
        <h3>{t('ciscoAssemblyMissingFeatures')}</h3>
        {a.completeness.missing_features.length
          ? <ul className="cisco-assembly-list">{a.completeness.missing_features.map((item) => <li key={item}><code>{item}</code></li>)}</ul>
          : <p className="empty">{t('ciscoNoCandidates')}</p>}
      </section>
      <section aria-label={t('ciscoAssemblyBlockers')}>
        <h3>{t('ciscoAssemblyBlockers')}</h3>
        {a.completeness.blockers.length
          ? <ul className="cisco-assembly-list">{a.completeness.blockers.map((item) => <li key={item}><code>{item}</code></li>)}</ul>
          : <p className="empty">{t('ciscoAssemblyNoBlockers')}</p>}
      </section>
    </div>
    <p className="cisco-source-note">{t('ciscoAssemblyHardwareNote')}</p>
  </>
}

function SourcePanel({ l2, l3 }: { l2: L2View; l3: L3View }) {
  const { t } = useMessages()
  const l2Report = l2.kind === 'ready' ? l2.report : undefined
  const l3Report = l3.kind === 'ready' ? l3.report : undefined
  return <section className="panel cisco-source-panel" aria-label={t('ciscoSourceAndLimitations')}>
    <div className="section-head"><h2>{t('ciscoSourceAndLimitations')}</h2>
      <span className="muted">{t('ciscoCandidateOnly')}</span></div>
    <p className="cisco-footer-note">{t('ciscoFooterNote')}</p>
    <dl className="cisco-source-grid">
      {l2Report && <>
        <div><dt>{t('ciscoL2Registry')}</dt><dd><code>{l2Report.source.command_evidence_registry_id}</code></dd></div>
        <div><dt>{t('ciscoL2RegistryFingerprint')}</dt><dd><code>{l2Report.source.command_evidence_fingerprint}</code></dd></div>
        <div><dt>{t('ciscoL2RenderFingerprint')}</dt><dd><code>{l2Report.source.render_fingerprint}</code></dd></div>
        <div><dt>{t('ciscoL2ReportFingerprint')}</dt><dd><code>{l2Report.report_fingerprint}</code></dd></div>
      </>}
      {l3Report && <>
        <div><dt>{t('ciscoL3Registry')}</dt><dd><code>{l3Report.source.command_evidence_registry_id}</code></dd></div>
        <div><dt>{t('ciscoL3RegistryFingerprint')}</dt><dd><code>{l3Report.source.command_evidence_registry_fingerprint}</code></dd></div>
        <div><dt>{t('ciscoL3RenderFingerprint')}</dt><dd><code>{l3Report.source.l3_render_fingerprint}</code></dd></div>
        <div><dt>{t('ciscoL3ReportFingerprint')}</dt><dd><code>{l3Report.report_fingerprint}</code></dd></div>
      </>}
    </dl>
    <p className="cisco-source-note">{t('ciscoL2L3Independent')}</p>
    <p className="cisco-source-note">{t('ciscoLimitationsText')}</p>
  </section>
}
