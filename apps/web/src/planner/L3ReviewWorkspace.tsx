import { useEffect, useState } from 'react'
import type { EventRecord } from '../api'
import { Badge, Button, Loading, Select, Table } from '../components/ui'
import { useMessages } from '../locale'
import type { MessageKey } from '../messages'
import type { Revision, Summary } from './model'
import {
  candidateStatusKeys, canLoadCandidates, coreAssignments, fetchCandidates, fetchValidation,
  filterReviewRows, isAbort, isReviewedC9200Registry, isUnreviewedRegistry, listRevisions,
  overallKeys, parseReviewError, problemKeys, readRevision, reviewCategories, reviewErrorKey,
  reviewRows, validateDocument, validateReport, verdictKeys,
} from './l3Review'
import type {
  CoreAssignment, L3CandidateDocument, L3ValidationReport, ReviewBinding, ReviewError,
  ReviewProblem, ReviewRow,
} from './l3Review'

type Phase = 'boot' | 'loading-revisions' | 'loading-revision' | 'loading-validation' | 'loading-candidates' | 'ready'

export function L3ReviewWorkspace({ event, navigate }: { event: EventRecord; navigate: (route: string) => void }) {
  const { t } = useMessages()
  const [revisions, setRevisions] = useState<Summary[] | null>(null)
  const [revisionId, setRevisionId] = useState('')
  const [revision, setRevision] = useState<Revision | null>(null)
  const [cores, setCores] = useState<CoreAssignment[]>([])
  const [assignmentId, setAssignmentId] = useState('')
  const [report, setReport] = useState<L3ValidationReport | null>(null)
  const [document, setDocument] = useState<L3CandidateDocument | null>(null)
  const [problems, setProblems] = useState<ReviewProblem[]>([])
  const [reportProblems, setReportProblems] = useState(false)
  const [error, setError] = useState<ReviewError | null>(null)
  const [candidateError, setCandidateError] = useState<ReviewError | null>(null)
  const [phase, setPhase] = useState<Phase>('boot')
  const [bootAttempt, setBootAttempt] = useState(0)
  const [revisionAttempt, setRevisionAttempt] = useState(0)
  const [validationAttempt, setValidationAttempt] = useState(0)
  const [categoryFilter, setCategoryFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    setPhase('loading-revisions')
    setRevisions(null)
    setRevisionId('')
    setRevision(null)
    setCores([])
    setAssignmentId('')
    setReport(null)
    setDocument(null)
    setProblems([])
    setReportProblems(false)
    setError(null)
    setCandidateError(null)
    void listRevisions(event.id, controller.signal).then((entries) => {
      if (controller.signal.aborted) return
      setRevisions(entries)
      setRevisionId(entries.at(-1)?.id ?? '')
      setPhase(entries.length ? 'loading-revision' : 'ready')
    }, (failure: unknown) => {
      if (controller.signal.aborted || isAbort(failure)) return
      setError(parseReviewError(failure))
      setPhase('ready')
    })
    return () => controller.abort()
  }, [event.id, bootAttempt])

  useEffect(() => {
    if (!revisionId) return
    const controller = new AbortController()
    setPhase('loading-revision')
    setRevision(null)
    setCores([])
    setAssignmentId('')
    setReport(null)
    setDocument(null)
    setProblems([])
    setReportProblems(false)
    setError(null)
    setCandidateError(null)
    void readRevision(event.id, revisionId, controller.signal).then((detail) => {
      if (controller.signal.aborted) return
      const assignments = coreAssignments(detail.plan)
      setRevision(detail)
      setCores(assignments)
      setAssignmentId(assignments[0]?.assignmentId ?? '')
      setPhase(assignments.length ? 'loading-validation' : 'ready')
    }, (failure: unknown) => {
      if (controller.signal.aborted || isAbort(failure)) return
      setError(parseReviewError(failure))
      setPhase('ready')
    })
    return () => controller.abort()
  }, [event.id, revisionId, revisionAttempt])

  useEffect(() => {
    if (!revision || !assignmentId) return
    const controller = new AbortController()
    const binding: ReviewBinding = { eventId: event.id, revision, assignmentId }
    setPhase('loading-validation')
    setReport(null)
    setDocument(null)
    setProblems([])
    setReportProblems(false)
    setError(null)
    setCandidateError(null)
    setCategoryFilter('')
    setStatusFilter('')
    void (async () => {
      try {
        const checked = await fetchValidation(event.id, revision.id, assignmentId, controller.signal)
        if (controller.signal.aborted) return
        const found = validateReport(checked, binding)
        setReport(checked)
        setProblems(found)
        setReportProblems(found.length > 0)
        if (found.length || !canLoadCandidates(checked)) {
          setPhase('ready')
          return
        }
        setPhase('loading-candidates')
        try {
          const rendered = await fetchCandidates(event.id, revision.id, assignmentId, controller.signal)
          if (controller.signal.aborted) return
          const documentProblems = validateDocument(checked, rendered, binding)
          if (documentProblems.length) {
            setProblems(documentProblems)
            setReportProblems(true)
          } else {
            setDocument(rendered)
          }
        } catch (failure) {
          if (controller.signal.aborted || isAbort(failure)) return
          setCandidateError(parseReviewError(failure))
        }
        setPhase('ready')
      } catch (failure) {
        if (controller.signal.aborted || isAbort(failure)) return
        setError(parseReviewError(failure))
        setPhase('ready')
      }
    })()
    return () => controller.abort()
  }, [assignmentId, event.id, revision, validationAttempt])

  const selectedCore = cores.find((item) => item.assignmentId === assignmentId)
  const unreviewedRegistry = report !== null && !reportProblems && isUnreviewedRegistry(report)
  const reviewedC9200 = report !== null && !reportProblems && isReviewedC9200Registry(report)
  const rows = report && !reportProblems ? reviewRows(report, document) : []
  const filtered = filterReviewRows(rows, categoryFilter, statusFilter)
  const categories = reviewCategories(rows)
  const loading = phase.startsWith('loading')
  const statusFilterOptions = [...new Set(rows.map((row) => row.status ?? row.verdict))].sort()

  function retry() {
    if (!revisions || !revisionId) setBootAttempt((value) => value + 1)
    else if (!revision) setRevisionAttempt((value) => value + 1)
    else setValidationAttempt((value) => value + 1)
  }

  return <main id="main" className="shell screen l3-review">
    <div className="page-head">
      <div>
        <p className="breadcrumb">{event.name} <span aria-hidden="true">/</span> {t('l3Review')}</p>
        <h1>{t('l3Review')}</h1>
        <div className="status-strip">
          <Badge tone="neutral">{t('l3ReadOnly')}</Badge>
          <Badge tone="warning">{t('hardwareNotVerified')}</Badge>
          {report && <Badge tone={unreviewedRegistry ? 'warning' : 'success'}>
            {t(unreviewedRegistry ? 'l3ProductionScopeOnly' : 'l3ProductionScope')}
          </Badge>}
          {unreviewedRegistry && <Badge tone="warning">{t('l3UnreviewedRegistry')}</Badge>}
          {reviewedC9200 && <Badge tone="success">{t('l3C9200ReviewedEvidence')}</Badge>}
        </div>
      </div>
      <div className="actions">
        <Button onClick={() => navigate('planner/addressing')}>{t('l3BackToPlanner')}</Button>
        <Button onClick={retry} disabled={loading}>{t('l3Retry')}</Button>
      </div>
    </div>
    <p className="l3-scope-note" role="note">{t('l3SavedRevisionOnly')}</p>
    {unreviewedRegistry && <p className="l3-scope-note l3-unreviewed-note" role="note">
      {t('l3UnreviewedRegistryNote')}
    </p>}

    {phase === 'loading-revisions' && <Loading>{t('l3LoadingReview')}</Loading>}
    {revisions && revisions.length > 0 && <section className="panel l3-controls" aria-label={t('l3ReviewControls')}>
      <label className="field" htmlFor="l3-revision">{t('l3SelectRevision')}
        <Select id="l3-revision" value={revisionId} disabled={loading} onChange={(input) => setRevisionId(input.target.value)}>
          {revisions.map((item) => <option value={item.id} key={item.id}>#{item.number}: {item.content_hash.slice(0, 12)}</option>)}
        </Select>
      </label>
      <label className="field" htmlFor="l3-assignment">{t('l3SelectAssignment')}
        <Select id="l3-assignment" value={assignmentId} disabled={loading || !cores.length}
          onChange={(input) => setAssignmentId(input.target.value)}>
          {cores.length
            ? cores.map((item) => <option value={item.assignmentId} key={item.assignmentId}>{item.hostname}{item.pid ? ' (' + item.pid + ')' : ''}</option>)
            : <option value="">{t('l3NoCiscoCore')}</option>}
        </Select>
      </label>
    </section>}

    {phase === 'ready' && revisions !== null && revisions.length === 0 && <section className="panel l3-empty">
      <h2>{t('l3NoSavedRevisions')}</h2>
      <p>{t('l3NoSavedRevisionsHelp')}</p>
      <Button primary onClick={() => navigate('planner/addressing')}>{t('l3BackToPlanner')}</Button>
    </section>}

    {revision && <section className="panel l3-revision" aria-label={t('l3SavedRevision')}>
      <div className="section-head"><h2>{t('l3SavedRevision')} #{revision.number}</h2>
        <span className="muted">{t('l3RevisionReadOnly')}</span></div>
      <dl className="l3-metadata">
        <div><dt>{t('event')}</dt><dd>{event.name}</dd></div>
        <div><dt>{t('revision')}</dt><dd>#{revision.number}</dd></div>
        <div><dt>{t('revisionId')}</dt><dd><code>{revision.id}</code></dd></div>
        <div><dt>{t('l3RevisionHash')}</dt><dd><code>{revision.content_hash}</code></dd></div>
        <div><dt>{t('device')}</dt><dd>{report?.device.hostname ?? selectedCore?.hostname ?? t('l3NotAvailable')}</dd></div>
        <div><dt>{t('l3AssignmentId')}</dt><dd><code>{assignmentId || t('l3NotAvailable')}</code></dd></div>
        <div><dt>{t('l3ExactPid')}</dt><dd><code>{report?.device.exact_pid ?? selectedCore?.pid ?? t('l3NotAvailable')}</code></dd></div>
        <div><dt>{t('l3SoftwareImage')}</dt><dd>{report?.device.software_image ?? selectedCore?.image ?? t('l3NotAvailable')}</dd></div>
        <div><dt>{t('l3SoftwareLicense')}</dt><dd>{report?.device.software_license ?? selectedCore?.license ?? t('l3NotAvailable')}</dd></div>
        <div><dt>{t('l3StackIdentity')}</dt><dd>{report?.device.stack_identity ?? selectedCore?.stackIdentity ?? t('l3NotAvailable')}</dd></div>
        <div><dt>{t('l3HardwareVerification')}</dt><dd><Badge tone="warning">{t('hardwareNotVerified')}</Badge></dd></div>
      </dl>
    </section>}

    {(loading || phase === 'boot') && revisions !== null && revisionId && <Loading>
      {phase === 'loading-candidates' ? t('l3LoadingCandidates') : phase === 'loading-validation' ? t('l3LoadingValidation') : t('l3LoadingRevision')}
    </Loading>}

    {error && <section className="panel l3-error" role="alert">
      <h2>{t('l3LoadReviewError')}</h2>
      <p>{t(reviewErrorKey(error))}</p>
      {error.reasonCode && <p><span className="muted">{t('l3ReasonCode')}</span> <code>{error.reasonCode}</code></p>}
      <Button onClick={retry}>{t('l3Retry')}</Button>
    </section>}

    {revision && cores.length === 0 && <section className="panel l3-empty" role="status">
      <h2>{t('l3NoCiscoCore')}</h2>
      <p>{t('l3NoCiscoCoreHelp')}</p>
    </section>}

    {reportProblems && <section className="panel l3-error" role="alert">
      <h2>{t('l3DataInconsistent')}</h2>
      <p>{t('l3DataInconsistentHelp')}</p>
      <ul>{[...new Set(problems)].map((item) => <li key={item}>{t(problemKeys[item])} <code>{item}</code></li>)}</ul>
    </section>}

    {report && !reportProblems && <section className="panel l3-report" aria-label={t('l3ValidationReport')}>
      <div className="section-head">
        <h2>{t('l3ValidationReport')}</h2>
        <Badge tone={report.overall_status === 'pass' ? 'success' : report.overall_status === 'partial' ? 'warning' : 'danger'}>
          {t(overallKeys[report.overall_status])}
        </Badge>
      </div>
      <p className="muted">{t('l3ValidationScopeNote')}</p>
      <dl className="l3-counts">
        <div><dt>{t('l3Total')}</dt><dd>{report.summary.total}</dd></div>
        <div><dt>{t('l3Passed')}</dt><dd>{report.summary.passed}</dd></div>
        <div><dt>{t('l3Failed')}</dt><dd>{report.summary.failed}</dd></div>
        <div><dt>{t('l3Blocked')}</dt><dd>{report.summary.blocked}</dd></div>
        <div><dt>{t('l3NotRun')}</dt><dd>{report.summary.not_run}</dd></div>
        <div><dt>{t('l3BaseCategoriesPassed')}</dt><dd>{report.summary.base_categories_passed}</dd></div>
        <div><dt>{t('l3BaseCandidatesPassed')}</dt><dd>{report.summary.base_candidates_passed}</dd></div>
        <div><dt>{t('l3DhcpHelper')}</dt><dd>{report.summary.dhcp_helper_blocked
          ? <Badge tone="danger">{t('l3Blocked')}</Badge> : <Badge tone="neutral">{t('l3NotBlocked')}</Badge>}</dd></div>
      </dl>
      {report.overall_status !== 'pass' && <p className="l3-partial-note" role="status">{t('l3PartialIsNotPass')}</p>}
      {report.overall_status === 'fail' && <p className="feedback error-text" role="status">{t('l3ValidationFailedNote')}</p>}
    </section>}

    {report && !reportProblems && candidateError && <section className="panel l3-candidate-error" role="alert">
      <h2>{t('l3CandidateDocumentUnavailable')}</h2>
      <p>{t(reviewErrorKey(candidateError))}</p>
      {candidateError.reasonCode && <p><span className="muted">{t('l3ReasonCode')}</span> <code>{candidateError.reasonCode}</code></p>}
      <p className="muted">{t('l3CandidateDocumentUnavailableHint')}</p>
    </section>}

    {report && !reportProblems && !error && <section className="panel l3-candidate-section" aria-label={t('l3Candidates')}>
      <div className="section-head">
        <h2>{t('l3Candidates')} <span className="count">({rows.length})</span></h2>
        <span className="muted">{t('l3CandidateOnlyNote')}</span>
      </div>
      <div className="table-tools l3-filters">
        <label htmlFor="l3-category-filter">{t('l3CandidateFilterCategory')}
          <Select id="l3-category-filter" value={categoryFilter} onChange={(input) => setCategoryFilter(input.target.value)}>
            <option value="">{t('l3AllCategories')}</option>
            {categories.map((category) => <option value={category} key={category}>{category}</option>)}
          </Select>
        </label>
        <label htmlFor="l3-status-filter">{t('l3CandidateFilterStatus')}
          <Select id="l3-status-filter" value={statusFilter} onChange={(input) => setStatusFilter(input.target.value)}>
            <option value="">{t('l3AllStatuses')}</option>
            {statusFilterOptions.map((status) => <option value={status} key={status}>{statusLabel(t, status)}</option>)}
          </Select>
        </label>
      </div>
      {(categoryFilter || statusFilter) && <p className="l3-filter-note" role="status">{t('l3FilteredView')}</p>}
      {rows.length > 0 && <p className="l3-table-hint muted">{t('l3ScrollTable')}</p>}
      {!rows.length ? <p className="empty">{t('l3NoCandidates')}</p>
        : !filtered.length ? <p className="empty">{t('l3NoCandidatesMatchFilters')}</p>
          : <Table label={t('l3Candidates')}>
            <thead><tr>
              <th scope="col">{t('l3Category')}</th><th scope="col">{t('l3Target')}</th>
              <th scope="col">{t('l3CandidateStatus')}</th><th scope="col">{t('l3IndependentVerdict')}</th>
              <th scope="col">{t('l3RiskClass')}</th><th scope="col">{t('l3CapabilityVerdict')}</th>
              <th scope="col">{t('l3EvidenceReview')}</th><th scope="col">{t('l3BlockingReasons')}</th>
              <th scope="col">{t('l3CandidateId')}</th><th scope="col">{t('l3Details')}</th>
            </tr></thead><tbody>
              {filtered.map((row) => <tr key={row.candidateId}>
                <td>{row.category}</td>
                <td>{row.targetName}</td>
                <td>{row.status
                  ? <Badge tone={row.status === 'candidate' ? 'success' : row.status === 'blocked' ? 'danger' : 'warning'}>{t(candidateStatusKeys[row.status])}</Badge>
                  : <span className="muted">{t('l3NotAvailable')}</span>}</td>
                <td><Badge tone={row.verdict === 'pass' ? 'success' : row.verdict === 'blocked' || row.verdict === 'fail' ? 'danger' : 'warning'}>{t(verdictKeys[row.verdict])}</Badge></td>
                <td>{row.risk}</td><td>{row.capability ?? t('l3NotAvailable')}</td><td>{row.evidenceReview ?? t('l3NotAvailable')}</td>
                <td>{row.blockingReasons.length ? row.blockingReasons.map((reason) => <code className="l3-reason" key={reason}>{reason}</code>) : <span className="muted">{t('l3NotAvailable')}</span>}</td>
                <td><code>{row.candidateId}</code></td>
                <td><CandidateDetails row={row} /></td>
              </tr>)}
            </tbody>
          </Table>}
      {rows.some((row) => row.category === 'dhcp-helper-address' && row.status === 'blocked') &&
        <div className="l3-dhcp-blocked" role="note">
          <Badge tone="danger">{t('l3DhcpHelperBlocked')}</Badge>
          <p>{t('l3DhcpHelperBlockedDetail')}</p>
        </div>}
    </section>}
  </main>
}

function CandidateDetails({ row }: { row: ReviewRow }) {
  const { t } = useMessages()
  return <details className="l3-candidate-details">
    <summary>{t('l3Details')}</summary>
    <dl className="l3-details-list">
      <div><dt>{t('l3Target')}</dt><dd>{row.targetName} <span className="muted">({row.targetKind})</span></dd></div>
      <div><dt>{t('l3CandidateId')}</dt><dd><code>{row.candidateId}</code></dd></div>
      {row.commandContext && <>
        <div><dt>{t('l3CommandContext')}</dt><dd><code>{row.commandContext.mode_header}</code> · {row.commandContext.target_name}</dd></div>
        <div><dt>{t('l3CommandText')}</dt><dd><pre className="l3-command"><code>{row.text}</code></pre></dd></div>
      </>}
      <div><dt>{t('l3CandidateText')}</dt><dd>{row.text ? t('l3SingleCommandOnly') : t('l3CandidateTextUnavailable')}</dd></div>
      {row.blockingReasons.length > 0 && <div><dt>{t('l3BlockingReasons')}</dt><dd>{row.blockingReasons.map((reason) => <code className="l3-reason" key={reason}>{reason}</code>)}</dd></div>}
    </dl>
  </details>
}

function statusLabel(t: (key: MessageKey) => string, status: string) {
  const keys: Record<string, MessageKey> = {
    candidate: 'candidateStatusCandidate',
    unsupported: 'candidateStatusUnsupported',
    pass: 'verdictPass',
    fail: 'verdictFail',
    blocked: 'candidateStatusBlocked',
    'not-run': 'verdictNotRun',
  }
  const key = keys[status]
  return key ? t(key) : status
}
