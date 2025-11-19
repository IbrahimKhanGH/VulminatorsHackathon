import { useEffect, useMemo, useState } from 'react';

const presets = [
  { value: 'fast', label: 'Fast (p/ci)' },
  { value: 'balanced', label: 'Balanced (security audit)' },
  { value: 'exhaustive', label: 'Exhaustive (OWASP top 10)' },
];

const defaultRepo = 'https://github.com/IbrahimKhanGH/finalDemo';
const stepStatusCopy = {
  pending: 'Pending',
  running: 'Agent at work…',
  done: 'Completed',
  failed: 'Failed',
  skipped: 'Skipped',
};

const severityRank = {
  critical: 5,
  high: 4,
  moderate: 3,
  medium: 3,
  low: 2,
  info: 1,
};

export default function App() {
  const backendBase = useMemo(
    () => import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000',
    []
  );

  const [repoUrl, setRepoUrl] = useState(defaultRepo);
  const [githubToken, setGithubToken] = useState('');
  const [preset, setPreset] = useState(presets[0].value);
  const [runId, setRunId] = useState('');
  const [status, setStatus] = useState('idle');
  const [message, setMessage] = useState('');
  const [findings, setFindings] = useState([]);
  const [prUrl, setPrUrl] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [pipelineSteps, setPipelineSteps] = useState([]);

  useEffect(() => {
    if (!runId) {
      return;
    }

    let cancelled = false;
    const poll = async () => {
      try {
        const response = await fetch(`${backendBase}/runs/${runId}`);
        if (!response.ok) {
          throw new Error('Failed to fetch run status');
        }
        const data = await response.json();
        if (cancelled) {
          return;
        }
        setStatus(data.status);
        setMessage(data.message || '');
        setFindings(data.findings || []);
        setPrUrl(data.pr_url || '');
        setPipelineSteps(data.steps || []);
      } catch (err) {
        console.error(err);
        if (!cancelled) {
          setError(err.message);
        }
      }
    };

    poll();
    const interval = setInterval(() => {
      if (status === 'completed' || status === 'failed') {
        return;
      }
      poll();
    }, 2500);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [backendBase, runId, status]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setMessage('');
    setFindings([]);
    setRunId('');
    setStatus('queued');
    setIsSubmitting(true);
    setPipelineSteps([]);

    try {
      const response = await fetch(`${backendBase}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: repoUrl,
          preset,
          run_ai_report: true,
          ...(githubToken.trim()
            ? { github_token: githubToken.trim() }
            : {}),
        }),
      });

      if (!response.ok) {
        throw new Error('Analyze request failed');
      }

      const data = await response.json();
      setRunId(data.run_id);
      setStatus(data.status);
      setMessage('Pipeline started…');
    } catch (err) {
      setError(err.message);
      setStatus('failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const canSubmit = repoUrl.length > 0 && !isSubmitting;

  const dependencyFindings = useMemo(
    () => findings.filter((finding) => finding.title?.startsWith('Upgraded')),
    [findings]
  );

  const refactorFindings = useMemo(
    () => findings.filter((finding) => finding.title?.startsWith('Refactor')),
    [findings]
  );

  const vulnFindings = useMemo(
    () =>
      findings.filter(
        (finding) =>
          !finding.title?.startsWith('Upgraded') &&
          !finding.title?.startsWith('Refactor')
      ),
    [findings]
  );

  const heroFinding = useMemo(() => {
    if (vulnFindings.length === 0) return null;
    return [...vulnFindings].sort((a, b) => {
      const aScore = severityRank[a.severity?.toLowerCase()] || 0;
      const bScore = severityRank[b.severity?.toLowerCase()] || 0;
      return bScore - aScore;
    })[0];
  }, [vulnFindings]);

  const activityLog = useMemo(() => {
    if (!message) return [];
    return message
      .split(';')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }, [message]);

  const isBusy = status === 'running' || status === 'queued';

  return (
    <main className="layout">
      <section className="panel">
        <header>
          <p className="eyebrow">Vulminator MVP</p>
          <h1>Scan any GitHub repo</h1>
          <p className="muted">
            Provide an HTTPS repo URL and optional GitHub token. The backend clones,
            runs Semgrep, and streams findings below.
          </p>
        </header>

        <form className="controls" onSubmit={handleSubmit}>
          <label>
            Repo URL
            <input
              type="url"
              value={repoUrl}
              onChange={(event) => setRepoUrl(event.target.value)}
              placeholder="https://github.com/org/repo"
              required
            />
          </label>

          <label>
            GitHub token (optional for public repos)
            <input
              type="password"
              value={githubToken}
              onChange={(event) => setGithubToken(event.target.value)}
              placeholder="ghp_..."
            />
          </label>

          <label>
            Scan preset
            <select value={preset} onChange={(event) => setPreset(event.target.value)}>
              {presets.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>

          <button type="submit" disabled={!canSubmit}>
            {isSubmitting ? 'Starting…' : 'Run analysis'}
          </button>
        </form>
      </section>

      <section className="panel results">
        <header>
          <p className="eyebrow">Run status</p>
          <h2>{runId ? `Run ${runId.slice(0, 8)}…` : 'Awaiting run'}</h2>
          <p className={`status status-${status}`}>{status}</p>
          {message && <p className="muted">{message}</p>}
          {error && <p className="error">{error}</p>}
          {prUrl && (
            <div className="pr-preview">
              <div>
                <p className="eyebrow">PR ready</p>
                <p className="muted">
                  {vulnFindings.length} findings · {dependencyFindings.length} upgrades
                </p>
              </div>
              <a className="pr-link" href={prUrl} target="_blank" rel="noreferrer">
                View PR ↗
              </a>
            </div>
          )}
        </header>

        {isBusy && (
          <div className="agent-animation">
            <div className="orb" />
            <p>Agent Vulminator is analyzing…</p>
          </div>
        )}

        {pipelineSteps.length > 0 && (
          <div className="agentic-timeline">
            {pipelineSteps.map((step) => (
              <div
                key={step.id}
                className={`agentic-step status-${step.status}`}
              >
                <div className="agentic-orb" />
                <div>
                  <p className="agentic-label">{step.label}</p>
                  <p className="agentic-sub">
                    {stepStatusCopy[step.status] || step.status}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}

        {activityLog.length > 0 && (
          <div className="agent-log">
            <p className="eyebrow">Agent log</p>
            <div className="log-stream">
              {activityLog.map((entry, index) => (
                <div key={`${entry}-${index}`} className="log-line">
                  <span className="log-dot" />
                  <p>{entry}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      {heroFinding && (
        <section className="panel hero">
          <p className="eyebrow">AI spotlight</p>
          <h2>{heroFinding.title}</h2>
          <div className="finding-meta">
            <span className={`badge badge-${heroFinding.severity?.toLowerCase()}`}>
              {heroFinding.severity?.toUpperCase()}
            </span>
            {heroFinding.file_path && (
              <span className="file">{heroFinding.file_path}</span>
            )}
          </div>
          <p>{heroFinding.summary}</p>
          {heroFinding.risk_brief && (
            <div className="ai-insight">
              <h4>AI risk brief</h4>
              <p>{heroFinding.risk_brief}</p>
            </div>
          )}
          {heroFinding.patch_suggestion && (
            <div className="ai-insight">
              <h4>AI patch idea</h4>
              <pre className="code-block diff">{heroFinding.patch_suggestion}</pre>
            </div>
          )}
        </section>
      )}

      {dependencyFindings.length > 0 && (
        <section className="panel secondary">
          <p className="eyebrow">Dependency actions</p>
          <h2>Auto-upgraded packages</h2>
          <div className="findings compact">
            {dependencyFindings.map((finding, index) => (
              <article key={`${finding.title}-${index}`} className="finding-card">
                <div className="finding-meta">
                  <span className="badge badge-info">INFO</span>
                  {finding.file_path && <span className="file">{finding.file_path}</span>}
                </div>
                <h3>{finding.title}</h3>
                <p>{finding.summary}</p>
                {finding.risk_brief && (
                  <div className="ai-insight">
                    <h4>AI risk brief</h4>
                    <p>{finding.risk_brief}</p>
                  </div>
                )}
                {finding.patch_suggestion && (
                  <div className="ai-insight">
                    <h4>AI patch idea</h4>
                    <pre className="code-block diff">{finding.patch_suggestion}</pre>
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      )}

      {refactorFindings.length > 0 && (
        <section className="panel secondary">
          <p className="eyebrow">AI refactor attempts</p>
          <h2>Commentary drops</h2>
          <div className="findings compact">
            {refactorFindings.map((finding, index) => (
              <article key={`${finding.title}-${index}`} className="finding-card">
                <div className="finding-meta">
                  <span
                    className={`badge badge-${
                      finding.severity?.toLowerCase() === 'info' ? 'info' : 'warning'
                    }`}
                  >
                    {finding.severity?.toUpperCase() || 'INFO'}
                  </span>
                  {finding.file_path && <span className="file">{finding.file_path}</span>}
                </div>
                <h3>{finding.title}</h3>
                <p>{finding.summary}</p>
                {finding.risk_brief && (
                  <div className="ai-insight">
                    <h4>AI risk brief</h4>
                    <p>{finding.risk_brief}</p>
                  </div>
                )}
                {finding.patch_suggestion && (
                  <div className="ai-insight">
                    <h4>AI patch idea</h4>
                    <pre className="code-block diff">{finding.patch_suggestion}</pre>
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="panel">
        <p className="eyebrow">Findings</p>
        <h2>Vulnerabilities & warnings</h2>
        <div className="findings">
          {vulnFindings.length === 0 && (
            <div className="empty-state">No findings yet — run a scan.</div>
          )}

          {vulnFindings.map((finding, index) => (
            <article key={`${finding.title}-${index}`} className="finding-card">
              <div className="finding-meta">
                <span className={`badge badge-${finding.severity?.toLowerCase()}`}>
                  {finding.severity?.toUpperCase() || 'INFO'}
                </span>
                {finding.file_path && <span className="file">{finding.file_path}</span>}
              </div>
              <h3>{finding.title}</h3>
              <p>{finding.summary}</p>
              {finding.risk_brief && (
                <div className="ai-insight">
                  <h4>AI risk brief</h4>
                  <p>{finding.risk_brief}</p>
                </div>
              )}
              {finding.patch_suggestion && (
                <div className="ai-insight">
                  <h4>AI patch idea</h4>
                  <pre className="code-block diff">{finding.patch_suggestion}</pre>
                </div>
              )}
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
