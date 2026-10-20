import { useRef, useState, type DragEvent, type ChangeEvent, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  Check,
  ChevronRight,
  CircleHelp,
  FileArchive,
  FileCheck2,
  FileCode2,
  LoaderCircle,
  RotateCcw,
  ShieldCheck,
  Upload,
  X,
} from 'lucide-react';
import { useHealthCheck, useScanProject } from '@workspace/api-client-react';
import {
  Route,
  Switch,
  useLocation,
  Router as WouterRouter,
} from 'wouter';

const queryClient = new QueryClient();

type ScanResult = NonNullable<ReturnType<typeof useScanProject>['data']>;
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
      }).format(date);
}

function markdownReport(scan: ScanResult) {
  const lines = [
    `# DeployCheck report`,
    ``,
    `- **Archive:** ${scan.archive_name}`,
    `- **Scanned:** ${formatDate(scan.scanned_at)}`,
    `- **Scan ID:** \`${scan.scan_id}\``,
    `- **Files scanned:** ${scan.files_scanned}`,
    `- **Files skipped:** ${scan.files_skipped}`,
    `- **Environment references checked:** ${scan.environment_references_checked}`,
    `- **Environment declarations available:** ${scan.environment_declarations_available ? 'Yes' : 'No'}`,
    ``,
    `> DeployCheck is static analysis, not a security certification. Findings are potential issues, not proof of compromise.`,
    ``,
    `## Severity summary`,
    ``,
    ...severities.map((severity) => `- **${severity}:** ${scan.severity_counts[severity]}`),
    ``,
    `## Findings`,
    ``,
  ];

  if (scan.findings.length === 0) lines.push(`No findings were returned for this archive.`, ``);
  scan.findings.forEach((finding, index) => {
    lines.push(
      `### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`,
      ``,
      `- **Rule:** \`${finding.rule_id}\``,
      `- **Location:** \`${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ''}\``,
      ``,
      finding.message,
      ``,
      `**Evidence**`,
      ``,
      `> ${finding.evidence.replace(/\n/g, '\n> ')}`,
      ``,
      `**Recommendation**`,
      ``,
      finding.recommendation,
      ``,
    );
  });
  if (scan.limitations.length > 0) {
    lines.push(`## Limitations`, ``);
    scan.limitations.forEach((limitation) => lines.push(`- ${limitation}`));
  }
  return lines.join('\n');
}

function Home() {
  const health = useHealthCheck();
  const scan = useScanProject();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [validationError, setValidationError] = useState('');

  const isAvailable = health.data?.status?.toLowerCase() === 'ok' || health.data?.status?.toLowerCase() === 'healthy';
  const filteredFindings = result?.findings.filter((finding) => filter === 'all' || finding.severity === filter) ?? [];

  function acceptFile(candidate?: File) {
    if (!candidate) return;
    if (!candidate.name.toLowerCase().endsWith('.zip')) {
      setValidationError('Choose a .zip archive to continue.');
      setFile(null);
      return;
    }
    setValidationError('');
    setFile(candidate);
    setResult(null);
    setFilter('all');
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    acceptFile(event.target.files?.[0]);
    event.target.value = '';
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    acceptFile(event.dataTransfer.files?.[0]);
  }

  function runScan() {
    if (!file || scan.isPending) return;
    setResult(null);
    setValidationError('');
    scan.mutate(
      { data: { archive: file } },
      {
        onSuccess: (response) => {
          setResult(response);
          setFilter('all');
        },
      },
    );
  }

  function downloadReport() {
    if (!result) return;
    const blob = new Blob([markdownReport(result)], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${result.archive_name.replace(/\.zip$/i, '')}-deploycheck-report.md`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="DeployCheck home" data-testid="link-brand">
          <span className="brand-mark"><ShieldCheck size={20} strokeWidth={2.1} /></span>
          <span>deploy<span className="brand-light">check</span></span>
        </a>
        <div className="topbar-meta">
          <span className={`api-pill ${health.isError ? 'api-offline' : isAvailable ? 'api-online' : 'api-pending'}`} data-testid="status-api">
            <span className="status-dot" />
            {health.isLoading ? 'Checking API' : health.isError ? 'API unavailable' : isAvailable ? 'API operational' : `API ${health.data?.status ?? 'checking'}`}
          </span>
          <span className="topbar-divider" />
          <span className="tool-version">STATIC ANALYSIS <span>·</span> V1</span>
        </div>
      </header>

      <div className="workspace">
        <section className="intro">
          <div className="eyebrow"><span className="eyebrow-rule" /> RELEASE READINESS / ONE PASS</div>
          <h1>A clearer view<br />before <span>you ship.</span></h1>
          <p className="intro-copy">Check a project archive for common deployment risks. Get the evidence, understand the limits, and decide what goes live.</p>
          <div className="confidence-note">
            <CircleHelp size={15} />
            <span>Findings are signals to review — not proof of compromise.</span>
          </div>
        </section>

        <section className="scan-panel" aria-labelledby="scan-title">
          <div className="panel-heading">
            <div className="step-index">01</div>
            <div>
              <div className="section-kicker">START WITH AN ARCHIVE</div>
              <h2 id="scan-title">Run a project check</h2>
            </div>
          </div>
          <div
            className={`dropzone ${dragging ? 'dropzone-active' : ''} ${file ? 'dropzone-file' : ''}`}
            onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node)) setDragging(false); }}
            onDrop={onDrop}
            data-testid="dropzone-archive"
          >
            <input
              ref={inputRef}
              className="visually-hidden"
              type="file"
              accept=".zip,application/zip,application/x-zip-compressed"
              onChange={onFileChange}
              aria-label="Choose project ZIP archive"
              data-testid="input-archive"
            />
            {file ? (
              <div className="selected-file">
                <span className="file-icon"><FileArchive size={21} /></span>
                <div className="file-meta">
                  <strong data-testid="text-selected-file">{file.name}</strong>
                  <span>{formatBytes(file.size)} <span className="file-dot">·</span> ZIP archive</span>
                </div>
                <button className="icon-button remove-file" onClick={() => { setFile(null); setValidationError(''); }} aria-label="Remove selected archive" data-testid="button-remove-file"><X size={16} /></button>
              </div>
            ) : (
              <div className="upload-prompt">
                <div className="upload-icon"><Upload size={21} /></div>
                <div className="upload-copy">
                  <strong>Drop your project ZIP here</strong>
                  <span>or <button className="text-button" type="button" onClick={() => inputRef.current?.click()} data-testid="button-browse">browse files</button></span>
                </div>
                <span className="zip-stamp">.ZIP</span>
              </div>
            )}
          </div>
          {validationError && <p className="inline-error" role="alert" data-testid="text-upload-error"><AlertTriangle size={14} />{validationError}</p>}
          {scan.isError && <p className="inline-error api-error" role="alert" data-testid="text-scan-error"><AlertTriangle size={14} />{(scan.error as Error)?.message || 'The scan could not be completed. Try again.'}</p>}
          <div className="scan-actions">
            <div className="privacy-caption"><FileCode2 size={15} /><span>Inspects supported files only.<br />Project code is never executed.</span></div>
            <button className="primary-button" onClick={runScan} disabled={!file || scan.isPending} data-testid="button-run-scan">
              {scan.isPending ? <><LoaderCircle className="spin" size={16} /> Scanning archive</> : <><span>Run scan</span><ChevronRight size={17} /></>}
            </button>
          </div>
          {scan.isPending && (
            <div className="scan-progress" role="status" data-testid="status-scanning">
              <div className="progress-track"><span /></div>
              <span>Reading archive and checking supported files…</span>
            </div>
          )}
        </section>

        <section className="scope-strip" aria-label="Scan scope">
          <div className="scope-title"><span className="scope-led" /> WHAT THIS PASS COVERS</div>
          <div className="scope-item"><Check size={14} /><span>Configuration &amp; source patterns</span></div>
          <div className="scope-item"><Check size={14} /><span>Environment references</span></div>
          <div className="scope-item scope-limit"><X size={14} /><span>Runtime behavior</span></div>
        </section>

        {result ? (
          <section className="results" aria-labelledby="results-title">
            <div className="results-topline">
              <div className="panel-heading result-heading">
                <div className="step-index">02</div>
                <div><div className="section-kicker">SCAN COMPLETE <span className="scan-id">/ {result.scan_id}</span></div><h2 id="results-title">Review the signals</h2></div>
              </div>
              <button className="export-button" onClick={downloadReport} data-testid="button-export-report"><ArrowDownToLine size={16} /> Export Markdown</button>
            </div>
            <div className="result-summary">
              <div className="summary-file"><FileCheck2 size={17} /><span>{result.archive_name}</span></div>
              <span className="summary-separator">/</span><span>Scanned {formatDate(result.scanned_at)}</span>
              <span className="summary-separator">/</span><span>{result.files_scanned} files inspected</span>
              <span className="summary-separator">/</span><span>{result.files_skipped} skipped</span>
            </div>
            <div className="metric-row" aria-label="Finding totals">
              {severities.map((severity) => (
                <button className={`severity-metric ${severity} ${filter === severity ? 'metric-selected' : ''}`} key={severity} onClick={() => setFilter(filter === severity ? 'all' : severity)} aria-pressed={filter === severity} data-testid={`filter-severity-${severity}`}>
                  <span className="metric-count">{result.severity_counts[severity]}</span>
                  <span className="metric-label">{severity}</span>
                </button>
              ))}
              <button className={`severity-metric all-metric ${filter === 'all' ? 'metric-selected' : ''}`} onClick={() => setFilter('all')} aria-pressed={filter === 'all'} data-testid="filter-severity-all">
                <span className="metric-count">{result.findings.length}</span>
                <span className="metric-label">all findings</span>
              </button>
            </div>
            <div className="analysis-facts">
              <div><span className="fact-label">ENVIRONMENT REFERENCES</span><strong>{result.environment_references_checked}</strong><span>checked</span></div>
              <div><span className="fact-label">DECLARATIONS</span><strong>{result.environment_declarations_available ? 'Found' : 'Not found'}</strong><span>in archive</span></div>
              <div><span className="fact-label">SCAN COVERAGE</span><strong>{result.files_scanned} <small>inspected</small></strong><span>{result.files_skipped} unsupported or skipped</span></div>
            </div>
            {!result.environment_declarations_available && (
              <div className="coverage-note" data-testid="status-env-declarations"><CircleHelp size={15} /><span>No environment declarations were available in this archive. Reference checks may be incomplete.</span></div>
            )}
            <div className="findings-header">
              <div><h3>Findings</h3><span>{filter === 'all' ? `${result.findings.length} potential ${result.findings.length === 1 ? 'issue' : 'issues'}` : `${filteredFindings.length} ${filter} ${filteredFindings.length === 1 ? 'finding' : 'findings'}`}</span></div>
              {filter !== 'all' && <button className="clear-filter" onClick={() => setFilter('all')} data-testid="button-clear-filter">Clear filter <X size={13} /></button>}
            </div>
            {filteredFindings.length > 0 ? (
              <div className="finding-list">
                {filteredFindings.map((finding, index) => (
                  <article className={`finding-card severity-border-${finding.severity}`} key={`${finding.rule_id}-${finding.file_path}-${finding.line_number}-${index}`} data-testid={`finding-${index}`}>
                    <div className="finding-top">
                      <span className={`severity-badge ${finding.severity}`}>{finding.severity}</span>
                      <code className="rule-id">{finding.rule_id}</code>
                      <span className="finding-location"><FileCode2 size={13} />{finding.file_path}{finding.line_number ? <span className="line-number">:{finding.line_number}</span> : ''}</span>
                    </div>
                    <h4>{finding.title}</h4>
                    <p className="finding-message">{finding.message}</p>
                    {finding.evidence && <div className="evidence-block"><span className="detail-label">EVIDENCE</span><pre>{finding.evidence}</pre></div>}
                    {finding.recommendation && <div className="recommendation-block"><span className="detail-label">RECOMMENDED NEXT STEP</span><p>{finding.recommendation}</p></div>}
                  </article>
                ))}
              </div>
            ) : (
              <div className="empty-findings" data-testid="empty-findings">
                <span className="empty-icon">{filter === 'all' ? <ShieldCheck size={22} /> : <Check size={20} />}</span>
                <div><strong>{filter === 'all' ? 'No findings returned' : `No ${filter} findings`}</strong><p>{filter === 'all' ? 'No potential issues were returned for the supported files in this archive.' : 'This severity is clear in the current scan.'}</p></div>
              </div>
            )}
            {result.limitations.length > 0 && (
              <details className="limitations" data-testid="details-limitations">
                <summary><span><CircleHelp size={15} /> Scan limitations <span className="limitations-count">{result.limitations.length}</span></span><ChevronRight size={16} className="limitations-chevron" /></summary>
                <ul>{result.limitations.map((limitation, index) => <li key={`${index}-${limitation}`}>{limitation}</li>)}</ul>
              </details>
            )}
            <div className="disclaimer"><ShieldCheck size={16} /><p><strong>A sanity pass, not a security certification.</strong> This static analysis checks supported files and known patterns; it cannot prove that a project is safe or detect every issue. Review the evidence in context before release.</p></div>
            <div className="results-footer"><span>SCAN ID <code>{result.scan_id}</code></span><button className="text-button rerun-button" onClick={() => { setFile(null); setResult(null); setFilter('all'); scan.reset(); window.scrollTo({ top: 0, behavior: 'smooth' }); }} data-testid="button-new-scan"><RotateCcw size={14} /> Start another scan</button></div>
          </section>
        ) : (
          <section className="waiting-state" aria-live="polite" data-testid="empty-scan">
            <div className="waiting-symbol"><Activity size={19} /></div>
            <div><strong>Your scan will appear here</strong><p>Choose a ZIP above to inspect supported project files.</p></div>
            <div className="waiting-index">02 <span>RESULTS</span></div>
          </section>
        )}

        <footer className="page-footer">
          <span><span className="footer-mark">D/</span> DEPLOYCHECK</span>
          <span>Know what was checked. Know what wasn’t.</span>
        </footer>
      </div>
    </main>
  );
}

function Router() {
  return (
    // Keep a shared shell (sidebar, navbar) outside the boundary so it
    // survives a page crash.
    <RoutedErrorBoundary>
      <Switch>
        <Route path="/" component={Home} />
        <Route component={NotFound} />
      </Switch>
    </RoutedErrorBoundary>
  );
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
