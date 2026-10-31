import React from 'react';
import {
  Cpu,
  CheckCircle2,
  Sparkles,
  ShieldAlert,
  Binary,
  Layers,
  HelpCircle,
  BookCheck,
  FileCode2
} from 'lucide-react';
import { DashboardSummary, ScanReport } from '../services/api';

interface AiEnginePageProps {
  summary: DashboardSummary | null;
  selectedScan: ScanReport | null;
}

const JURY_MODULES_EXPLANATION = [
  {
    module: 'Module 1: Static AST & Pattern Rule Engine (`ruleEngine.js`)',
    toolType: 'Deterministic Static Code Analysis (Semgrep / AST Inspired)',
    howItWorks:
      'Scans added diff lines without executing code. Correlates credential reads (`os.environ`, `process.env`, `.ssh/id_rsa`, `.npmrc`) with outbound network calls (`requests.post`, `fetch`, `webhook.site`), flags `eval`/`exec`/`base64`/`zlib`/`marshal` obfuscation, and audits `.github/workflows` permissions.',
    precaution: 'Never run untrusted PR code in a privileged environment before static rules pass.'
  },
  {
    module: 'Module 2: Supply-Chain Dependency Scanner (`dependencyScanner.js`)',
    toolType: 'OSV REST API + OpenSSF Registry + Levenshtein Distance',
    howItWorks:
      'Parses `package.json`, `requirements.txt`, `pyproject.toml`, `pom.xml`, `go.mod`, and `Cargo.toml`. Checks exact versions against OpenSSF/Datadog malicious packages, runs Levenshtein edit-distance = 1 typosquatting detection, and queries OSV for CVEs.',
    precaution: 'Use `npm ci --ignore-scripts` in CI sandboxes and pin exact safe versions in lockfiles.'
  },
  {
    module: 'Module 3: In-Memory TF-IDF + L2 Logistic Regression (`mlDetector.js`)',
    toolType: 'Statistical NLP & Machine Learning Classifier',
    howItWorks:
      'Converts unified code diffs into a TF-IDF vector of word unigrams, word bigrams, and 5 high-signal domain security indicator tokens, then evaluates 12 security vector checks and per-file suspicion scores via L2-regularized Logistic Regression.',
    precaution: 'Used as a supporting signal (+15 pts max) alongside deterministic evidence to minimize false positives.'
  },
  {
    module: 'Module 4: Transparent Risk & Remediation Engine (`riskEngine.js`)',
    toolType: 'Deduplicated Evidence Scoring & Dynamic Recalculation',
    howItWorks:
      'Combines deduplicated category weights (Secret Exfil +35, Malicious Dep +40, Vulnerable Dep +30, Install Script +30, Obfuscation +25, Workflow +20, AI Signal +15) capped at 100, and dynamically recalculates down to 0 when issues are resolved.',
    precaution: 'Always require human maintainer sign-off and audit trail logging when resolving critical findings.'
  }
];

const DEFAULT_PENDING_CHECKS = [
  { id: 'AI-CHK-01', check_name: 'Environment & Secret Harvesting Analysis', category: 'secret_exfiltration' },
  { id: 'AI-CHK-02', check_name: 'Outbound Network & Webhook Exfiltration Check', category: 'network_exfiltration' },
  { id: 'AI-CHK-03', check_name: 'Base64 & Hexadecimal Payload Obfuscation Check', category: 'obfuscated_execution' },
  { id: 'AI-CHK-04', check_name: 'Dynamic Code Execution (eval / exec / Function) Check', category: 'obfuscated_execution' },
  { id: 'AI-CHK-05', check_name: 'Compressed Bytecode & Deserialization Backdoor Check', category: 'obfuscated_execution' },
  { id: 'AI-CHK-06', check_name: 'Package Install Hook (preinstall / postinstall / setup.py) Check', category: 'dangerous_install_script' },
  { id: 'AI-CHK-07', check_name: 'OpenSSF & Datadog Compromised Package Registry Check', category: 'malicious_dependency' },
  { id: 'AI-CHK-08', check_name: 'Levenshtein Edit-Distance Typosquatting Check', category: 'malicious_dependency' },
  { id: 'AI-CHK-09', check_name: 'OSV Real-Time CVE & Vulnerable Version Check', category: 'vulnerable_dependency' },
  { id: 'AI-CHK-10', check_name: 'CI/CD GitHub Actions Workflow Privilege & Secret Check', category: 'ci_workflow_tampering' },
  { id: 'AI-CHK-11', check_name: 'SSH Private Key & .npmrc Registry Token Theft Check', category: 'secret_exfiltration' },
  { id: 'AI-CHK-12', check_name: 'Hidden Shell & Encoded PowerShell Execution Check', category: 'obfuscated_execution' }
];

export const AiEnginePage: React.FC<AiEnginePageProps> = ({ summary, selectedScan }) => {
  const metrics = summary?.ml_metrics;
  if (!metrics) return null;

  const liveChecks = selectedScan?.ml_prediction?.ai_checks || [];
  const filePredictions = selectedScan?.ml_prediction?.file_predictions || [];
  const flaggedChecksCount = liveChecks.filter(c => c.predicted_label === 1).length;
  const benignChecksCount = liveChecks.filter(c => c.predicted_label === 0).length;
  const flaggedFilesCount = filePredictions.filter(f => f.predicted_label === 1).length;

  return (
    <div className="space-y-6">
      {/* 1. Header Card */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/95 via-slate-900/85 to-indigo-950/25 border border-slate-800 space-y-2 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg font-extrabold text-white flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-400" />
            AI & Hybrid Security Engine — Live Pull Request Vector Classification
          </h2>
          <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-bold">
            Dynamic 12-Point PR Check Matrix ({metrics.vocabulary_size} TF-IDF Dimensions)
          </span>
        </div>
        <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
          Whenever you scan a Pull Request, the <strong className="text-slate-200">{metrics.model_name}</strong> automatically evaluates the PR across <strong>12 security threat vectors</strong> and classifies every modified file in the PR as <strong>Malicious (1)</strong> or <strong>Benign (0)</strong>.
        </p>
      </div>

      {/* 2. Live Scanned PR KPI Cards & Feature Extraction Breakdown */}
      {selectedScan ? (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                Scanned PR AI Verdict
              </div>
              <div
                className={`text-2xl font-black mt-1 ${
                  selectedScan.ml_prediction.flagged ? 'text-rose-400' : 'text-emerald-400'
                }`}
              >
                {selectedScan.ml_prediction.flagged ? 'Malicious (1)' : 'Benign (0)'}
              </div>
              <div className="text-xs text-slate-400 mt-1">
                Suspicion Score: {(selectedScan.ml_prediction.ml_confidence_score * 100).toFixed(1)}%
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                12-Point Vector Checks
              </div>
              <div className="text-2xl font-black text-indigo-400 mt-1">
                {flaggedChecksCount} Flagged / {benignChecksCount} Benign
              </div>
              <div className="text-xs text-slate-400 mt-1">
                Evaluated on {selectedScan.repository} #{selectedScan.pr_number}
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                PR Files Classified
              </div>
              <div className="text-2xl font-black text-white mt-1">
                {flaggedFilesCount} Flagged / {filePredictions.length} Total
              </div>
              <div className="text-xs text-slate-400 mt-1">
                +{selectedScan.features.total_added_lines} added lines inspected
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                PR Composite Risk Score
              </div>
              <div className="text-2xl font-black text-amber-400 mt-1">
                {selectedScan.risk_score} / 100 ({selectedScan.risk_level})
              </div>
              <div className="text-xs text-slate-400 mt-1">
                {selectedScan.open_findings_count} open findings · {selectedScan.resolved_findings_count} resolved
              </div>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/85 border border-indigo-500/30 space-y-3 shadow-lg">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <span className="text-[11px] font-bold uppercase tracking-wider text-indigo-400">
                  Active Pull Request Structural Feature Vector
                </span>
                <h3 className="text-sm font-bold text-white">
                  {selectedScan.repository} #{selectedScan.pr_number} — {selectedScan.title}
                </h3>
              </div>
              <span
                className={`px-3 py-1 rounded-full text-xs font-extrabold border ${
                  selectedScan.ml_prediction.flagged
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}
              >
                AI Suspicion: {(selectedScan.ml_prediction.ml_confidence_score * 100).toFixed(1)}% (
                {selectedScan.ml_prediction.flagged ? 'MALICIOUS (1)' : 'BENIGN (0)'})
              </span>
            </div>
            <p className="text-xs text-slate-300">{selectedScan.ml_prediction.explanation}</p>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 pt-1 text-xs">
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-400">File Formats</div>
                <div className="font-mono font-bold text-indigo-300 truncate">
                  {selectedScan.features.changed_file_types.join(', ') || 'none'}
                </div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-400">Dangerous APIs</div>
                <div className="font-mono font-bold text-white">
                  {selectedScan.features.dangerous_api_count}
                </div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-400">Secret Reads</div>
                <div className="font-mono font-bold text-white">
                  {selectedScan.features.secret_access_count}
                </div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-400">Outbound Network</div>
                <div className="font-mono font-bold text-white">
                  {selectedScan.features.network_activity_count}
                </div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-400">Obfuscation</div>
                <div className="font-mono font-bold text-white">
                  {selectedScan.features.obfuscation_indicators}
                </div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-400">Workflow Change</div>
                <div className="font-mono font-bold text-white">
                  {selectedScan.features.workflow_permission_change ? 'Yes (Risky)' : 'No'}
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 text-center space-y-2">
          <h3 className="text-sm font-bold text-white">
            No Pull Request Scanned Yet — 12-Point AI Security Matrix Ready
          </h3>
          <p className="text-xs text-slate-400 max-w-xl mx-auto">
            Paste any GitHub Pull Request URL or click "Use & Scan" on a live open PR in the Security Dashboard. All 12 AI Security Checks below will automatically execute on your scanned PR and classify each check as Malicious (1) or Benign (0).
          </p>
        </div>
      )}

      {/* 3. Live 12-Point AI Security Check Matrix on Scanned Pull Request */}
      <div className="rounded-2xl bg-slate-900/75 border border-slate-800 overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-emerald-400" />
              {selectedScan
                ? `Live 12-Point AI Security Check Results for ${selectedScan.repository} #${selectedScan.pr_number}`
                : '12-Point AI Security Check Matrix (Evaluated Automatically on Every Scanned PR)'}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Automatically checks the scanned PR across 12 supply-chain & code threat vectors and determines whether each vector is Malicious (1) or Benign (0).
            </p>
          </div>
          {selectedScan && (
            <span className="text-xs text-indigo-300 font-semibold flex items-center gap-1">
              <Sparkles className="w-3.5 h-3.5" /> Live PR Evaluation
            </span>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 bg-slate-950/60">
                <th className="py-3 px-4">Check ID</th>
                <th className="py-3 px-4">AI Security Check Vector</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Live Evidence Extracted from Scanned PR</th>
                <th className="py-3 px-4">AI Prediction</th>
                <th className="py-3 px-4">Suspicion Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {(liveChecks.length > 0 ? liveChecks : DEFAULT_PENDING_CHECKS).map((item: any) => (
                <tr key={item.id} className="hover:bg-slate-800/35">
                  <td className="py-3 px-4 font-mono text-xs text-indigo-300 font-bold">{item.id}</td>
                  <td className="py-3 px-4 text-xs text-white font-semibold">{item.check_name}</td>
                  <td className="py-3 px-4 text-xs text-slate-400 font-mono">{item.category}</td>
                  <td className="py-3 px-4 text-xs font-mono text-slate-300 max-w-md truncate">
                    {selectedScan ? item.evidence : 'Waiting for PR scan...'}
                  </td>
                  <td className="py-3 px-4 text-xs">
                    {!selectedScan ? (
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-semibold">
                        Pending Scan
                      </span>
                    ) : (
                      <span
                        className={`px-2.5 py-0.5 rounded font-bold inline-flex items-center gap-1 ${
                          item.predicted_label === 1
                            ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {item.predicted_label === 1 ? (
                          <ShieldAlert className="w-3 h-3" />
                        ) : (
                          <CheckCircle2 className="w-3 h-3" />
                        )}
                        {item.predicted_label === 1 ? 'Malicious (1)' : 'Benign (0)'}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-slate-200 font-bold">
                    {!selectedScan ? '—' : `${(item.suspicion_score * 100).toFixed(1)}%`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. Per-File AI Classification Table for the Scanned PR */}
      {selectedScan && filePredictions.length > 0 && (
        <div className="rounded-2xl bg-slate-900/75 border border-slate-800 overflow-hidden shadow-lg">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileCode2 className="w-4 h-4 text-indigo-400" />
              Per-File AI Classification in {selectedScan.repository} #{selectedScan.pr_number} ({filePredictions.length} Files)
            </h3>
            <span className="text-xs text-slate-400">Individual File Diff Scoring</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 bg-slate-950/60">
                  <th className="py-3 px-4">Changed File in PR</th>
                  <th className="py-3 px-4">Detected Ecosystem / Type</th>
                  <th className="py-3 px-4">Diff Lines</th>
                  <th className="py-3 px-4">File AI Verdict</th>
                  <th className="py-3 px-4">File Suspicion Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filePredictions.map((fp, idx) => (
                  <tr key={`${fp.filename}-${idx}`} className="hover:bg-slate-800/35">
                    <td className="py-3 px-4 font-mono text-xs text-white font-bold">{fp.filename}</td>
                    <td className="py-3 px-4 font-mono text-xs text-indigo-300">{fp.file_type}</td>
                    <td className="py-3 px-4 font-mono text-xs">
                      <span className="text-emerald-400">+{fp.additions}</span>{' '}
                      <span className="text-rose-400">-{fp.deletions}</span>
                    </td>
                    <td className="py-3 px-4 text-xs">
                      <span
                        className={`px-2.5 py-0.5 rounded font-bold inline-flex items-center gap-1 ${
                          fp.predicted_label === 1
                            ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {fp.predicted_label === 1 ? (
                          <ShieldAlert className="w-3 h-3" />
                        ) : (
                          <CheckCircle2 className="w-3 h-3" />
                        )}
                        {fp.predicted_label === 1 ? 'Malicious (1)' : 'Benign (0)'}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-200 font-bold">
                      {(fp.suspicion_score * 100).toFixed(1)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 5. Jury Q&A Guide: Which Tools & Modules Are Used for Scanning? */}
      <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <HelpCircle className="w-4 h-4 text-amber-400" />
            Jury Technical Breakdown: Which Modules & Algorithms Power PRevent?
          </h3>
          <span className="text-xs text-slate-400">4-Module Hybrid Architecture</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {JURY_MODULES_EXPLANATION.map((m, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 flex flex-col justify-between"
            >
              <div className="space-y-1.5">
                <div className="text-xs font-bold text-indigo-300">{m.module}</div>
                <div className="text-[11px] font-semibold text-amber-300">
                  Technique: {m.toolType}
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">{m.howItWorks}</p>
              </div>
              <div className="pt-2 border-t border-slate-900 text-[11px] text-emerald-400 flex items-center gap-1.5">
                <BookCheck className="w-3.5 h-3.5 shrink-0" />
                <span>Precaution: {m.precaution}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
