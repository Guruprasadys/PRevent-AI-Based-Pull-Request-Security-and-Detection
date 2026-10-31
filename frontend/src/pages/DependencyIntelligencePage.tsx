import React, { useState } from 'react';
import {
  PackageSearch,
  ArrowRight,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Wrench,
  CheckCircle2,
  Layers,
  ListChecks,
  FileCode2
} from 'lucide-react';
import { DashboardSummary, ScanReport } from '../services/api';

interface DependencyIntelligencePageProps {
  summary: DashboardSummary | null;
  selectedScan: ScanReport | null;
  resolvingId: string | null;
  onRunTestCase: (tcId: string) => void;
  onResolveFinding: (findingId: string, actionLabel: string) => void;
}

const SUPPORTED_MANIFEST_FORMATS = [
  { format: 'package.json / package-lock.json', ecosystem: 'npm (Node.js)', checks: 'Lifecycle hooks, OpenSSF malicious versions, OSV CVEs, Levenshtein typosquats' },
  { format: 'requirements.txt / pyproject.toml / setup.py', ecosystem: 'PyPI (Python)', checks: 'Pinned version transitions, PyPI typosquats, custom install classes, OSV CVEs' },
  { format: 'pom.xml / build.gradle', ecosystem: 'Maven (Java)', checks: 'Group:Artifact:Version coordinates, Log4Shell & critical RCE advisories' },
  { format: 'go.mod / go.sum', ecosystem: 'Go Modules', checks: 'Module path & semantic version tag inspection against OSV advisories' },
  { format: 'Cargo.toml / Cargo.lock', ecosystem: 'Cargo (Rust)', checks: 'Crate version transitions & typosquatting edit-distance checks' },
  { format: 'Dockerfile / .github/workflows/*.yml', ecosystem: 'Container & CI/CD', checks: 'Untrusted base images, remote curl|sh bootstrap, workflow permissions' }
];

const DETECTION_PROCEDURE_STEPS = [
  {
    step: 'Step 1',
    title: 'Manifest Diff & Version Delta Extraction',
    desc: 'Parses unified git diffs (`-` removed vs `+` added lines) across 6 manifest formats to reconstruct `old_version → new_version` transitions.'
  },
  {
    step: 'Step 2',
    title: 'OpenSSF & Datadog Compromised Package Match',
    desc: 'Checks package name and exact version against documented supply-chain account-takeover and protestware incidents (`event-stream@3.3.6`, `ua-parser-js@0.7.29`, `node-ipc@10.1.1`).'
  },
  {
    step: 'Step 3',
    title: 'Levenshtein Edit-Distance Typosquatting Rule',
    desc: 'Computes character edit distance against top ecosystem libraries (`requests` vs `reqeusts`, `colorama` vs `colourama`, `axios` vs `axois`) to catch lookalike malware.'
  },
  {
    step: 'Step 4',
    title: 'OSV (Open Source Vulnerabilities) CVE Lookup',
    desc: 'Queries OSV vulnerability records to separate accidental use of a known vulnerable version (e.g. `pyyaml@5.3.1`, `log4j-core@2.14.1`) from deliberate malware.'
  },
  {
    step: 'Step 5',
    title: 'Install Script & Safe Version Remediation',
    desc: 'Audits `preinstall`/`postinstall` hooks for shell/network execution and generates a 1-click safe version pin patch.'
  }
];

export const DependencyIntelligencePage: React.FC<DependencyIntelligencePageProps> = ({
  summary,
  selectedScan,
  resolvingId,
  onRunTestCase,
  onResolveFinding
}) => {
  const [ecoFilter, setEcoFilter] = useState<string>('ALL');

  const allDeps = (summary?.recent_scans || []).flatMap(scan =>
    (scan.dependencies || []).map(dep => ({
      ...dep,
      repository: scan.repository,
      pr_number: scan.pr_number,
      scan_id: scan.scan_id
    }))
  );

  const filteredDeps = allDeps.filter(
    d => ecoFilter === 'ALL' || d.ecosystem.toLowerCase() === ecoFilter.toLowerCase()
  );

  const activePrDeps = selectedScan?.dependencies || [];
  const activeDepFindings = (selectedScan?.findings || []).filter(
    f => f.category === 'malicious_dependency' || f.category === 'vulnerable_dependency' || f.category === 'dangerous_install_script'
  );

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/95 via-slate-900/85 to-amber-950/20 border border-slate-800 flex flex-wrap items-center justify-between gap-4 shadow-xl">
        <div className="space-y-1">
          <h2 className="text-lg font-extrabold text-white flex items-center gap-2">
            <PackageSearch className="w-5 h-5 text-amber-400" />
            Supply-Chain Dependency Intelligence, Decision Factors & Precautions
          </h2>
          <p className="text-xs text-slate-400 max-w-2xl">
            Explains <strong>how</strong> the system identifies risky dependencies, <strong>which rules & factors</strong> led to the conclusion, and <strong>exact precautions & resolution steps</strong>.
          </p>
        </div>
        <button
          onClick={() => onRunTestCase('TC-002')}
          className="px-4 py-2 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/35 text-xs font-bold transition shadow"
        >
          Test Dependency Alert (TC-002)
        </button>
      </div>

      {/* 2. Currently Selected PR — Live Dependency Verdict, Decision Factors, Precautions & Resolution */}
      {selectedScan && (
        <div className="p-5 rounded-2xl bg-slate-900/85 border border-indigo-500/30 space-y-4 shadow-lg">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-indigo-400">
                Currently Active Pull Request Inspection
              </span>
              <h3 className="text-base font-bold text-white mt-0.5">
                {selectedScan.repository} #{selectedScan.pr_number} — {selectedScan.title}
              </h3>
            </div>
            {activeDepFindings.some(f => f.status === 'OPEN') && (
              <button
                onClick={() => onResolveFinding('ALL', 'PINNED_SAFE_DEPENDENCY')}
                disabled={resolvingId !== null}
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold flex items-center gap-1.5 shadow"
              >
                <Wrench className="w-3.5 h-3.5" />
                Resolve Dependency Issues & Pin Safe Version
              </button>
            )}
          </div>

          {activePrDeps.length === 0 ? (
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 flex items-center justify-between">
              <span>
                This Pull Request (<code className="text-indigo-300">{selectedScan.files.map(f => f.filename).join(', ')}</code>) modifies source code/workflows only and does not add or upgrade external package dependencies.
              </span>
              <span className="px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-300 font-bold">
                0 Dependency Changes
              </span>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {activePrDeps.map((dep, i) => (
                <div
                  key={i}
                  className={`p-4 rounded-xl border space-y-3 ${
                    dep.status === 'MALICIOUS'
                      ? 'bg-rose-950/15 border-rose-500/35'
                      : dep.status === 'VULNERABLE'
                      ? 'bg-amber-950/15 border-amber-500/35'
                      : 'bg-emerald-950/15 border-emerald-500/30'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-black text-white">{dep.package}</span>
                      <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-indigo-300 font-semibold">
                        {dep.manifest_format || dep.ecosystem}
                      </span>
                      <span className="font-mono text-xs bg-slate-950 px-2.5 py-0.5 rounded border border-slate-800 text-slate-300 inline-flex items-center gap-1.5">
                        {dep.old_version} <ArrowRight className="w-3 h-3 text-indigo-400" />{' '}
                        <strong className="text-white">{dep.new_version}</strong>
                      </span>
                    </div>
                    <span
                      className={`px-3 py-0.5 rounded-full text-xs font-extrabold border ${
                        dep.status === 'MALICIOUS'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : dep.status === 'VULNERABLE'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      }`}
                    >
                      Verdict: {dep.status}
                    </span>
                  </div>

                  {dep.detection_rule && (
                    <div className="text-xs font-mono text-indigo-300 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                      Triggered Rule: {dep.detection_rule}
                    </div>
                  )}

                  {/* 3-Column Explanation: Decision Factors | Precautions | Resolution Steps */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
                    <div className="p-3 rounded-xl bg-slate-950/90 border border-slate-800 space-y-1.5">
                      <div className="text-[11px] font-bold uppercase tracking-wider text-indigo-400">
                        1. Why Flagged (Decision Factors)
                      </div>
                      <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                        {(dep.decision_factors || []).map((f, idx) => (
                          <li key={idx}>{f}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-950/90 border border-slate-800 space-y-1.5">
                      <div className="text-[11px] font-bold uppercase tracking-wider text-amber-400">
                        2. Security Precautions & Alerts
                      </div>
                      <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                        {(dep.precautions || []).map((p, idx) => (
                          <li key={idx}>{p}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-950/90 border border-slate-800 space-y-1.5">
                      <div className="text-[11px] font-bold uppercase tracking-wider text-emerald-400">
                        3. How to Resolve the Problem
                      </div>
                      <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                        {(dep.resolution_steps || []).map((r, idx) => (
                          <li key={idx}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 3. How the System Identifies Dependency Threats (5-Step Rule Procedure) */}
      <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <ListChecks className="w-4 h-4 text-emerald-400" />
            5-Stage Dependency Identification Procedure & Rule Pipeline
          </h3>
          <span className="text-xs text-slate-400">
            Deterministic Supply-Chain Verification Protocol
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {DETECTION_PROCEDURE_STEPS.map((s, idx) => (
            <div
              key={idx}
              className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 flex flex-col justify-between"
            >
              <div className="space-y-1">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300">
                  {s.step}
                </span>
                <h4 className="text-xs font-bold text-white pt-1">{s.title}</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed">{s.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 4. Supported Multi-Ecosystem Scanning Formats */}
      <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-3">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <FileCode2 className="w-4 h-4 text-indigo-400" />
          Supported Multi-Ecosystem Manifest & Lockfile Scanning Formats
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {SUPPORTED_MANIFEST_FORMATS.map((mf, i) => (
            <div key={i} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-bold text-indigo-300">{mf.format}</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                  {mf.ecosystem}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">{mf.checks}</p>
            </div>
          ))}
        </div>
      </div>

      {/* 5. All Inspected Dependencies Across Recent PR Scans */}
      <div className="rounded-2xl bg-slate-900/75 border border-slate-800 overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-amber-400" />
              All Dependencies Inspected Across Scanned Pull Requests ({filteredDeps.length})
            </h3>
          </div>

          <div className="flex items-center gap-1.5">
            {['ALL', 'npm', 'PyPI', 'Maven', 'Go'].map(eco => (
              <button
                key={eco}
                onClick={() => setEcoFilter(eco)}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition ${
                  ecoFilter === eco
                    ? 'bg-indigo-600 text-white'
                    : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                }`}
              >
                {eco === 'ALL' ? 'All Ecosystems' : eco}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 bg-slate-950/60">
                <th className="py-3 px-4">Package & Ecosystem</th>
                <th className="py-3 px-4">Version Transition</th>
                <th className="py-3 px-4">Manifest Source</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Rule & Remediation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredDeps.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-10 px-4 text-center text-xs text-slate-400">
                    No dependency changes detected in scanned Pull Requests yet. Scan a GitHub PR that modifies package manifests (e.g., package.json, requirements.txt, pom.xml, go.mod, Cargo.toml) to inspect dependency intelligence.
                  </td>
                </tr>
              ) : (
                filteredDeps.map((dep, idx) => (
                <tr key={`${dep.scan_id}-${idx}`} className="hover:bg-slate-800/35">
                  <td className="py-3.5 px-4 font-mono font-bold text-white">
                    {dep.package}
                    <span className="ml-2 text-[10px] px-2 py-0.5 rounded bg-slate-800 text-indigo-300 font-sans">
                      {dep.ecosystem}
                    </span>
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="inline-flex items-center gap-2 font-mono text-xs bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800">
                      <span className="text-slate-400">{dep.old_version}</span>
                      <ArrowRight className="w-3.5 h-3.5 text-indigo-400" />
                      <span
                        className={`font-bold ${
                          dep.status === 'MALICIOUS'
                            ? 'text-rose-400'
                            : dep.status === 'VULNERABLE'
                            ? 'text-amber-300'
                            : 'text-emerald-400'
                        }`}
                      >
                        {dep.new_version}
                      </span>
                    </div>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-400">
                    {dep.file} ({dep.repository} #{dep.pr_number})
                  </td>
                  <td className="py-3.5 px-4">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-extrabold border inline-flex items-center gap-1 ${
                        dep.status === 'MALICIOUS'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : dep.status === 'VULNERABLE'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : dep.status === 'REMEDIATED'
                          ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      }`}
                    >
                      {dep.status === 'MALICIOUS' ? (
                        <ShieldAlert className="w-3 h-3" />
                      ) : dep.status === 'VULNERABLE' ? (
                        <AlertTriangle className="w-3 h-3" />
                      ) : (
                        <CheckCircle2 className="w-3 h-3" />
                      )}
                      {dep.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-xs text-slate-300">
                    <div className="font-semibold text-white">
                      {dep.detection_rule || 'Standard Manifest Verification'}
                    </div>
                    {dep.resolution_steps && dep.resolution_steps[0] && (
                      <div className="text-[11px] text-emerald-400 mt-0.5">
                        Action: {dep.resolution_steps[0]}
                      </div>
                    )}
                  </td>
                </tr>
              ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
