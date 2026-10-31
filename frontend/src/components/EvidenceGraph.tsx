import React from 'react';
import {
  FileCode2,
  Cpu,
  ShieldAlert,
  ShieldCheck,
  PackageSearch,
  ArrowRight,
  Network
} from 'lucide-react';
import { ScanReport } from '../services/api';
import { formatCategoryLabel, getScoreColor } from '../utils/theme';

interface EvidenceGraphProps {
  scan: ScanReport;
}

export const EvidenceGraph: React.FC<EvidenceGraphProps> = ({ scan }) => {
  const staticCount = scan.findings.filter(f => !f.rule_id.startsWith('DEP-')).length;
  const depAlertsCount = scan.findings.filter(f => f.rule_id.startsWith('DEP-')).length;

  return (
    <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Network className="w-4 h-4 text-indigo-400" />
            Interactive Evidence Graph & Attack-Chain Correlation
          </h3>
          <p className="text-xs text-slate-400">
            Traces how modified files and dependency manifests trigger static rules, OSV advisories, and AI signals.
          </p>
        </div>
        <span className="text-[11px] px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 font-mono">
          {scan.files.length} Files → 3 Hybrid Engines → {scan.findings.length} Findings
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-stretch">
        {/* Stage 1: Changed Files */}
        <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800/90 flex flex-col justify-between space-y-2.5">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-indigo-400">
              <span>1. PR Changed Files</span>
              <FileCode2 className="w-3.5 h-3.5" />
            </div>
            <div className="space-y-1.5">
              {scan.files.map((f, idx) => (
                <div
                  key={idx}
                  className="p-2 rounded-lg bg-slate-900/90 border border-slate-800/80 text-xs flex items-center justify-between gap-2"
                >
                  <span className="font-mono text-slate-200 truncate" title={f.filename}>
                    {f.filename}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 shrink-0">
                    +{f.additions}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="text-[11px] text-slate-500 flex items-center justify-between pt-2 border-t border-slate-900">
            <span>Total Added Lines</span>
            <span className="font-mono text-slate-300">{scan.features.total_added_lines}</span>
          </div>
        </div>

        {/* Stage 2: Hybrid Detection Modules */}
        <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800/90 flex flex-col justify-between space-y-2.5">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-violet-400">
              <span>2. Hybrid Engines</span>
              <Cpu className="w-3.5 h-3.5" />
            </div>
            <div className="space-y-1.5">
              <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-xs flex items-center justify-between">
                <span className="text-slate-300">Static AST & Rules</span>
                <span
                  className={`font-mono font-bold ${
                    staticCount > 0 ? 'text-rose-400' : 'text-emerald-400'
                  }`}
                >
                  {staticCount} hit{staticCount === 1 ? '' : 's'}
                </span>
              </div>
              <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-xs flex items-center justify-between">
                <span className="text-slate-300">OSV & OpenSSF DB</span>
                <span
                  className={`font-mono font-bold ${
                    depAlertsCount > 0 ? 'text-amber-400' : 'text-emerald-400'
                  }`}
                >
                  {depAlertsCount} alert{depAlertsCount === 1 ? '' : 's'}
                </span>
              </div>
              <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-xs flex items-center justify-between">
                <span className="text-slate-300">AI Pattern Classifier</span>
                <span
                  className={`font-mono font-bold ${
                    scan.ml_prediction.flagged ? 'text-rose-400' : 'text-emerald-400'
                  }`}
                >
                  {(scan.ml_prediction.ml_confidence_score * 100).toFixed(0)}%
                </span>
              </div>
            </div>
          </div>
          <div className="text-[11px] text-slate-500 flex items-center justify-between pt-2 border-t border-slate-900">
            <span>Packages Checked</span>
            <span className="font-mono text-slate-300">{scan.dependencies.length}</span>
          </div>
        </div>

        {/* Stage 3: Correlated Threat Categories */}
        <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800/90 flex flex-col justify-between space-y-2.5">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-amber-400">
              <span>3. Threat Categories</span>
              <PackageSearch className="w-3.5 h-3.5" />
            </div>
            {scan.findings.length === 0 ? (
              <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-emerald-300 text-xs flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 shrink-0" />
                <span>Zero threat vectors triggered</span>
              </div>
            ) : (
              <div className="space-y-1.5">
                {Array.from(new Set(scan.findings.map(f => f.category))).map((cat, i) => (
                  <div
                    key={i}
                    className="p-2 rounded-lg bg-rose-950/20 border border-rose-500/25 text-xs text-rose-200 flex items-center gap-1.5"
                  >
                    <ArrowRight className="w-3 h-3 text-rose-400 shrink-0" />
                    <span className="truncate">{formatCategoryLabel(cat)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="text-[11px] text-slate-500 flex items-center justify-between pt-2 border-t border-slate-900">
            <span>Open / Resolved</span>
            <span className="font-mono text-slate-300">
              {scan.open_findings_count} / {scan.resolved_findings_count}
            </span>
          </div>
        </div>

        {/* Stage 4: Repository Impact & Blast Radius */}
        <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800/90 flex flex-col justify-between space-y-2.5">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-rose-400">
              <span>4. Blast Radius</span>
              <ShieldAlert className="w-3.5 h-3.5" />
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {scan.risk_score >= 75
                ? 'Critical impact: Potential exfiltration of CI/runtime secrets or remote code execution during package installation.'
                : scan.risk_score >= 50
                ? 'High impact: Suspicious dynamic execution, obfuscated payload, or elevated GitHub Actions workflow permissions.'
                : scan.risk_score >= 25
                ? 'Moderate impact: Known package vulnerability or unusual build pattern requiring maintainer verification.'
                : 'Low impact: Changes follow safe coding patterns with no active supply-chain or credential theft indicators.'}
            </p>
          </div>
          <div className="pt-2 border-t border-slate-900 flex items-center justify-between text-xs">
            <span className="text-slate-400">Final Risk Score</span>
            <span className={`font-black font-mono ${getScoreColor(scan.risk_score)}`}>
              {scan.risk_score} / 100 ({scan.risk_level})
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
