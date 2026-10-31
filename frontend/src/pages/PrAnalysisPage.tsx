import React from 'react';
import {
  Wrench,
  ShieldCheck,
  CheckCircle2,
  Cpu,
  History,
  Scale
} from 'lucide-react';
import { ScanReport, Finding } from '../services/api';
import { RiskGauge } from '../components/RiskGauge';
import { EvidenceGraph } from '../components/EvidenceGraph';
import { FindingCard } from '../components/FindingCard';
import { DiffViewer } from '../components/DiffViewer';

interface PrAnalysisPageProps {
  scan: ScanReport;
  resolvingId: string | null;
  copiedId: string | null;
  resolutionNote: string;
  setResolutionNote: (note: string) => void;
  onResolveFinding: (findingId: string, actionLabel: string) => void;
  onDecisionUpdate: (decision: string) => void;
  onCopyPatch: (id: string, text: string) => void;
  onExportJson: () => void;
  onOpenReportModal: () => void;
}

export const PrAnalysisPage: React.FC<PrAnalysisPageProps> = ({
  scan,
  resolvingId,
  copiedId,
  resolutionNote,
  setResolutionNote,
  onResolveFinding,
  onDecisionUpdate,
  onCopyPatch,
  onExportJson,
  onOpenReportModal
}) => {
  return (
    <div className="space-y-6">
      {/* 1. Top Radial Risk Score Gauge & Action Bar */}
      <RiskGauge
        scan={scan}
        resolvingId={resolvingId}
        onResolveAll={() => onResolveFinding('ALL', 'APPLIED_ALL_REMEDIATION_PATCHES')}
        onDecisionUpdate={onDecisionUpdate}
        onExportJson={onExportJson}
        onOpenReportModal={onOpenReportModal}
      />

      {/* 2. Transparent Risk Score Calculation & AI Heuristic Signal */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Scale className="w-4 h-4 text-indigo-400" />
              Transparent Risk Score Breakdown (Capped at 100)
            </h3>
            <span className="text-[11px] text-slate-400">
              Deduplicated by threat category · Decision-support evidence
            </span>
          </div>

          {scan.score_breakdown.length === 0 ? (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-300 text-xs flex items-center gap-2.5">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>
                <strong>0 active risk points.</strong> Either this Pull Request had no suspicious indicators or all flagged findings have been remediated and verified!
              </span>
            </div>
          ) : (
            <div className="space-y-2">
              {scan.score_breakdown.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-slate-950/85 border border-slate-800/90 flex items-center justify-between text-xs"
                >
                  <div>
                    <span className="font-bold text-indigo-300">{item.source}: </span>
                    <span className="text-slate-200">{item.title}</span>
                  </div>
                  <span className="px-2.5 py-0.5 rounded-full bg-rose-500/15 text-rose-300 border border-rose-500/30 font-mono font-bold shrink-0">
                    +{item.points} pts
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* AI Heuristic Classifier Verdict */}
        <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-3 flex flex-col justify-between">
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-indigo-400" />
                AI Pattern Signal
              </h3>
              <span
                className={`text-[11px] px-2.5 py-0.5 rounded-full font-bold border ${
                  scan.ml_prediction.flagged
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}
              >
                {scan.ml_prediction.flagged ? 'SUSPICIOUS DIFF' : 'BENIGN DIFF'}
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {scan.ml_prediction.explanation}
            </p>
          </div>

          <div className="pt-2 space-y-2 text-xs">
            <div className="flex justify-between text-slate-400">
              <span>AI Pattern Confidence:</span>
              <span className="font-mono font-bold text-white">
                {(scan.ml_prediction.ml_confidence_score * 100).toFixed(1)}%
              </span>
            </div>
            <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800">
              <div
                className={`h-full transition-all duration-500 ${
                  scan.ml_prediction.flagged ? 'bg-rose-500' : 'bg-emerald-500'
                }`}
                style={{
                  width: `${Math.min(100, Math.round(scan.ml_prediction.ml_confidence_score * 100))}%`
                }}
              />
            </div>
            <div className="grid grid-cols-2 gap-2 pt-1 text-[11px] text-slate-400">
              <div className="p-1.5 rounded bg-slate-950 border border-slate-800/80">
                Dangerous APIs: <strong className="text-white">{scan.features.dangerous_api_count}</strong>
              </div>
              <div className="p-1.5 rounded bg-slate-950 border border-slate-800/80">
                Network Calls: <strong className="text-white">{scan.features.network_activity_count}</strong>
              </div>
              <div className="p-1.5 rounded bg-slate-950 border border-slate-800/80">
                Secret Reads: <strong className="text-white">{scan.features.secret_access_count}</strong>
              </div>
              <div className="p-1.5 rounded bg-slate-950 border border-slate-800/80">
                Obfuscation: <strong className="text-white">{scan.features.obfuscation_indicators}</strong>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Interactive 4-Stage Evidence Graph */}
      <EvidenceGraph scan={scan} />

      {/* 4. Flagged Security Findings & Interactive "Resolve the Issue" Workbench */}
      <div className="space-y-4">
        <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Wrench className="w-4 h-4 text-emerald-400" />
              Security Findings & Interactive "Resolve the Issue" Workbench ({scan.findings.length})
            </h3>
            <p className="text-xs text-slate-400">
              Apply suggested remediation patches or mark verified findings resolved to dynamically recalculate the PR risk score.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Maintainer Audit Note:</span>
            <input
              type="text"
              value={resolutionNote}
              onChange={e => setResolutionNote(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-200 w-72 focus:outline-none focus:border-indigo-500"
            />
          </div>
        </div>

        {scan.findings.length === 0 ? (
          <div className="p-8 rounded-2xl bg-slate-900/50 border border-slate-800 text-center space-y-2">
            <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
            <h4 className="text-sm font-bold text-white">
              No Suspicious Static or Supply-Chain Dependency Findings Detected
            </h4>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              This Pull Request passed static AST/pattern rules, OSV vulnerability lookups, and malicious package checks without triggering any alerts.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {scan.findings.map((finding: Finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                resolvingId={resolvingId}
                copiedId={copiedId}
                onResolveFinding={onResolveFinding}
                onCopyPatch={onCopyPatch}
              />
            ))}
          </div>
        )}
      </div>

      {/* 5. Syntax-Highlighted Unified Diff Viewer */}
      <DiffViewer files={scan.files} findings={scan.findings} />

      {/* 6. Maintainer Resolution & Audit Trail */}
      {scan.resolution_log && scan.resolution_log.length > 0 && (
        <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <History className="w-4 h-4 text-emerald-400" />
            Maintainer Remediation & Audit Trail ({scan.resolution_log.length})
          </h3>
          <div className="space-y-2">
            {scan.resolution_log.map((log, i) => (
              <div
                key={i}
                className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between text-xs gap-2"
              >
                <div>
                  <span className="font-bold text-emerald-400">{log.action}</span> on{' '}
                  <span className="font-mono text-indigo-300">{log.finding_id}</span> —{' '}
                  <span className="text-slate-300">{log.note}</span>
                </div>
                <div className="text-slate-400 font-mono">
                  Recalculated Risk Score: <strong className="text-white">{log.new_risk_score}/100</strong>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
