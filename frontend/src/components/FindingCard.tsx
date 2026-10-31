import React, { useState } from 'react';
import {
  CheckCircle2,
  Copy,
  Check,
  Wrench,
  RotateCcw,
  FileCode2,
  AlertOctagon,
  ShieldCheck
} from 'lucide-react';
import { Finding } from '../services/api';
import { formatCategoryLabel, getRiskBadgeStyle } from '../utils/theme';

interface FindingCardProps {
  finding: Finding;
  resolvingId: string | null;
  copiedId: string | null;
  onResolveFinding: (findingId: string, actionLabel: string) => void;
  onCopyPatch: (id: string, patchText: string) => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({
  finding,
  resolvingId,
  copiedId,
  onResolveFinding,
  onCopyPatch
}) => {
  const isResolved = finding.status === 'RESOLVED';
  const [selectedAction, setSelectedAction] = useState('APPLIED_REMEDIATION_PATCH');

  return (
    <div
      className={`p-5 rounded-2xl border transition-all duration-300 ${
        isResolved
          ? 'bg-emerald-950/15 border-emerald-500/35 shadow-lg shadow-emerald-950/10'
          : 'bg-slate-900/85 border-slate-800 hover:border-slate-700 shadow-lg'
      }`}
    >
      {/* Top Row: Severity, Rule ID, File:Line & Interactive Resolve Controls */}
      <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
        <div className="space-y-1.5 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`px-2.5 py-0.5 rounded-full text-[11px] font-extrabold border ${
                isResolved
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                  : getRiskBadgeStyle(finding.severity)
              }`}
            >
              {isResolved ? 'RESOLVED & REMEDIATED' : finding.severity}
            </span>
            <span className="text-xs font-mono font-semibold text-indigo-300 bg-indigo-500/15 border border-indigo-500/25 px-2 py-0.5 rounded">
              {finding.rule_id}
            </span>
            <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {formatCategoryLabel(finding.category)}
            </span>
            <span className="text-xs font-mono text-slate-400 inline-flex items-center gap-1">
              <FileCode2 className="w-3.5 h-3.5 text-slate-500" />
              {finding.file}:{finding.line}
            </span>
          </div>

          <h4 className="text-base font-bold text-white pt-0.5">{finding.title}</h4>
          <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>
        </div>

        {/* Resolve Action Selector & Button */}
        <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
          {!isResolved && (
            <select
              value={selectedAction}
              onChange={e => setSelectedAction(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
            >
              <option value="APPLIED_REMEDIATION_PATCH">Apply Safe Patch</option>
              <option value="PINNED_SAFE_DEPENDENCY">Pin Safe Package Version</option>
              <option value="VERIFIED_SAFE_BY_MAINTAINER">Verified Safe by Maintainer</option>
            </select>
          )}

          <button
            onClick={() =>
              onResolveFinding(
                finding.id,
                isResolved ? 'REOPENED_ISSUE' : selectedAction
              )
            }
            disabled={resolvingId === finding.id}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 ${
              isResolved
                ? 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
                : 'bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-md shadow-emerald-600/20'
            }`}
          >
            {isResolved ? (
              <>
                <RotateCcw className="w-3.5 h-3.5" />
                Reopen Issue
              </>
            ) : (
              <>
                <Wrench className="w-3.5 h-3.5" />
                {resolvingId === finding.id ? 'Resolving...' : 'Resolve Issue & Apply Fix'}
              </>
            )}
          </button>
        </div>
      </div>

      {/* Bottom Row: Side-by-Side Suspicious Snippet vs. Recommended Safe Patch */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
        {/* Left: Flagged Suspicious Code */}
        <div className="p-3.5 rounded-xl bg-slate-950 border border-rose-500/25 space-y-2 flex flex-col justify-between">
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-rose-400">
              <span className="flex items-center gap-1.5">
                <AlertOctagon className="w-3.5 h-3.5" />
                Flagged Suspicious Evidence
              </span>
              <span className="font-mono text-slate-500">
                Line {finding.line}
              </span>
            </div>
            <pre className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-500/15 text-xs font-mono text-rose-200 overflow-x-auto whitespace-pre-wrap">
              {finding.snippet}
            </pre>
          </div>
          <div className="text-[11px] text-slate-500">
            Static/Dependency rule <code className="text-rose-300">{finding.rule_id}</code> matched this pattern without executing untrusted code.
          </div>
        </div>

        {/* Right: Suggested Remediation & Patch */}
        <div className="p-3.5 rounded-xl bg-slate-950 border border-emerald-500/25 space-y-2 flex flex-col justify-between">
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                Recommended Safe Remediation Patch
              </span>
              {finding.suggested_patch && (
                <button
                  onClick={() => onCopyPatch(finding.id, finding.suggested_patch)}
                  className="text-[11px] px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 flex items-center gap-1 transition"
                >
                  {copiedId === finding.id ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" /> Copied Patch
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" /> Copy Safe Patch
                    </>
                  )}
                </button>
              )}
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">{finding.remediation}</p>
            {finding.suggested_patch && (
              <pre className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                {finding.suggested_patch}
              </pre>
            )}
          </div>
          {isResolved && (
            <div className="text-[11px] text-emerald-400 font-semibold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Issue marked resolved — risk score dynamically updated.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
