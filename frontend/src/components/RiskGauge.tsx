import React from 'react';
import {
  Wrench,
  CheckCircle2,
  Download,
  MessageSquareCode,
  ShieldCheck,
  ShieldAlert,
  TrendingDown
} from 'lucide-react';
import { ScanReport } from '../services/api';
import { getRiskBadgeStyle, getScoreColor, getScoreStrokeColor } from '../utils/theme';

interface RiskGaugeProps {
  scan: ScanReport;
  resolvingId: string | null;
  onResolveAll: () => void;
  onDecisionUpdate: (decision: string) => void;
  onExportJson: () => void;
  onOpenReportModal: () => void;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  scan,
  resolvingId,
  onResolveAll,
  onDecisionUpdate,
  onExportJson,
  onOpenReportModal
}) => {
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.max(0, Math.min(100, scan.risk_score));
  const strokeDashoffset = circumference - (progress / 100) * circumference;
  const strokeColor = getScoreStrokeColor(scan.risk_score);
  const scoreReduced = scan.initial_risk_score > scan.risk_score;

  return (
    <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/95 via-slate-900/80 to-slate-950 border border-slate-800 shadow-xl flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
      {/* Left: PR Metadata & Recommended Action */}
      <div className="space-y-3 flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          {scan.scenario_badge && (
            <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
              {scan.scenario_badge}
            </span>
          )}
          <span className="text-xs font-mono px-2.5 py-0.5 rounded-md bg-slate-950 border border-slate-800 text-slate-300">
            {scan.repository} #{scan.pr_number}
          </span>
          <span className="text-xs text-slate-400">
            Author: <strong className="text-slate-200">@{scan.author}</strong>
          </span>
          <span
            className={`text-[11px] font-semibold px-2.5 py-0.5 rounded-md border ${
              scan.review_decision === 'REMEDIATED_AND_VERIFIED' ||
              scan.review_decision === 'APPROVED'
                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                : scan.review_decision === 'BLOCKED'
                ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                : 'bg-slate-800 text-slate-300 border-slate-700'
            }`}
          >
            Status: {scan.review_decision}
          </span>
        </div>

        <h2 className="text-xl sm:text-2xl font-extrabold text-white tracking-tight">
          {scan.title}
        </h2>

        <div
          className={`p-3.5 rounded-xl border text-xs flex items-start gap-3 ${
            scan.risk_score >= 50
              ? 'bg-rose-950/20 border-rose-500/30 text-rose-200'
              : scan.risk_score >= 25
              ? 'bg-amber-950/20 border-amber-500/30 text-amber-200'
              : 'bg-emerald-950/20 border-emerald-500/30 text-emerald-200'
          }`}
        >
          {scan.risk_score >= 25 ? (
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          ) : (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          )}
          <div>
            <span className="font-bold uppercase tracking-wider text-[11px] block mb-0.5">
              Recommended Decision-Support Action
            </span>
            <span className="text-slate-200 leading-relaxed">{scan.recommended_action}</span>
          </div>
        </div>
      </div>

      {/* Right: Radial SVG Gauge & Interactive Action Controls */}
      <div className="flex flex-wrap sm:flex-nowrap items-center gap-6 bg-slate-950/90 p-4 rounded-2xl border border-slate-800/90 w-full lg:w-auto justify-between sm:justify-start">
        {/* Radial SVG Gauge */}
        <div className="flex items-center gap-4">
          <div className="relative w-28 h-28 flex items-center justify-center shrink-0">
            <svg className="w-28 h-28 -rotate-90 transform" viewBox="0 0 108 108">
              <circle
                cx="54"
                cy="54"
                r={radius}
                stroke="#1e293b"
                strokeWidth="9"
                fill="transparent"
              />
              <circle
                cx="54"
                cy="54"
                r={radius}
                stroke={strokeColor}
                strokeWidth="9"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-700 ease-out"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className={`text-3xl font-black leading-none ${getScoreColor(scan.risk_score)}`}>
                {scan.risk_score}
              </span>
              <span className="text-[10px] text-slate-500 font-semibold mt-0.5">/ 100</span>
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
              Risk Verdict
            </div>
            <span
              className={`inline-block px-3 py-1 rounded-full text-xs font-extrabold border ${getRiskBadgeStyle(
                scan.risk_level
              )}`}
            >
              {scan.risk_level}
            </span>
            <div className="text-xs text-slate-400">{scan.risk_label}</div>
            {scoreReduced && (
              <div className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                <TrendingDown className="w-3 h-3" />
                Reduced from {scan.initial_risk_score}
              </div>
            )}
          </div>
        </div>

        {/* Maintainer Actions */}
        <div className="border-t sm:border-t-0 sm:border-l border-slate-800 pt-3 sm:pt-0 sm:pl-5 space-y-2.5 w-full sm:w-auto">
          {scan.open_findings_count > 0 ? (
            <button
              onClick={onResolveAll}
              disabled={resolvingId !== null}
              className="w-full px-4 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-emerald-600/20"
            >
              <Wrench className="w-3.5 h-3.5" />
              Resolve All Issues ({scan.open_findings_count})
            </button>
          ) : (
            <div className="px-3.5 py-2 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-bold flex items-center justify-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" />
              All Issues Resolved
            </div>
          )}

          <div className="grid grid-cols-2 gap-1.5">
            <button
              onClick={() => onDecisionUpdate('APPROVED')}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-emerald-950/60 text-emerald-400 border border-slate-800 hover:border-emerald-500/40 text-xs font-semibold transition"
            >
              Approve PR
            </button>
            <button
              onClick={() => onDecisionUpdate('BLOCKED')}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-rose-950/60 text-rose-400 border border-slate-800 hover:border-rose-500/40 text-xs font-semibold transition"
            >
              Block Merge
            </button>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={onOpenReportModal}
              className="flex-1 px-2.5 py-1.5 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-300 border border-indigo-500/30 text-[11px] font-semibold flex items-center justify-center gap-1.5 transition"
            >
              <MessageSquareCode className="w-3.5 h-3.5" />
              Bot Summary
            </button>
            <button
              onClick={onExportJson}
              title="Export Full JSON Security Report"
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-[11px] font-semibold flex items-center gap-1 transition"
            >
              <Download className="w-3.5 h-3.5" />
              JSON
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
