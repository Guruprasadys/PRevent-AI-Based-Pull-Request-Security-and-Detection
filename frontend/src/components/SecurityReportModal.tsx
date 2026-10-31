import React from 'react';
import { X, Copy, Check, Download, ShieldAlert } from 'lucide-react';
import { ScanReport } from '../services/api';
import { buildGithubBotComment, getRiskBadgeStyle } from '../utils/theme';

interface SecurityReportModalProps {
  scan: ScanReport | null;
  isOpen: boolean;
  onClose: () => void;
  copiedId: string | null;
  onCopy: (id: string, text: string) => void;
  onExportJson: () => void;
}

export const SecurityReportModal: React.FC<SecurityReportModalProps> = ({
  scan,
  isOpen,
  onClose,
  copiedId,
  onCopy,
  onExportJson
}) => {
  if (!isOpen || !scan) return null;

  const botMarkdown = buildGithubBotComment(scan);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-3xl w-full max-h-[88vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-indigo-400" />
            <div>
              <h3 className="text-base font-bold text-white">
                GitHub PR Bot Security Comment & Executive Summary
              </h3>
              <p className="text-xs text-slate-400">
                Ready to paste into GitHub PR #{scan.pr_number} or export for security audit records
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-4 flex-1">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-xs text-slate-400">Pull Request Target</div>
              <div className="text-sm font-bold text-white">
                {scan.repository} #{scan.pr_number} — {scan.title}
              </div>
            </div>
            <span
              className={`px-3 py-1 rounded-full text-xs font-extrabold border ${getRiskBadgeStyle(
                scan.risk_level
              )}`}
            >
              Score: {scan.risk_score}/100 ({scan.risk_level})
            </span>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Generated Markdown Comment for GitHub Actions Bot
              </span>
              <button
                onClick={() => onCopy('MODAL-MD', botMarkdown)}
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 transition"
              >
                {copiedId === 'MODAL-MD' ? (
                  <>
                    <Check className="w-3.5 h-3.5" /> Copied Markdown!
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" /> Copy Markdown Comment
                  </>
                )}
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {botMarkdown}
            </pre>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={onExportJson}
            className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            Download Full JSON Report
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
