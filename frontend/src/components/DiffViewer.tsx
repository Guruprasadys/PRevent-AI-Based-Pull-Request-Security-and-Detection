import React, { useState } from 'react';
import { FileCode2, AlertTriangle } from 'lucide-react';
import { Finding } from '../services/api';

interface FileDiff {
  filename: string;
  status: string;
  file_type: string;
  additions: number;
  deletions: number;
  patch: string;
}

interface DiffViewerProps {
  files: FileDiff[];
  findings: Finding[];
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ files, findings }) => {
  const [selectedFileIndex, setSelectedFileIndex] = useState<number | 'all'>('all');

  const displayedFiles =
    selectedFileIndex === 'all' ? files : [files[selectedFileIndex]].filter(Boolean);

  return (
    <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <FileCode2 className="w-4 h-4 text-indigo-400" />
            Syntax-Highlighted Unified Diff Inspector ({files.length} file
            {files.length === 1 ? '' : 's'})
          </h3>
          <p className="text-xs text-slate-400">
            Inspect added (<span className="text-emerald-400 font-mono">+</span>) and removed (
            <span className="text-rose-400 font-mono">-</span>) lines with inline security alert markers.
          </p>
        </div>

        {/* File Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setSelectedFileIndex('all')}
            className={`px-2.5 py-1 rounded-lg text-xs font-medium transition ${
              selectedFileIndex === 'all'
                ? 'bg-indigo-600 text-white'
                : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            All Files ({files.length})
          </button>
          {files.map((f, idx) => (
            <button
              key={idx}
              onClick={() => setSelectedFileIndex(idx)}
              className={`px-2.5 py-1 rounded-lg text-xs font-mono transition ${
                selectedFileIndex === idx
                  ? 'bg-indigo-600 text-white'
                  : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {f.filename}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-4">
        {displayedFiles.map((file, idx) => {
          const rawLines = (file.patch || '').split(/\r?\n/);
          const fileFindings = findings.filter(f => f.file === file.filename);
          let currentNewLine = 1;

          return (
            <div
              key={idx}
              className="rounded-xl bg-slate-950 border border-slate-800/90 overflow-hidden shadow-inner"
            >
              {/* File Header Bar */}
              <div className="px-4 py-2.5 bg-slate-900/95 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-white">{file.filename}</span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] uppercase">
                    {file.file_type}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 text-[10px]">
                    {file.status}
                  </span>
                </div>
                <div className="flex items-center gap-3 font-mono">
                  {fileFindings.length > 0 && (
                    <span className="text-rose-400 font-sans font-semibold flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      {fileFindings.length} alert{fileFindings.length === 1 ? '' : 's'} in file
                    </span>
                  )}
                  <span className="text-emerald-400 font-bold">+{file.additions}</span>
                  <span className="text-rose-400 font-bold">-{file.deletions}</span>
                </div>
              </div>

              {/* Diff Lines */}
              <div className="divide-y divide-slate-900/60 font-mono text-xs overflow-x-auto">
                {rawLines.map((line, lineIdx) => {
                  const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
                  if (hunkMatch) {
                    currentNewLine = parseInt(hunkMatch[1], 10);
                    return (
                      <div
                        key={lineIdx}
                        className="px-4 py-1.5 bg-indigo-950/30 text-indigo-300 text-[11px] select-none"
                      >
                        {line}
                      </div>
                    );
                  }

                  const isAdd = line.startsWith('+') && !line.startsWith('+++');
                  const isDel = line.startsWith('-') && !line.startsWith('---');
                  const displayLineNum = isAdd ? currentNewLine++ : !isDel ? currentNewLine++ : null;

                  const matchingFindings = isAdd
                    ? fileFindings.filter(f => f.line === (displayLineNum || 0) - 1)
                    : [];

                  return (
                    <div
                      key={lineIdx}
                      className={`px-4 py-1 flex items-start justify-between gap-4 ${
                        isAdd
                          ? matchingFindings.length > 0
                            ? 'bg-rose-500/15 text-rose-200 border-l-2 border-rose-500'
                            : 'bg-emerald-500/10 text-emerald-200 border-l-2 border-emerald-500/60'
                          : isDel
                          ? 'bg-rose-950/25 text-rose-400/80 border-l-2 border-rose-800/50'
                          : 'text-slate-400'
                      }`}
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <span className="w-7 text-right text-[10px] text-slate-600 select-none shrink-0">
                          {displayLineNum ?? '·'}
                        </span>
                        <span className="whitespace-pre-wrap break-all">{line}</span>
                      </div>

                      {matchingFindings.length > 0 && (
                        <span className="shrink-0 px-2 py-0.5 rounded bg-rose-500/25 border border-rose-500/40 text-[10px] font-sans font-bold text-rose-200 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-rose-400" />
                          {matchingFindings[0].rule_id}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
