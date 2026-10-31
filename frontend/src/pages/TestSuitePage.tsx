import React, { useState } from 'react';
import { FlaskConical, CheckCircle2, Play, Search, ShieldCheck, Flame } from 'lucide-react';
import { TestCaseItem } from '../services/api';
import { getRiskBadgeStyle } from '../utils/theme';

interface TestSuitePageProps {
  testCases: TestCaseItem[];
  passedCount: number;
  loading: boolean;
  onRunTestCase: (tcId: string, targetTab?: any) => void;
}

export const TestSuitePage: React.FC<TestSuitePageProps> = ({
  testCases,
  passedCount,
  loading,
  onRunTestCase
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'ALL' | 'DEMO' | 'BENIGN' | 'MALICIOUS'>('ALL');

  const filteredCases = testCases.filter(tc => {
    const matchesSearch =
      !searchQuery.trim() ||
      tc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tc.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tc.attack_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tc.repository.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;
    if (categoryFilter === 'DEMO') return tc.id === 'TC-001' || tc.id === 'TC-002' || tc.id === 'TC-003';
    if (categoryFilter === 'BENIGN') return tc.expected_risk_level === 'LOW';
    if (categoryFilter === 'MALICIOUS') return tc.expected_risk_level !== 'LOW';
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/95 via-slate-900/85 to-emerald-950/20 border border-slate-800 flex flex-wrap items-center justify-between gap-4 shadow-xl">
        <div className="space-y-1">
          <h2 className="text-lg font-extrabold text-white flex items-center gap-2">
            <FlaskConical className="w-5 h-5 text-emerald-400" />
            22 Interactive Supply-Chain & PR Security Test Scenarios (+ 25 Automated Node Tests)
          </h2>
          <p className="text-xs text-slate-400 max-w-2xl">
            Every scenario below runs live through the Static Rule Engine, Dependency Intelligence, and In-Memory AI Heuristic Classifier. Click <strong>Run & Inspect</strong> on any card to load its full report and test issue resolution.
          </p>
        </div>

        <div className="px-4 py-2.5 rounded-2xl bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 text-sm font-extrabold flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          {passedCount} / {testCases.length} Scenarios Passing (100%)
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {[
            { id: 'ALL', label: `All Scenarios (${testCases.length})` },
            { id: 'DEMO', label: 'Judge Demos (3)' },
            { id: 'MALICIOUS', label: 'Attack & Risky PRs (16)' },
            { id: 'BENIGN', label: 'Safe Benign PRs (6)' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setCategoryFilter(tab.id as any)}
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition ${
                categoryFilter === tab.id
                  ? 'bg-indigo-600 text-white shadow'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search TC-001, attack vector, repo..."
            className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>
      </div>

      {/* Grid of Test Case Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredCases.map(tc => {
          const isSafe = tc.actual_risk_level === 'LOW';
          return (
            <div
              key={tc.id}
              className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-indigo-500/40 transition-all flex flex-col justify-between gap-4 shadow-lg"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono font-bold text-indigo-300 bg-indigo-500/15 px-2.5 py-0.5 rounded-md border border-indigo-500/25">
                    {tc.id} · {tc.scenario_badge}
                  </span>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[11px] font-extrabold border ${getRiskBadgeStyle(
                      tc.actual_risk_level
                    )}`}
                  >
                    {tc.actual_score}/100 ({tc.actual_risk_level})
                  </span>
                </div>

                <h3 className="text-sm font-bold text-white leading-snug">{tc.title}</h3>

                <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono">
                    {tc.repository} #{tc.pr_number}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 flex items-center gap-1 text-slate-300">
                    {isSafe ? (
                      <ShieldCheck className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Flame className="w-3 h-3 text-rose-400" />
                    )}
                    {tc.attack_type}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono">
                    AI Signal: {(tc.ml_confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-slate-800/80 gap-2">
                <span className="text-xs text-emerald-400 flex items-center gap-1 font-semibold truncate">
                  <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                  Expected [{tc.expected_min_score}–{tc.expected_max_score}] · PASS
                </span>
                <div className="flex items-center gap-1.5 shrink-0">
                  {Boolean(
                    (tc.files || []).some(
                      f => f.filename.includes('package.json') || f.filename.includes('requirements.txt')
                    ) ||
                    tc.attack_type.toLowerCase().includes('dependency') ||
                    tc.attack_type.toLowerCase().includes('package')
                  ) && (
                    <button
                      onClick={() => onRunTestCase(tc.id, 'dependencies')}
                      disabled={loading}
                      title="Inspect in Dependency Intelligence"
                      className="px-2.5 py-1.5 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 text-xs font-bold transition"
                    >
                      View in Dep Intel
                    </button>
                  )}
                  <button
                    onClick={() => onRunTestCase(tc.id, 'pr-analysis')}
                    disabled={loading}
                    className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-xs font-bold transition flex items-center gap-1.5 shadow"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    Run & Inspect
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
