import React, { useState } from 'react';
import {
  GitPullRequest,
  ShieldAlert,
  PackageSearch,
  Wrench,
  Play,
  RefreshCw,
  ChevronRight,
  Search,
  BarChart3,
  Layers,
  Globe,
  ExternalLink,
  Trash2
} from 'lucide-react';
import { DashboardSummary, ScanReport, fetchLiveOpenPrs, LivePublicPr } from '../services/api';
import { formatCategoryLabel, getRiskBadgeStyle, getScoreColor } from '../utils/theme';

interface OverviewDashboardProps {
  summary: DashboardSummary | null;
  loading: boolean;
  onScanUrl: (url: string) => void;
  onScanCustom: (title: string, filename: string, patch: string) => void;
  onSelectScan: (scan: ScanReport) => void;
  onRefresh: () => void;
  onClearHistory?: () => void;
}

const POPULAR_PUBLIC_REPOS = [
  'expressjs/express',
  'axios/axios',
  'facebook/react',
  'vercel/next.js',
  'nodejs/node'
];

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  summary,
  loading,
  onScanUrl,
  onScanCustom,
  onSelectScan,
  onRefresh,
  onClearHistory
}) => {
  const [inputMode, setInputMode] = useState<'url' | 'custom'>('url');
  const [prUrlInput, setPrUrlInput] = useState('');
  const [repoQuery, setRepoQuery] = useState('expressjs/express');
  const [livePrs, setLivePrs] = useState<LivePublicPr[]>([]);
  const [fetchingPrs, setFetchingPrs] = useState(false);
  const [fetchPrError, setFetchPrError] = useState<string | null>(null);
  const [customTitle, setCustomTitle] = useState('');
  const [customFilename, setCustomFilename] = useState('');
  const [customPatch, setCustomPatch] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('ALL');

  const handleLoadOpenPrs = async (targetRepo: string) => {
    setRepoQuery(targetRepo);
    setFetchingPrs(true);
    setFetchPrError(null);
    try {
      const data = await fetchLiveOpenPrs(targetRepo);
      setLivePrs(data.pull_requests || []);
    } catch (err: any) {
      setFetchPrError(err?.message || 'Could not load open PRs from GitHub.');
      setLivePrs([]);
    } finally {
      setFetchingPrs(false);
    }
  };

  const recentScans = summary?.recent_scans || [];
  const filteredScans = recentScans.filter(s => {
    const matchesLevel = levelFilter === 'ALL' || s.risk_level === levelFilter;
    const matchesSearch =
      !searchFilter.trim() ||
      s.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
      s.repository.toLowerCase().includes(searchFilter.toLowerCase()) ||
      s.author.toLowerCase().includes(searchFilter.toLowerCase());
    return matchesLevel && matchesSearch;
  });

  // Compute Risk Distribution & Category Breakdown from recent scans
  const levelCounts = {
    CRITICAL: recentScans.filter(s => s.risk_level === 'CRITICAL').length,
    HIGH: recentScans.filter(s => s.risk_level === 'HIGH').length,
    MEDIUM: recentScans.filter(s => s.risk_level === 'MEDIUM').length,
    LOW: recentScans.filter(s => s.risk_level === 'LOW').length
  };
  const totalScans = Math.max(1, recentScans.length);

  const categoryCounts: Record<string, number> = {};
  recentScans.forEach(s => {
    (s.findings || []).forEach(f => {
      categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
    });
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputMode === 'url') {
      onScanUrl(prUrlInput);
    } else {
      onScanCustom(customTitle, customFilename, customPatch);
    }
  };

  return (
    <div className="space-y-6">
      {/* Row 1: 4 Glowing KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-900/90 to-slate-950 border border-slate-800/90 shadow-lg flex items-center justify-between">
          <div>
            <p className="text-[11px] uppercase tracking-wider text-slate-400 font-bold">
              PRs Analyzed
            </p>
            <p className="text-3xl font-black text-white mt-1">
              {summary?.total_prs_analyzed ?? 0}
            </p>
            <p className="text-xs text-indigo-400 mt-1 font-medium">
              Hybrid Static + Dep + AI
            </p>
          </div>
          <div className="w-12 h-12 rounded-2xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
            <GitPullRequest className="w-6 h-6" />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-900/90 to-slate-950 border border-slate-800/90 shadow-lg flex items-center justify-between">
          <div>
            <p className="text-[11px] uppercase tracking-wider text-slate-400 font-bold">
              High / Critical PRs
            </p>
            <p className="text-3xl font-black text-rose-400 mt-1">
              {summary?.high_risk_findings ?? 0}
            </p>
            <p className="text-xs text-slate-400 mt-1">Flagged before merge</p>
          </div>
          <div className="w-12 h-12 rounded-2xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-900/90 to-slate-950 border border-slate-800/90 shadow-lg flex items-center justify-between">
          <div>
            <p className="text-[11px] uppercase tracking-wider text-slate-400 font-bold">
              Dependency Alerts
            </p>
            <p className="text-3xl font-black text-amber-400 mt-1">
              {summary?.dependency_alerts ?? 0}
            </p>
            <p className="text-xs text-slate-400 mt-1">OSV & Malicious Registry</p>
          </div>
          <div className="w-12 h-12 rounded-2xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <PackageSearch className="w-6 h-6" />
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-900/90 to-slate-950 border border-slate-800/90 shadow-lg flex items-center justify-between">
          <div>
            <p className="text-[11px] uppercase tracking-wider text-slate-400 font-bold">
              Issues Remediated
            </p>
            <p className="text-3xl font-black text-emerald-400 mt-1">
              {summary?.resolved_issues_count ?? 0}
            </p>
            <p className="text-xs text-emerald-400/80 mt-1 font-medium">
              Verified & Risk Lowered
            </p>
          </div>
          <div className="w-12 h-12 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Wrench className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Row 2: Visual Analytics (Risk Distribution & Threat Vector Breakdown) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-3.5">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-indigo-400" />
              PR Risk Severity Distribution
            </h3>
            <span className="text-xs text-slate-400">{recentScans.length} total scans</span>
          </div>
          <div className="space-y-2.5">
            {[
              { label: 'CRITICAL (75–100)', count: levelCounts.CRITICAL, color: 'bg-rose-500' },
              { label: 'HIGH (50–74)', count: levelCounts.HIGH, color: 'bg-orange-500' },
              { label: 'MEDIUM (25–49)', count: levelCounts.MEDIUM, color: 'bg-amber-400' },
              { label: 'LOW (0–24)', count: levelCounts.LOW, color: 'bg-emerald-500' }
            ].map(item => {
              const pct = Math.round((item.count / totalScans) * 100);
              return (
                <div key={item.label} className="space-y-1 text-xs">
                  <div className="flex justify-between text-slate-300">
                    <span className="font-medium">{item.label}</span>
                    <span className="font-mono text-slate-400">
                      {item.count} PR{item.count === 1 ? '' : 's'} ({pct}%)
                    </span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden border border-slate-800">
                    <div
                      className={`h-full ${item.color} transition-all duration-500`}
                      style={{ width: `${Math.max(pct, item.count > 0 ? 8 : 0)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/75 border border-slate-800 space-y-3.5">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-violet-400" />
              Detected Attack Vectors Across Repository Scans
            </h3>
            <span className="text-xs text-slate-400">Categorized Evidence</span>
          </div>
          {Object.keys(categoryCounts).length === 0 ? (
            <div className="text-xs text-slate-400 py-6 text-center">
              No suspicious categories triggered yet.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {Object.entries(categoryCounts).map(([cat, count]) => (
                <div
                  key={cat}
                  className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between gap-2"
                >
                  <span className="text-xs text-slate-200 font-medium truncate">
                    {formatCategoryLabel(cat)}
                  </span>
                  <span className="px-2 py-0.5 rounded-md bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 font-mono text-xs font-bold shrink-0">
                    {count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Interactive PR URL & Custom Diff Sandbox Scanner */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/95 via-slate-900/80 to-indigo-950/20 border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-indigo-400" />
              Submit a Pull Request or Custom Code Diff for Hybrid Security Analysis
            </h2>
            <p className="text-xs text-slate-400">
              Scan any public GitHub Pull Request URL live via the GitHub API, or experiment with custom code/manifest diffs in the sandbox.
            </p>
          </div>

          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
            <button
              type="button"
              onClick={() => setInputMode('url')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                inputMode === 'url'
                  ? 'bg-indigo-600 text-white shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              GitHub PR URL
            </button>
            <button
              type="button"
              onClick={() => setInputMode('custom')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                inputMode === 'custom'
                  ? 'bg-indigo-600 text-white shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Interactive Diff Sandbox
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          {inputMode === 'url' ? (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={prUrlInput}
                  onChange={e => setPrUrlInput(e.target.value)}
                  placeholder="https://github.com/owner/repository/pull/123"
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 disabled:opacity-50 text-white text-sm font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20"
                >
                  <Play className="w-4 h-4 fill-current" />
                  {loading ? 'Scanning PR...' : 'Scan Pull Request'}
                </button>
              </div>

              {/* Live Public GitHub Open PR Browser */}
              <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800/90 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-indigo-300">
                    <Globe className="w-4 h-4 text-indigo-400" />
                    Need a Real Public GitHub PR URL? Browse Live Open PRs from GitHub API:
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {POPULAR_PUBLIC_REPOS.map(repo => (
                      <button
                        key={repo}
                        type="button"
                        onClick={() => handleLoadOpenPrs(repo)}
                        className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition border ${
                          repoQuery === repo && livePrs.length > 0
                            ? 'bg-indigo-600/25 text-indigo-200 border-indigo-500/50'
                            : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
                        }`}
                      >
                        {repo}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={repoQuery}
                    onChange={e => setRepoQuery(e.target.value)}
                    placeholder="Enter any public GitHub repo (e.g. owner/repo)"
                    className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-indigo-500"
                  />
                  <button
                    type="button"
                    disabled={fetchingPrs}
                    onClick={() => handleLoadOpenPrs(repoQuery)}
                    className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-indigo-300 border border-slate-700 transition flex items-center justify-center gap-1.5"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${fetchingPrs ? 'animate-spin' : ''}`} />
                    {fetchingPrs ? 'Querying api.github.com...' : 'Fetch Live Open PRs'}
                  </button>
                </div>

                {fetchPrError && (
                  <div className="text-xs text-rose-400 bg-rose-950/40 border border-rose-500/30 rounded-lg px-3 py-2">
                    {fetchPrError}
                  </div>
                )}

                {livePrs.length > 0 && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
                    {livePrs.map(pr => {
                      const targetUrl =
                        pr.pr_url ||
                        (pr as any).html_url ||
                        `https://github.com/${pr.repository}/pull/${pr.pr_number}`;
                      return (
                        <div
                          key={`${pr.repository}-${pr.pr_number}`}
                          className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-indigo-500/40 flex items-center justify-between gap-2 transition"
                        >
                          <div className="min-w-0">
                            <div className="text-xs font-semibold text-white truncate">
                              #{pr.pr_number} · {pr.title}
                            </div>
                            <div className="text-[11px] text-slate-400 font-mono truncate">
                              {pr.repository} · by @{pr.author}
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <a
                              href={targetUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="p-1.5 rounded-md bg-slate-950 text-slate-400 hover:text-white border border-slate-800"
                              title="View on GitHub"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                            <button
                              type="button"
                              disabled={loading}
                              onClick={() => {
                                setPrUrlInput(targetUrl);
                                onScanUrl(targetUrl);
                              }}
                              className="px-2.5 py-1 rounded-md bg-indigo-600 hover:bg-indigo-500 text-white text-[11px] font-bold transition"
                            >
                              {loading && prUrlInput === targetUrl ? 'Scanning...' : 'Use & Scan'}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1 font-medium">PR Title</label>
                  <input
                    type="text"
                    value={customTitle}
                    onChange={e => setCustomTitle(e.target.value)}
                    placeholder="Enter Pull Request title"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1 font-medium">
                    Target File (`src/app.py`, `package.json`, `.github/workflows/ci.yml`)
                  </label>
                  <input
                    type="text"
                    value={customFilename}
                    onChange={e => setCustomFilename(e.target.value)}
                    placeholder="e.g. package.json or src/index.js"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white font-mono placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1 font-medium">
                  Unified Code / Dependency Diff
                </label>
                <textarea
                  rows={4}
                  value={customPatch}
                  onChange={e => setCustomPatch(e.target.value)}
                  placeholder="Paste unified git diff lines (starting with + or -)"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-300 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={loading}
                  className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm font-bold transition flex items-center gap-2 shadow-lg shadow-indigo-600/20"
                >
                  <Play className="w-4 h-4 fill-current" />
                  {loading ? 'Analyzing Diff...' : 'Run Hybrid Security Scan'}
                </button>
              </div>
            </div>
          )}
        </form>
      </div>

      {/* Row 4: Searchable & Filterable Recent Scan History Table */}
      <div className="rounded-2xl bg-slate-900/75 border border-slate-800 overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white">Recent PR Security Scans</h3>
            <p className="text-xs text-slate-400">
              Click any scan report to open the PR Analysis & Issue Resolution Workbench.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchFilter}
                onChange={e => setSearchFilter(e.target.value)}
                placeholder="Filter repo, PR title, author..."
                className="bg-slate-950 border border-slate-800 rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <select
              value={levelFilter}
              onChange={e => setLevelFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs text-slate-300"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High Only</option>
              <option value="MEDIUM">Medium Only</option>
              <option value="LOW">Low Only</option>
            </select>

            <button
              onClick={onRefresh}
              className="text-xs text-slate-300 hover:text-white flex items-center gap-1 px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Refresh
            </button>

            {onClearHistory && recentScans.length > 0 && (
              <button
                onClick={onClearHistory}
                className="text-xs text-rose-300 hover:text-white flex items-center gap-1 px-3 py-1.5 rounded-xl bg-rose-950/40 border border-rose-500/30"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Clear History
              </button>
            )}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 bg-slate-950/60">
                <th className="py-3 px-4">Pull Request / Scenario</th>
                <th className="py-3 px-4">Repository & Author</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Findings</th>
                <th className="py-3 px-4">Review Decision</th>
                <th className="py-3 px-4 text-right">Workbench</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredScans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 px-4 text-center text-xs text-slate-400">
                    No Pull Requests scanned yet. Paste a GitHub PR URL above or click a repository under "Browse Live Open PRs" to scan a real PR.
                  </td>
                </tr>
              ) : (
                filteredScans.map(scan => (
                <tr
                  key={scan.scan_id}
                  onClick={() => onSelectScan(scan)}
                  className="hover:bg-slate-800/45 cursor-pointer transition"
                >
                  <td className="py-3.5 px-4">
                    <div className="font-semibold text-white">{scan.title}</div>
                    {scan.scenario_badge && (
                      <span className="inline-block mt-1 text-[10px] font-bold px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                        {scan.scenario_badge}
                      </span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-300">
                    {scan.repository} #{scan.pr_number}
                    <div className="text-[11px] text-slate-500 font-sans">by @{scan.author}</div>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`text-lg font-black ${getScoreColor(scan.risk_score)}`}>
                      {scan.risk_score}
                    </span>
                    <span className="text-xs text-slate-500"> / 100</span>
                    {scan.initial_risk_score !== scan.risk_score && (
                      <div className="text-[10px] text-emerald-400 font-semibold">
                        Was {scan.initial_risk_score} before fix
                      </div>
                    )}
                  </td>
                  <td className="py-3.5 px-4">
                    <span
                      className={`px-2.5 py-1 rounded-full text-xs font-extrabold border ${getRiskBadgeStyle(
                        scan.risk_level
                      )}`}
                    >
                      {scan.risk_level}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-xs">
                    <span className="text-rose-400 font-bold">{scan.open_findings_count} open</span>
                    {' · '}
                    <span className="text-emerald-400 font-bold">
                      {scan.resolved_findings_count} resolved
                    </span>
                  </td>
                  <td className="py-3.5 px-4">
                    <span
                      className={`text-xs font-semibold px-2.5 py-0.5 rounded-md ${
                        scan.review_decision === 'REMEDIATED_AND_VERIFIED' ||
                        scan.review_decision === 'APPROVED'
                          ? 'bg-emerald-500/15 text-emerald-300'
                          : scan.review_decision === 'BLOCKED'
                          ? 'bg-rose-500/15 text-rose-300'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {scan.review_decision}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button className="text-xs text-indigo-400 hover:text-indigo-300 font-bold inline-flex items-center gap-1">
                      Inspect & Resolve <ChevronRight className="w-3.5 h-3.5" />
                    </button>
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
