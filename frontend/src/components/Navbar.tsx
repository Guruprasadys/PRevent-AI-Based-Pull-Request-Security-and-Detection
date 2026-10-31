import React from 'react';
import {
  ShieldAlert,
  GitPullRequest,
  FileCode2,
  PackageSearch,
  FlaskConical,
  Cpu,
  Database,
  Activity
} from 'lucide-react';
import { ActiveTab } from '../utils/theme';
import { DashboardSummary, ScanReport } from '../services/api';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  selectedScan: ScanReport | null;
  passedCount: number;
  totalTestCases: number;
  summary: DashboardSummary | null;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  selectedScan,
  passedCount,
  totalTestCases,
  summary
}) => {
  const navItems: {
    id: ActiveTab;
    label: string;
    icon: React.ReactNode;
    badge?: React.ReactNode;
  }[] = [
    {
      id: 'overview',
      label: 'Security Dashboard',
      icon: <GitPullRequest className="w-3.5 h-3.5" />
    },
    {
      id: 'pr-analysis',
      label: 'PR Analysis & Resolve',
      icon: <FileCode2 className="w-3.5 h-3.5" />,
      badge:
        selectedScan && selectedScan.open_findings_count > 0 ? (
          <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-rose-500/30 text-rose-200 border border-rose-400/30 font-bold leading-none">
            {selectedScan.open_findings_count}
          </span>
        ) : selectedScan ? (
          <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-emerald-500/20 text-emerald-300 font-bold leading-none">
            0
          </span>
        ) : null
    },
    {
      id: 'dependencies',
      label: 'Dependency Intel',
      icon: <PackageSearch className="w-3.5 h-3.5" />,
      badge:
        summary && summary.dependency_alerts > 0 ? (
          <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-amber-500/20 text-amber-300 font-semibold leading-none">
            {summary.dependency_alerts}
          </span>
        ) : null
    },
    {
      id: 'test-suite',
      label: '22+ Test Suite',
      icon: <FlaskConical className="w-3.5 h-3.5" />,
      badge: (
        <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold leading-none">
          {passedCount}/{totalTestCases || 22}
        </span>
      )
    },
    {
      id: 'ai-engine',
      label: 'AI Security Engine',
      icon: <Cpu className="w-3.5 h-3.5" />
    }
  ];

  return (
    <header className="border-b border-slate-800/80 bg-slate-950/85 backdrop-blur-xl sticky top-0 z-40 shadow-lg shadow-black/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Brand Identity */}
        <div
          onClick={() => setActiveTab('overview')}
          className="flex items-center gap-3.5 cursor-pointer group"
        >
          <div className="relative">
            <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-indigo-500/30 via-indigo-600/20 to-violet-600/30 border border-indigo-500/40 flex items-center justify-center text-indigo-400 shadow-lg shadow-indigo-500/10 group-hover:border-indigo-400 transition">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-emerald-400 border-2 border-slate-950 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-extrabold tracking-tight bg-gradient-to-r from-white via-slate-100 to-indigo-200 bg-clip-text text-transparent">
                PRevent
              </h1>
              <span className="text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-md bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                MERN Security
              </span>
              <span className="hidden sm:inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                <Activity className="w-3 h-3" /> Live Guard
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Malicious PR & Supply-Chain Dependency-Update Detector
            </p>
          </div>
        </div>

        {/* Navigation Pills */}
        <nav className="flex flex-wrap items-center gap-1 bg-slate-900/90 p-1.5 rounded-2xl border border-slate-800/90 shadow-inner">
          {navItems.map(item => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-gradient-to-r from-indigo-600 to-violet-600 text-white shadow-md shadow-indigo-600/25'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/70'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
                {item.badge}
              </button>
            );
          })}
        </nav>

        {/* Database & GitHub Status Pills */}
        <div className="hidden lg:flex items-center gap-2">
          <div
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[11px] font-medium ${
              summary?.database_status?.connected_to_mongod
                ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                : 'bg-slate-900/70 border-slate-800 text-slate-400'
            }`}
          >
            <Database className="w-3.5 h-3.5 text-emerald-400" />
            <span>{summary?.database_status?.engine || 'MongoDB'}</span>
          </div>
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-[11px] font-medium ${
              summary?.database_status?.github_token_configured
                ? 'bg-indigo-950/40 border-indigo-500/30 text-indigo-300'
                : 'bg-slate-900/70 border-slate-800 text-slate-400'
            }`}
            title={
              summary?.database_status?.github_token_configured
                ? 'Authenticated GitHub API (5,000 req/hr)'
                : 'Public GitHub API (60 req/hr) - Add GITHUB_TOKEN in .env for 5,000 req/hr'
            }
          >
            <span>
              {summary?.database_status?.github_token_configured
                ? 'GitHub Token: Active'
                : 'GitHub API: Public Mode'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
