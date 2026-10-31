import React from 'react';
import { ShieldCheck, AlertTriangle, XCircle, Sparkles, Play } from 'lucide-react';

interface DemoScenarioBannerProps {
  onRunScenario: (tcId: string) => void;
  loading: boolean;
  activeScenarioBadge?: string | null;
}

export const DemoScenarioBanner: React.FC<DemoScenarioBannerProps> = ({
  onRunScenario,
  loading,
  activeScenarioBadge
}) => {
  const scenarios = [
    {
      id: 'TC-001',
      badge: 'Judge Demo 1 — Safe PR',
      title: 'Scenario 1: Safe PR',
      subtitle: 'Email validation & unit tests',
      riskTag: 'LOW RISK (0/100)',
      icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
      cardStyle:
        'border-emerald-500/30 bg-gradient-to-r from-emerald-950/35 to-slate-900/80 hover:border-emerald-400/60',
      tagStyle: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
    },
    {
      id: 'TC-002',
      badge: 'Judge Demo 2 — Risky Dependency Update',
      title: 'Scenario 2: Risky Dependency',
      subtitle: 'event-stream 3.3.6 + postinstall',
      riskTag: 'CRITICAL (100/100)',
      icon: <AlertTriangle className="w-4 h-4 text-amber-400" />,
      cardStyle:
        'border-amber-500/30 bg-gradient-to-r from-amber-950/35 to-slate-900/80 hover:border-amber-400/60',
      tagStyle: 'bg-amber-500/15 text-amber-300 border-amber-500/30'
    },
    {
      id: 'TC-003',
      badge: 'Judge Demo 3 — Suspicious Code Change',
      title: 'Scenario 3: Secret Exfiltration',
      subtitle: 'Steals AWS/DB tokens over HTTP',
      riskTag: 'CRITICAL (75/100)',
      icon: <XCircle className="w-4 h-4 text-rose-400" />,
      cardStyle:
        'border-rose-500/30 bg-gradient-to-r from-rose-950/35 to-slate-900/80 hover:border-rose-400/60',
      tagStyle: 'bg-rose-500/15 text-rose-300 border-rose-500/30'
    }
  ];

  return (
    <section className="bg-slate-900/45 border-b border-slate-800/70">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-slate-300 shrink-0">
            <div className="p-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <div className="font-bold text-white">Controlled Judge Demo Scenarios</div>
              <div className="text-[11px] text-slate-400">1-Click Live Scan & Remediation</div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 flex-1 max-w-4xl">
            {scenarios.map(s => {
              const isSelected = activeScenarioBadge === s.badge;
              return (
                <button
                  key={s.id}
                  onClick={() => onRunScenario(s.id)}
                  disabled={loading}
                  className={`p-2.5 rounded-xl border text-left transition-all flex items-center justify-between gap-2 group ${
                    s.cardStyle
                  } ${isSelected ? 'ring-2 ring-indigo-500/60 shadow-lg' : ''}`}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      {s.icon}
                      <span className="text-xs font-bold text-white truncate">{s.title}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 truncate mt-0.5">{s.subtitle}</p>
                  </div>
                  <div className="flex flex-col items-end gap-1 shrink-0">
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${s.tagStyle}`}>
                      {s.riskTag}
                    </span>
                    <span className="text-[10px] text-indigo-300 group-hover:translate-x-0.5 transition inline-flex items-center gap-0.5 font-medium">
                      <Play className="w-2.5 h-2.5 fill-current" /> Scan
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
};
