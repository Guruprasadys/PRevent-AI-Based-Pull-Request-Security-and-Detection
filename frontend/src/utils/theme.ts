import { ScanReport } from '../services/api';

export type ActiveTab =
  | 'overview'
  | 'pr-analysis'
  | 'dependencies'
  | 'test-suite'
  | 'ai-engine';

export function getRiskBadgeStyle(level: string): string {
  switch (level) {
    case 'CRITICAL':
      return 'bg-rose-500/15 text-rose-300 border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.15)]';
    case 'HIGH':
      return 'bg-orange-500/15 text-orange-300 border-orange-500/40 shadow-[0_0_12px_rgba(249,115,22,0.15)]';
    case 'MEDIUM':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
    default:
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40';
  }
}

export function getScoreColor(score: number): string {
  if (score >= 75) return 'text-rose-400';
  if (score >= 50) return 'text-orange-400';
  if (score >= 25) return 'text-amber-300';
  return 'text-emerald-400';
}

export function getScoreStrokeColor(score: number): string {
  if (score >= 75) return '#f43f5e'; // rose-500
  if (score >= 50) return '#f97316'; // orange-500
  if (score >= 25) return '#f59e0b'; // amber-500
  return '#10b981'; // emerald-500
}

export function formatCategoryLabel(category: string): string {
  const map: Record<string, string> = {
    secret_exfiltration: 'Secret & Credential Exfiltration',
    malicious_dependency: 'Malicious / Typosquatted Dependency',
    vulnerable_dependency: 'Known Vulnerable Dependency (OSV)',
    dangerous_install_script: 'Dangerous Build / Install Hook',
    dangerous_execution: 'Remote Shell / Command Execution',
    obfuscation: 'Obfuscated Payload / Dynamic Exec',
    workflow_compromise: 'CI/CD Workflow Permission Escalation'
  };
  return map[category] || category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function buildGithubBotComment(scan: ScanReport): string {
  const icon =
    scan.risk_score >= 75
      ? '🚨'
      : scan.risk_score >= 50
      ? '⚠️'
      : scan.risk_score >= 25
      ? '🔎'
      : '✅';

  const findingsList =
    scan.findings.length === 0
      ? '_No static security or supply-chain dependency alerts triggered._'
      : scan.findings
          .map(
            f =>
              `- **[${f.status === 'RESOLVED' ? 'RESOLVED ✅' : f.severity}] \`${f.rule_id}\`** in \`${f.file}:${f.line}\` — **${f.title}**\n  > ${f.description}\n  > **Fix:** ${f.remediation}`
          )
          .join('\n');

  return `## ${icon} PRevent — Automated Supply-Chain & PR Security Review

| Metric | Assessment |
| :--- | :--- |
| **Repository & PR** | \`${scan.repository}#${scan.pr_number}\` (${scan.title}) |
| **Hybrid Risk Score** | **${scan.risk_score} / 100** (Initial: ${scan.initial_risk_score}/100) |
| **Risk Classification** | **${scan.risk_level}** — ${scan.risk_label} |
| **Findings Status** | **${scan.open_findings_count} Open** · **${scan.resolved_findings_count} Resolved** |
| **AI Heuristic Signal** | ${(scan.ml_prediction.ml_confidence_score * 100).toFixed(1)}% Suspicion (${scan.ml_prediction.flagged ? 'Flagged' : 'Benign'}) |

### Recommended Maintainer Action
> **${scan.recommended_action}**

### Detailed Security Evidence
${findingsList}
`;
}
