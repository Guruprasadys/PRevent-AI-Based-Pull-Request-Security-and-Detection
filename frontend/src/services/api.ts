export interface Finding {
  id: string;
  category: string;
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  file: string;
  line: number;
  snippet: string;
  remediation: string;
  suggested_patch: string;
  status: 'OPEN' | 'RESOLVED';
}

export interface DependencyRecord {
  package: string;
  ecosystem: string;
  manifest_format?: string;
  old_version: string;
  new_version: string;
  change_type: string;
  file: string;
  line: number;
  is_known_malicious: boolean;
  vulnerabilities: { id: string; summary: string; fixed_version: string }[];
  status: 'CLEAN' | 'VULNERABLE' | 'MALICIOUS' | 'REMEDIATED';
  detection_rule?: string;
  decision_factors?: string[];
  precautions?: string[];
  resolution_steps?: string[];
}

export interface ScanReport {
  scan_id: string;
  timestamp: string;
  pr_url: string;
  scenario_badge?: string | null;
  repository: string;
  pr_number: number;
  title: string;
  author: string;
  review_decision: string;
  reviewer_note: string;
  risk_score: number;
  initial_risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_label: string;
  recommended_action: string;
  score_breakdown: { source: string; title: string; points: number }[];
  findings: Finding[];
  open_findings_count: number;
  resolved_findings_count: number;
  resolved_finding_ids: string[];
  resolution_log: {
    timestamp: string;
    finding_id: string;
    action: string;
    note: string;
    new_risk_score: number;
  }[];
  dependencies: DependencyRecord[];
  ml_prediction: {
    flagged: boolean;
    ml_confidence_score: number;
    raw_tfidf_score: number;
    label: number;
    explanation: string;
    ai_checks?: {
      id: string;
      check_name: string;
      category: string;
      evidence: string;
      predicted_label: number;
      suspicion_score: number;
    }[];
    file_predictions?: {
      filename: string;
      file_type: string;
      additions: number;
      deletions: number;
      predicted_label: number;
      suspicion_score: number;
    }[];
  };
  features: {
    diff_text: string;
    changed_file_types: string[];
    dependency_change: boolean;
    dangerous_api_count: number;
    network_activity: boolean;
    network_activity_count: number;
    secret_access_count: number;
    obfuscation_indicators: number;
    workflow_permission_change: boolean;
    total_added_lines: number;
  };
  files: {
    filename: string;
    status: string;
    file_type: string;
    additions: number;
    deletions: number;
    patch: string;
  }[];
}

export interface TestCaseItem {
  id: string;
  scenario_badge: string;
  title: string;
  repository: string;
  pr_number: number;
  author: string;
  expected_risk_level: string;
  expected_min_score: number;
  expected_max_score: number;
  attack_type: string;
  actual_score: number;
  actual_risk_level: string;
  findings_count: number;
  ml_confidence: number;
  passed: boolean;
  files?: {
    filename: string;
    status: string;
    patch: string;
  }[];
}

export interface DashboardSummary {
  total_prs_analyzed: number;
  high_risk_findings: number;
  dependency_alerts: number;
  resolved_issues_count: number;
  database_status: {
    connected_to_mongod: boolean;
    engine: string;
    documents_count: number;
    github_token_configured?: boolean;
  };
  recent_scans: ScanReport[];
  ml_metrics: {
    model_name: string;
    training_samples: number;
    evaluation_samples: number;
    vocabulary_size: number;
    precision: number;
    recall: number;
    f1_score: number;
    false_positive_rate: number;
    confusion_matrix: { tn: number; fp: number; fn: number; tp: number };
    evaluation_details: {
      id: string;
      description: string;
      category: string;
      actual_label: number;
      predicted_label: number;
      suspicion_score: number;
      correct: boolean;
    }[];
  };
}

export interface LivePublicPr {
  pr_number: number;
  title: string;
  author: string;
  pr_url: string;
  repository: string;
  created_at: string;
  updated_at: string;
}

const API_BASE = import.meta.env.VITE_API_URL || '';

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  const res = await fetch(`${API_BASE}/api/dashboard/summary`);
  if (!res.ok) throw new Error('Failed to load dashboard summary');
  return res.json();
}

export async function fetchLiveOpenPrs(repo: string): Promise<{
  repository: string;
  pull_requests: LivePublicPr[];
}> {
  const res = await fetch(`${API_BASE}/api/github/open-prs?repo=${encodeURIComponent(repo)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to fetch open PRs from GitHub' }));
    throw new Error(err.detail || 'Failed to fetch open PRs from GitHub');
  }
  return res.json();
}

export async function fetchTestCases(): Promise<{
  total_test_cases: number;
  passed_count: number;
  test_cases: TestCaseItem[];
}> {
  const res = await fetch(`${API_BASE}/api/test-cases`);
  if (!res.ok) throw new Error('Failed to load test cases');
  return res.json();
}

export async function scanPullRequest(payload: {
  pr_url?: string;
  test_case_id?: string;
  title?: string;
  repository?: string;
  pr_number?: number;
  author?: string;
  files?: { filename: string; status: string; patch: string }[];
}): Promise<ScanReport> {
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(err.detail || 'Scan failed');
  }
  return res.json();
}

export async function resolveFindingApi(
  scanId: string,
  findingId: string,
  resolutionAction = 'APPLIED_REMEDIATION_PATCH',
  reviewerNote = 'Maintainer applied remediation patch and verified evidence.'
): Promise<ScanReport> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/resolve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding_id: findingId,
      resolution_action: resolutionAction,
      reviewer_note: reviewerNote,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to resolve finding' }));
    throw new Error(err.detail || 'Failed to resolve finding');
  }
  return res.json();
}

export async function updateReviewDecisionApi(
  scanId: string,
  decision: string,
  reviewerNote: string
): Promise<ScanReport> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision, reviewer_note: reviewerNote }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to update review decision' }));
    throw new Error(err.detail || 'Failed to update review decision');
  }
  return res.json();
}

export async function clearAllScansApi(): Promise<{ cleared: boolean }> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Failed to clear scan history');
  return res.json();
}
