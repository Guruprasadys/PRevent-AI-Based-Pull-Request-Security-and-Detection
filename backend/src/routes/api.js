const express = require('express');
const crypto = require('crypto');
const { parsePatch } = require('../services/diffParser');
const { extractFeatures } = require('../services/featureExtractor');
const { runStaticRules } = require('../services/ruleEngine');
const { scanDependencies } = require('../services/dependencyScanner');
const { mlDetectorInstance } = require('../services/mlDetector');
const { computeRiskAssessment } = require('../services/riskEngine');
const { fetchGithubPr, fetchOpenPullRequestsFromRepo } = require('../services/githubClient');
const { TEST_CASES_CATALOG } = require('../data/testCasesData');
const {
  saveScanReport,
  getScanReport,
  getAllScanReports,
  clearAllScanReports,
  serializeReport,
  getDbStatus
} = require('../config/db');

const router = express.Router();

async function executeHybridAnalysis({
  title,
  repository,
  prNumber,
  author,
  rawFiles,
  prUrl = '',
  scenarioBadge = null,
  scanId = null,
  checkLiveOsv = false
}) {
  const changedFiles = (rawFiles || []).map(f =>
    parsePatch(f.filename, f.patch || '', f.status || 'modified')
  );

  const features = extractFeatures(changedFiles);
  const staticFindings = runStaticRules(changedFiles);
  const depResult = await scanDependencies(changedFiles, checkLiveOsv);
  const depFindings = depResult.findings;

  const mlBase = mlDetectorInstance.predictDiff(
    features.diff_text,
    features.changed_file_types,
    features
  );
  const { checks: aiChecks, filePredictions } = mlDetectorInstance.evaluatePrChecks(
    changedFiles,
    features,
    staticFindings,
    depFindings,
    depResult.dependencies
  );
  const mlResult = {
    ...mlBase,
    ai_checks: aiChecks,
    file_predictions: filePredictions
  };

  const riskReport = computeRiskAssessment(
    staticFindings,
    depFindings,
    mlResult,
    []
  );

  const sid = scanId || `SCAN-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const record = {
    scan_id: sid,
    timestamp: new Date().toISOString(),
    pr_url: prUrl || `https://github.com/${repository}/pull/${prNumber}`,
    scenario_badge: scenarioBadge,
    repository,
    pr_number: prNumber,
    title,
    author,
    review_decision: 'PENDING_REVIEW',
    reviewer_note: '',
    risk_score: riskReport.risk_score,
    initial_risk_score: riskReport.risk_score,
    risk_level: riskReport.risk_level,
    risk_label: riskReport.risk_label,
    recommended_action: riskReport.recommended_action,
    score_breakdown: riskReport.score_breakdown,
    findings: riskReport.findings,
    open_findings_count: riskReport.open_findings_count,
    resolved_findings_count: riskReport.resolved_findings_count,
    resolved_finding_ids: [],
    resolution_log: [],
    dependencies: depResult.dependencies,
    ml_prediction: mlResult,
    features,
    files: changedFiles.map(cf => ({
      filename: cf.filename,
      status: cf.status,
      file_type: cf.file_type,
      additions: cf.additions,
      deletions: cf.deletions,
      patch: cf.patch
    })),
    _raw_static_findings: staticFindings,
    _raw_dep_findings: depFindings
  };

  return await saveScanReport(record);
}

async function ensureSeeded() {
  // Start with a 100% clean dashboard (zero dummy/pre-populated scans) so user can test everything manually
}

router.delete('/scans', async (req, res) => {
  try {
    await clearAllScanReports();
    res.json({ cleared: true });
  } catch (err) {
    res.status(500).json({ detail: err.message });
  }
});

router.get('/dashboard/summary', async (req, res) => {
  try {
    await ensureSeeded();
    const scans = await getAllScanReports();
    const highOrCrit = scans.filter(s => ['HIGH', 'CRITICAL'].includes(s.risk_level)).length;
    const depAlerts = scans.reduce(
      (acc, s) => acc + (s.dependencies || []).filter(d => d.status !== 'CLEAN').length,
      0
    );
    const resolvedTotal = scans.reduce((acc, s) => acc + (s.resolved_findings_count || 0), 0);

    res.json({
      total_prs_analyzed: scans.length,
      high_risk_findings: highOrCrit,
      dependency_alerts: depAlerts,
      resolved_issues_count: resolvedTotal,
      database_status: getDbStatus(),
      recent_scans: scans,
      ml_metrics: mlDetectorInstance.metrics
    });
  } catch (err) {
    res.status(500).json({ detail: err.message });
  }
});

router.get('/test-cases', async (req, res) => {
  try {
    const results = [];
    for (const tc of TEST_CASES_CATALOG) {
      const changedFiles = tc.files.map(f => parsePatch(f.filename, f.patch || '', f.status || 'modified'));
      const features = extractFeatures(changedFiles);
      const staticFindings = runStaticRules(changedFiles);
      const depResult = await scanDependencies(changedFiles, false);
      const mlRes = mlDetectorInstance.predictDiff(features.diff_text, features.changed_file_types, features);
      const risk = computeRiskAssessment(staticFindings, depResult.findings, mlRes, []);
      const passed = risk.risk_score >= tc.expected_min_score && risk.risk_score <= tc.expected_max_score;

      results.push({
        ...tc,
        actual_score: risk.risk_score,
        actual_risk_level: risk.risk_level,
        findings_count: risk.findings.length,
        ml_confidence: mlRes.ml_confidence_score,
        passed
      });
    }
    res.json({
      total_test_cases: results.length,
      passed_count: results.filter(r => r.passed).length,
      test_cases: results
    });
  } catch (err) {
    res.status(500).json({ detail: err.message });
  }
});

router.get('/github/open-prs', async (req, res) => {
  try {
    const repo = String(req.query.repo || 'expressjs/express').trim();
    const prs = await fetchOpenPullRequestsFromRepo(repo, 6);
    res.json({ repository: repo, pull_requests: prs });
  } catch (err) {
    res.status(502).json({ detail: err.message });
  }
});

router.post('/scan', async (req, res) => {
  try {
    await ensureSeeded();
    const { pr_url, test_case_id, title, repository, pr_number, author, files } = req.body || {};

    if (test_case_id) {
      const tc = TEST_CASES_CATALOG.find(t => t.id === test_case_id);
      if (!tc) {
        return res.status(404).json({ detail: `Test case ${test_case_id} not found` });
      }
      const report = await executeHybridAnalysis({
        title: tc.title,
        repository: tc.repository,
        prNumber: tc.pr_number,
        author: tc.author,
        rawFiles: tc.files,
        prUrl: `https://github.com/${tc.repository}/pull/${tc.pr_number}`,
        scenarioBadge: tc.scenario_badge,
        checkLiveOsv: false
      });
      return res.json(report);
    }

    if (Array.isArray(files) && files.length > 0) {
      const report = await executeHybridAnalysis({
        title: title || 'Custom PR Security Scan',
        repository: repository || 'custom-org/custom-repo',
        prNumber: pr_number || 999,
        author: author || 'contributor',
        rawFiles: files,
        prUrl: pr_url || 'https://github.com/custom-org/custom-repo/pull/999',
        scenarioBadge: 'Custom Diff Submission',
        checkLiveOsv: true
      });
      return res.json(report);
    }

    if (pr_url) {
      try {
        const ghData = await fetchGithubPr(pr_url);
        const report = await executeHybridAnalysis({
          title: ghData.title,
          repository: ghData.repository,
          prNumber: ghData.pr_number,
          author: ghData.author,
          rawFiles: ghData.files,
          prUrl: ghData.pr_url,
          scenarioBadge: 'Live GitHub PR Scan',
          checkLiveOsv: true
        });
        return res.json(report);
      } catch (err) {
        const status = err.message.includes('Invalid GitHub PR URL') ? 400 : 502;
        return res.status(status).json({ detail: err.message });
      }
    }

    return res.status(400).json({ detail: 'Provide either pr_url, test_case_id, or files to scan.' });
  } catch (err) {
    res.status(500).json({ detail: err.message });
  }
});

router.get('/scans/:scanId', async (req, res) => {
  await ensureSeeded();
  const record = await getScanReport(req.params.scanId);
  if (!record) {
    return res.status(404).json({ detail: 'Scan report not found' });
  }
  res.json(serializeReport(record));
});

router.post('/scans/:scanId/resolve', async (req, res) => {
  try {
    await ensureSeeded();
    const record = await getScanReport(req.params.scanId);
    if (!record) {
      return res.status(404).json({ detail: 'Scan report not found' });
    }

    const {
      finding_id,
      resolution_action = 'APPLIED_REMEDIATION_PATCH',
      reviewer_note = 'Maintainer applied remediation patch and verified evidence.'
    } = req.body || {};

    let resolvedIds = Array.isArray(record.resolved_finding_ids) ? [...record.resolved_finding_ids] : [];

    if (finding_id === 'ALL') {
      resolvedIds = (record.findings || []).map(f => f.id);
    } else if (resolvedIds.includes(finding_id)) {
      resolvedIds = resolvedIds.filter(id => id !== finding_id);
    } else if (finding_id) {
      resolvedIds.push(finding_id);
    }

    // Fallback if _raw_static_findings or _raw_dep_findings were stripped by older DB docs
    const existingFindings = record.findings || [];
    const rawStatic =
      Array.isArray(record._raw_static_findings) && record._raw_static_findings.length > 0
        ? record._raw_static_findings
        : existingFindings.filter(f => !String(f.id || '').startsWith('DEP-'));
    const rawDep =
      Array.isArray(record._raw_dep_findings) && record._raw_dep_findings.length > 0
        ? record._raw_dep_findings
        : existingFindings.filter(f => String(f.id || '').startsWith('DEP-'));

    const updatedRisk = computeRiskAssessment(
      rawStatic,
      rawDep,
      record.ml_prediction || {},
      resolvedIds
    );

    record.resolved_finding_ids = resolvedIds;
    record.risk_score = updatedRisk.risk_score;
    record.risk_level = updatedRisk.risk_level;
    record.risk_label = updatedRisk.risk_label;
    record.recommended_action = updatedRisk.recommended_action;
    record.score_breakdown = updatedRisk.score_breakdown;
    record.findings = updatedRisk.findings;
    record.open_findings_count = updatedRisk.open_findings_count;
    record.resolved_findings_count = updatedRisk.resolved_findings_count;

    for (const dep of record.dependencies || []) {
      const matchingFinding = (record.findings || []).find(f => f.id.includes(dep.package));
      if (matchingFinding && matchingFinding.status === 'RESOLVED') {
        dep.status = 'REMEDIATED';
      } else if (matchingFinding && matchingFinding.status === 'OPEN') {
        dep.status = dep.is_known_malicious ? 'MALICIOUS' : 'VULNERABLE';
      }
    }

    record.resolution_log = record.resolution_log || [];
    record.resolution_log.push({
      timestamp: new Date().toISOString(),
      finding_id,
      action: resolution_action,
      note: reviewer_note,
      new_risk_score: updatedRisk.risk_score
    });

    if (updatedRisk.open_findings_count === 0 && (record.findings || []).length > 0) {
      record.review_decision = 'REMEDIATED_AND_VERIFIED';
    }

    const saved = await saveScanReport(record);
    res.json(saved);
  } catch (err) {
    res.status(500).json({ detail: err.message });
  }
});

router.post('/scans/:scanId/decision', async (req, res) => {
  await ensureSeeded();
  const record = await getScanReport(req.params.scanId);
  if (!record) {
    return res.status(404).json({ detail: 'Scan report not found' });
  }
  const { decision, reviewer_note = '' } = req.body || {};
  record.review_decision = decision || 'PENDING_REVIEW';
  record.reviewer_note = reviewer_note;
  const saved = await saveScanReport(record);
  res.json(saved);
});

router.get('/ml/metrics', (req, res) => {
  res.json(mlDetectorInstance.metrics);
});

module.exports = { router, executeHybridAnalysis, ensureSeeded };
