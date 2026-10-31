const CATEGORY_WEIGHTS = {
  secret_exfiltration: 35,
  malicious_dependency: 40,
  vulnerable_dependency: 30,
  dangerous_install_script: 30,
  dangerous_execution: 30,
  obfuscation: 25,
  workflow_compromise: 20
};

const ML_SUSPICIOUS_WEIGHT = 15;

function classifyRiskLevel(score) {
  if (score >= 75) {
    return {
      level: 'CRITICAL',
      label: 'Critical review recommended',
      recommended_action:
        'BLOCK MERGE immediately. Isolate branch, do NOT execute CI workflows with secrets, and conduct manual security audit.'
    };
  } else if (score >= 50) {
    return {
      level: 'HIGH',
      label: 'High risk',
      recommended_action:
        'HOLD MERGE. Require senior maintainer security review and verify all flagged lines and package versions.'
    };
  } else if (score >= 25) {
    return {
      level: 'MEDIUM',
      label: 'Medium risk',
      recommended_action:
        'REVIEW CAREFULLY. Inspect dependency advisories or workflow changes before approving.'
    };
  }
  return {
    level: 'LOW',
    label: 'Low risk',
    recommended_action:
      'SAFE FOR STANDARD REVIEW. No high-risk supply-chain or code exfiltration indicators detected.'
  };
}

function computeRiskAssessment(staticFindings, dependencyFindings, mlResult, resolvedFindingIds = []) {
  const resolvedSet = new Set(resolvedFindingIds || []);
  const allFindings = [];

  for (const f of [...staticFindings, ...dependencyFindings]) {
    allFindings.push({
      ...f,
      status: resolvedSet.has(f.id) ? 'RESOLVED' : 'OPEN'
    });
  }

  const activeFindings = allFindings.filter(f => f.status === 'OPEN');
  const seenCategories = new Set();
  const scoreBreakdown = [];
  let rawScore = 0;

  for (const f of activeFindings) {
    const cat = f.category || 'other';
    if (!seenCategories.has(cat)) {
      seenCategories.add(cat);
      const weight = CATEGORY_WEIGHTS[cat] || 15;
      rawScore += weight;
      scoreBreakdown.push({
        source: `Finding (${cat})`,
        title: f.title,
        points: weight
      });
    }
  }

  if (seenCategories.size >= 2) {
    rawScore += 15;
    scoreBreakdown.push({
      source: 'Multi-Vector Correlation',
      title: 'Multiple distinct security risk categories detected in the same PR',
      points: 15
    });
  } else if (
    ['secret_exfiltration', 'malicious_dependency', 'dangerous_install_script', 'dangerous_execution'].some(c =>
      seenCategories.has(c)
    )
  ) {
    rawScore += 25;
    scoreBreakdown.push({
      source: 'High-Severity Attack Vector',
      title: 'Critical supply-chain or credential exfiltration indicator present',
      points: 25
    });
  }

  if (mlResult && mlResult.flagged && (activeFindings.length > 0 || resolvedSet.size === 0)) {
    rawScore += ML_SUSPICIOUS_WEIGHT;
    scoreBreakdown.push({
      source: 'ML Classifier (TF-IDF + LogReg)',
      title: mlResult.explanation || 'ML model flagged the diff as suspicious',
      points: ML_SUSPICIOUS_WEIGHT
    });
  }

  const finalScore = Math.min(100, Math.max(0, rawScore));
  const classification = classifyRiskLevel(finalScore);

  return {
    risk_score: finalScore,
    risk_level: classification.level,
    risk_label: classification.label,
    recommended_action: classification.recommended_action,
    score_breakdown: scoreBreakdown,
    findings: allFindings,
    open_findings_count: activeFindings.length,
    resolved_findings_count: allFindings.length - activeFindings.length
  };
}

module.exports = { computeRiskAssessment, classifyRiskLevel };
