const mongoose = require('mongoose');

const FindingSchema = new mongoose.Schema({
  id: { type: String, required: true },
  category: { type: String, required: true },
  rule_id: { type: String, required: true },
  severity: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  file: { type: String, required: true },
  line: { type: Number, default: 1 },
  snippet: { type: String, default: '' },
  remediation: { type: String, default: '' },
  suggested_patch: { type: String, default: '' },
  status: { type: String, enum: ['OPEN', 'RESOLVED'], default: 'OPEN' }
}, { _id: false });

const DependencySchema = new mongoose.Schema({
  package: { type: String, required: true },
  ecosystem: { type: String, required: true },
  manifest_format: { type: String, default: '' },
  old_version: { type: String, default: 'None (New)' },
  new_version: { type: String, required: true },
  change_type: { type: String, default: 'added' },
  file: { type: String, required: true },
  line: { type: Number, default: 1 },
  is_known_malicious: { type: Boolean, default: false },
  vulnerabilities: { type: Array, default: [] },
  status: { type: String, default: 'CLEAN' },
  detection_rule: { type: String, default: '' },
  decision_factors: { type: [String], default: [] },
  precautions: { type: [String], default: [] },
  resolution_steps: { type: [String], default: [] }
}, { _id: false });

const ScanReportSchema = new mongoose.Schema({
  scan_id: { type: String, required: true, unique: true, index: true },
  timestamp: { type: String, required: true },
  pr_url: { type: String, required: true },
  scenario_badge: { type: String, default: null },
  repository: { type: String, required: true },
  pr_number: { type: Number, required: true },
  title: { type: String, required: true },
  author: { type: String, required: true },
  review_decision: { type: String, default: 'PENDING_REVIEW' },
  reviewer_note: { type: String, default: '' },
  risk_score: { type: Number, required: true },
  initial_risk_score: { type: Number, required: true },
  risk_level: { type: String, required: true },
  risk_label: { type: String, required: true },
  recommended_action: { type: String, required: true },
  score_breakdown: { type: Array, default: [] },
  findings: [FindingSchema],
  open_findings_count: { type: Number, default: 0 },
  resolved_findings_count: { type: Number, default: 0 },
  resolved_finding_ids: { type: [String], default: [] },
  resolution_log: { type: Array, default: [] },
  dependencies: [DependencySchema],
  ml_prediction: { type: Object, default: {} },
  features: { type: Object, default: {} },
  files: { type: Array, default: [] },
  _raw_static_findings: { type: Array, default: [] },
  _raw_dep_findings: { type: Array, default: [] }
}, { timestamps: true });

const ScanReportModel = mongoose.models.ScanReport || mongoose.model('ScanReport', ScanReportSchema);

module.exports = { ScanReportModel, ScanReportSchema };
