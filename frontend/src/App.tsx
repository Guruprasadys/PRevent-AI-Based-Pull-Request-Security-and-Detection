import React, { useEffect, useState } from 'react';
import {
  DashboardSummary,
  ScanReport,
  TestCaseItem,
  fetchDashboardSummary,
  fetchTestCases,
  scanPullRequest,
  resolveFindingApi,
  updateReviewDecisionApi,
  clearAllScansApi
} from './services/api';
import { ActiveTab } from './utils/theme';
import { Navbar } from './components/Navbar';
import { SecurityReportModal } from './components/SecurityReportModal';
import { OverviewDashboard } from './pages/OverviewDashboard';
import { PrAnalysisPage } from './pages/PrAnalysisPage';
import { DependencyIntelligencePage } from './pages/DependencyIntelligencePage';
import { TestSuitePage } from './pages/TestSuitePage';
import { AiEnginePage } from './pages/AiEnginePage';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [selectedScan, setSelectedScan] = useState<ScanReport | null>(null);
  const [testCases, setTestCases] = useState<TestCaseItem[]>([]);
  const [passedCount, setPassedCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Interactive Resolution & Modal state
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [resolutionNote, setResolutionNote] = useState(
    'Applied suggested safe remediation patch & verified code.'
  );
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  const loadAllData = async (selectDefaultIfNone = true) => {
    try {
      const [sumData, tcData] = await Promise.all([fetchDashboardSummary(), fetchTestCases()]);
      setSummary(sumData);
      setTestCases(tcData.test_cases);
      setPassedCount(tcData.passed_count);

      if (sumData.recent_scans.length === 0) {
        setSelectedScan(null);
      } else if (selectDefaultIfNone && !selectedScan) {
        setSelectedScan(sumData.recent_scans[0]);
      } else if (selectedScan) {
        const refreshed = sumData.recent_scans.find(s => s.scan_id === selectedScan.scan_id);
        setSelectedScan(refreshed || sumData.recent_scans[0]);
      }
    } catch (e: any) {
      setErrorMsg(e.message || 'Failed to connect to MERN backend on port 5000');
    }
  };

  const handleClearHistory = async () => {
    try {
      await clearAllScansApi();
      setSelectedScan(null);
      await loadAllData(false);
    } catch (e: any) {
      setErrorMsg(e.message || 'Failed to clear scan history');
    }
  };

  useEffect(() => {
    loadAllData(true);
  }, []);

  const handleRunTestCase = async (tcId: string, targetTab: ActiveTab = 'pr-analysis') => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const report = await scanPullRequest({ test_case_id: tcId });
      setSelectedScan(report);
      // Immediately refresh dashboard summary in state so all tabs (including Dependency Intel)
      // see the newly scanned PR right away without needing a manual browser refresh
      const [sumData, tcData] = await Promise.all([fetchDashboardSummary(), fetchTestCases()]);
      setSummary(sumData);
      setTestCases(tcData.test_cases);
      setPassedCount(tcData.passed_count);
      setActiveTab(targetTab);
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleScanUrl = async (url: string) => {
    if (!url.trim()) {
      setErrorMsg('Please enter a valid GitHub Pull Request URL (e.g. https://github.com/owner/repo/pull/123)');
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    try {
      const report = await scanPullRequest({ pr_url: url.trim() });
      setSelectedScan(report);
      await loadAllData(false);
      setActiveTab('pr-analysis');
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleScanCustom = async (title: string, filename: string, patch: string) => {
    if (!patch.trim()) {
      setErrorMsg('Please enter or paste code/dependency diff lines in the Unified Diff box before scanning.');
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    try {
      const report = await scanPullRequest({
        title: title.trim() || 'Custom PR Security Scan',
        repository: 'custom-org/security-sandbox',
        pr_number: Math.floor(200 + Math.random() * 700),
        author: 'sandbox-contributor',
        files: [{ filename: filename.trim() || 'src/index.js', status: 'modified', patch }]
      });
      setSelectedScan(report);
      await loadAllData(false);
      setActiveTab('pr-analysis');
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResolveFinding = async (findingId: string, actionLabel = 'APPLIED_REMEDIATION_PATCH') => {
    if (!selectedScan) return;
    setResolvingId(findingId);
    try {
      const updated = await resolveFindingApi(
        selectedScan.scan_id,
        findingId,
        actionLabel,
        resolutionNote
      );
      setSelectedScan(updated);
      await loadAllData(false);
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setResolvingId(null);
    }
  };

  const handleDecisionUpdate = async (decision: string) => {
    if (!selectedScan) return;
    try {
      const updated = await updateReviewDecisionApi(selectedScan.scan_id, decision, resolutionNote);
      setSelectedScan(updated);
      await loadAllData(false);
    } catch (e: any) {
      setErrorMsg(e.message);
    }
  };

  const handleCopyText = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleExportReport = () => {
    if (!selectedScan) return;
    const blob = new Blob([JSON.stringify(selectedScan, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedScan.scan_id}-security-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col selection:bg-indigo-500 selection:text-white">
      {/* Top Glassmorphic Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        selectedScan={selectedScan}
        passedCount={passedCount}
        totalTestCases={testCases.length}
        summary={summary}
      />

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto w-full px-4 sm:px-6 py-6 flex-1 space-y-6">
        {errorMsg && (
          <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/35 text-rose-200 text-xs sm:text-sm flex items-center justify-between shadow-lg">
            <span>{errorMsg}</span>
            <button
              onClick={() => setErrorMsg(null)}
              className="text-xs font-bold underline ml-4 hover:text-white"
            >
              Dismiss
            </button>
          </div>
        )}

        {activeTab === 'overview' && (
          <OverviewDashboard
            summary={summary}
            loading={loading}
            onScanUrl={handleScanUrl}
            onScanCustom={handleScanCustom}
            onSelectScan={scan => {
              setSelectedScan(scan);
              setActiveTab('pr-analysis');
            }}
            onRefresh={() => loadAllData(false)}
            onClearHistory={handleClearHistory}
          />
        )}

        {activeTab === 'pr-analysis' && (
          selectedScan ? (
            <PrAnalysisPage
              scan={selectedScan}
              resolvingId={resolvingId}
              copiedId={copiedId}
              resolutionNote={resolutionNote}
              setResolutionNote={setResolutionNote}
              onResolveFinding={handleResolveFinding}
              onDecisionUpdate={handleDecisionUpdate}
              onCopyPatch={handleCopyText}
              onExportJson={handleExportReport}
              onOpenReportModal={() => setIsReportModalOpen(true)}
            />
          ) : (
            <div className="p-10 rounded-2xl bg-slate-900/75 border border-slate-800 text-center space-y-3">
              <h3 className="text-base font-bold text-white">No Pull Request Scanned Yet</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Paste any public GitHub Pull Request URL or select a live open PR on the Security Dashboard to run a scan and inspect the results here.
              </p>
              <button
                onClick={() => setActiveTab('overview')}
                className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold transition"
              >
                Go to Security Dashboard
              </button>
            </div>
          )
        )}

        {activeTab === 'dependencies' && (
          <DependencyIntelligencePage
            summary={summary}
            selectedScan={selectedScan}
            resolvingId={resolvingId}
            onRunTestCase={handleRunTestCase}
            onResolveFinding={handleResolveFinding}
          />
        )}

        {activeTab === 'test-suite' && (
          <TestSuitePage
            testCases={testCases}
            passedCount={passedCount}
            loading={loading}
            onRunTestCase={handleRunTestCase}
          />
        )}

        {activeTab === 'ai-engine' && (
          <AiEnginePage summary={summary} selectedScan={selectedScan} />
        )}
      </main>

      {/* GitHub Bot Summary & Report Modal */}
      <SecurityReportModal
        scan={selectedScan}
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        copiedId={copiedId}
        onCopy={handleCopyText}
        onExportJson={handleExportReport}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/60 py-4 px-6 mt-12">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
          <span>
            PRevent — Malicious PR & Dependency-Update Detector (MERN Stack: MongoDB · Express · React · Node.js)
          </span>
          <span>Decision-Support Supply-Chain Security Platform · Never executes untrusted PR code</span>
        </div>
      </footer>
    </div>
  );
}
