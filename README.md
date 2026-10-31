# PRevent — Malicious PR & Dependency-Update Detector (MERN Stack)

A hybrid AI, static analysis, and supply-chain dependency security platform built with the **MERN Stack (MongoDB, Express.js, React, Node.js)** to protect open-source repositories before malicious Pull Requests or compromised dependency updates are merged.

---

## 1. Architecture & Hybrid Detection Modules

1. **Module 1 — Static Security Analysis (`backend/src/services/ruleEngine.js`)**
   - Detects credential & secret exfiltration (`os.environ`, `process.env`, `~/.ssh/id_rsa`, `~/.npmrc` paired with outbound HTTP/socket calls).
   - Flags dangerous build/lifecycle hooks (`preinstall`, `install`, `postinstall` in `package.json`, `setup.py` custom commands).
   - Identifies obfuscated payloads (`base64`, `Buffer.from`, `atob`, `zlib`, `marshal`, `eval`, `new Function`).
   - Audits GitHub Actions workflow changes (`pull_request_target`, `permissions: write-all`, secret dumps).
2. **Module 2 — Dependency Risk Analysis (`backend/src/services/dependencyScanner.js`)**
   - Parses `package.json` and `requirements.txt` diffs (`old_version -> new_version`).
   - Queries **OSV API** for known CVE/GHSA vulnerabilities and checks against **OpenSSF / Datadog** malicious & typosquatted package intelligence (`event-stream`, `flatmap-stream`, `ua-parser-js`, `node-ipc`, `reqeusts`, `colourama`, etc.).
3. **Module 3 — In-Memory AI & Heuristic Pattern Classifier (`backend/src/services/mlDetector.js`)**
   - Self-contained **In-Memory TF-IDF + L2 Logistic Regression** engine with built-in security pattern calibration (zero external CSV dataset files required).
   - Reports **Precision, Recall, F1-Score, False-Positive Rate (FPR)**, and confusion matrix.
4. **Module 4 — Transparent Risk-Scoring & Issue Resolution Engine (`backend/src/services/riskEngine.js`)**
   - Combines deduplicated evidence weights (capped at `100`):
     - `0–24`: **LOW** (Low risk)
     - `25–49`: **MEDIUM** (Medium risk)
     - `50–74`: **HIGH** (High risk)
     - `75–100`: **CRITICAL** (Critical review recommended)
   - **Interactive "Resolve the Issue" Workflow**: Maintainers can apply suggested safe remediation patches or mark findings resolved with trusted evidence, dynamically recalculating the PR risk score in real time.

---

## 2. Project Folder Structure

```text
Hackothon/
├── backend/                                      # Node.js + Express + MongoDB (Mongoose)
│   ├── src/
│   │   ├── config/db.js                          # Mongoose connection + automatic in-memory fallback
│   │   ├── models/ScanReport.js                  # Mongoose schema for PR scans, findings & audit logs
│   │   ├── services/
│   │   │   ├── githubClient.js                   # GitHub REST API PR & patch fetcher
│   │   │   ├── diffParser.js                     # Unified diff parser & line number extractor
│   │   │   ├── featureExtractor.js               # Diff feature extractor
│   │   │   ├── ruleEngine.js                     # Static security rules
│   │   │   ├── dependencyScanner.js              # OSV API + malicious package detector
│   │   │   ├── mlDetector.js                     # Self-contained in-memory AI/ML classifier
│   │   │   └── riskEngine.js                     # Risk score calculator & issue resolver
│   │   ├── data/testCasesData.js                 # 22 interactive PR test scenarios
│   │   ├── routes/api.js                         # Express REST API endpoints
│   │   └── server.js                             # Express entry point (port 5000)
│   ├── tests/scanner.test.js                     # 25 automated Node.js tests
│   └── package.json
├── frontend/                                     # React + TypeScript + Tailwind CSS + Vite
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.tsx                        # Glassmorphic top navigation & status bar
│   │   │   ├── DemoScenarioBanner.tsx            # 3 Judge Demo 1-click scenario cards
│   │   │   ├── RiskGauge.tsx                     # Radial SVG risk score gauge & action controls
│   │   │   ├── EvidenceGraph.tsx                 # 4-stage interactive evidence & attack-chain graph
│   │   │   ├── FindingCard.tsx                   # Side-by-side code evidence & remediation patch card
│   │   │   ├── DiffViewer.tsx                    # Syntax-highlighted unified diff inspector
│   │   │   └── SecurityReportModal.tsx           # GitHub PR Bot Markdown comment modal
│   │   ├── pages/
│   │   │   ├── OverviewDashboard.tsx             # KPI cards, risk charts, sandbox & scan history
│   │   │   ├── PrAnalysisPage.tsx                # PR analysis & interactive issue resolution workbench
│   │   │   ├── DependencyIntelligencePage.tsx    # Version diff timeline & supply-chain encyclopedia
│   │   │   ├── TestSuitePage.tsx                 # 22+ interactive test scenarios runner
│   │   │   └── AiEnginePage.tsx                  # In-memory AI heuristic engine inspector
│   │   ├── services/api.ts                       # Backend API client & TypeScript types
│   │   ├── utils/theme.ts                        # Styling helpers & GitHub bot comment formatter
│   │   ├── App.tsx
│   │   └── main.tsx
│   └── package.json
├── .github/workflows/prevent-pr-scanner.yml      # GitHub Actions CI workflow
└── .env.example
```

---

## 3. Running the Application & Tests

### Run the 25 Automated Tests
```bash
npm test
```

### Start the Express + MongoDB Backend (Port 5000)
```bash
npm run start:backend
```

### Start the React Dashboard (Port 5173)
```bash
npm run start:frontend
```
