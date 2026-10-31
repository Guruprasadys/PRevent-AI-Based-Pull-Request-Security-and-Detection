function runStaticRules(changedFiles) {
  const findings = [];

  for (const cf of changedFiles) {
    const addedLines = cf.added_lines || [];
    let hasSecretAccess = false;
    let secretLine = 1;
    let secretSnippet = '';

    let hasNetworkSend = false;
    let networkLine = 1;
    let networkSnippet = '';

    for (const item of addedLines) {
      const ln = Number(item.line_number) || 1;
      const txt = String(item.content || '');

      // 1. Check sensitive credential / env access
      if (
        /(os\.environ|os\.getenv\s*\(\s*['"](?:[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|DATABASE_URL|AWS)[A-Z0-9_]*)['"]|process\.env|\.ssh\/id_rsa|\.aws\/credentials|\.npmrc|open\s*\(\s*['"]\.env['"])/i.test(
          txt
        )
      ) {
        hasSecretAccess = true;
        secretLine = ln;
        secretSnippet = txt.trim();
      }

      // Check outbound network call
      if (
        /(requests\.(?:post|put|get)|urllib\.request|httpx\.(?:post|get)|https?\.(?:request|get)|fetch\s*\(|socket\.socket|socket\.gethostbyname|curl\s+.*(?:-d|--data|-X\s*POST)|webhook\.site|discord\.com\/api\/webhooks)/i.test(
          txt
        )
      ) {
        hasNetworkSend = true;
        networkLine = ln;
        networkSnippet = txt.trim();
      }

      // 2. Dangerous Build / Install Script Hooks (package.json)
      if (cf.file_type === 'npm_manifest' || cf.filename.endsWith('package.json')) {
        if (
          /"(?:preinstall|install|postinstall)"\s*:\s*".*(?:curl|wget|bash|sh\b|nc\b|python|node\s+-e|powershell)/i.test(
            txt
          )
        ) {
          findings.push({
            id: `RULE-INSTALL-${cf.filename}-${ln}`,
            category: 'dangerous_install_script',
            rule_id: 'SEC-INSTALL-001',
            severity: 'CRITICAL',
            title: 'Suspicious npm lifecycle install script executing shell/network command',
            description:
              'Added a `preinstall`, `install`, or `postinstall` hook in `package.json` that downloads or executes external commands automatically during `npm install`.',
            file: cf.filename,
            line: ln,
            snippet: txt.trim(),
            remediation:
              'Remove remote shell execution from `package.json` lifecycle scripts and run `npm install --ignore-scripts` in CI.',
            suggested_patch: `- ${txt.trim()}\n+ // Removed unsafe lifecycle install script hook`
          });
        }
      }

      // setup.py or Python/JS shell execution
      if (cf.filename.endsWith('setup.py') || cf.file_type === 'python' || cf.file_type === 'javascript') {
        if (
          /(os\.system|subprocess\.(?:Popen|call|run)|child_process\.exec)\s*\(.*(?:curl|wget|\/dev\/tcp\/|nc\s+-e|powershell|chmod\s+\+x|\/bin\/sh)/i.test(
            txt
          )
        ) {
          findings.push({
            id: `RULE-EXEC-${cf.filename}-${ln}`,
            category: cf.filename.endsWith('setup.py') ? 'dangerous_install_script' : 'dangerous_execution',
            rule_id: 'SEC-EXEC-002',
            severity: 'CRITICAL',
            title: 'Remote payload or shell execution via subprocess/os.system/exec',
            description:
              'Code executes a shell command that fetches remote binaries, opens a reverse shell, or invokes hidden system commands.',
            file: cf.filename,
            line: ln,
            snippet: txt.trim(),
            remediation:
              'Eliminate shell command execution (`os.system`, `shell=True`, `child_process.exec`) and audit the contributor branch for unauthorized backdoors.',
            suggested_patch: `# BLOCKED: Unsafe command execution removed\n# ${txt.trim()}`
          });
        }
      }

      // 3. Obfuscated or Hidden Code
      if (
        /(base64\.b64decode|Buffer\.from\([^,]+,\s*['"]base64['"]\)|\batob\s*\(|zlib\.decompress|marshal\.loads|bytes\.fromhex|__import__\s*\(\s*['"]['"]\.join|new\s+Function\s*\(|\beval\s*\(\s*compile\s*\()/i.test(
          txt
        )
      ) {
        findings.push({
          id: `RULE-OBF-${cf.filename}-${ln}`,
          category: 'obfuscation',
          rule_id: 'SEC-OBF-003',
          severity: 'HIGH',
          title: 'Obfuscated payload decoding or dynamic execution indicator',
          description:
            'Detected encoded payload decoding (`base64`, `hex`, `zlib`, `marshal`) or dynamic code construction (`eval`, `new Function`, `__import__`) often used to conceal malicious logic from code reviewers.',
          file: cf.filename,
          line: ln,
          snippet: txt.trim(),
          remediation:
            'Require contributors to submit human-readable, unencoded source code. Decode and inspect the payload in an isolated sandbox before merging.',
          suggested_patch: `# Replace obfuscated/encoded execution with transparent, auditable code\n# Original flagged line: ${txt.trim()}`
        });
      }

      // 4. Suspicious GitHub Actions Workflow Modifications
      if (
        cf.file_type === 'github_workflow' ||
        cf.filename.includes('.github/workflows') ||
        /(pull_request_target|permissions\s*:\s*write-all|toJSON\s*\(\s*secrets\s*\))/.test(txt)
      ) {
        if (
          /(pull_request_target|permissions\s*:\s*write-all|toJSON\s*\(\s*secrets\s*\)|secrets\.[A-Z0-9_]+.*(?:curl|wget)|curl\s+.*chmod\s+\+x)/i.test(
            txt
          )
        ) {
          findings.push({
            id: `RULE-WF-${cf.filename}-${ln}`,
            category: 'workflow_compromise',
            rule_id: 'SEC-CI-004',
            severity: 'HIGH',
            title: 'Risky GitHub Actions workflow trigger, permission escalation, or secret exposure',
            description:
              'Workflow modification uses `pull_request_target`, grants `write-all` permissions, or pipes repository secrets to an external command.',
            file: cf.filename,
            line: ln,
            snippet: txt.trim(),
            remediation:
              'Use `on: pull_request` instead of `pull_request_target` for untrusted forks, enforce least-privilege `permissions: contents: read`, and never pass `secrets` to curl/shell commands.',
            suggested_patch: 'on:\n  pull_request:\npermissions:\n  contents: read'
          });
        }
      }
    }

    // Combined secret access + outbound transfer finding
    if (hasSecretAccess && hasNetworkSend) {
      findings.push({
        id: `RULE-EXFIL-${cf.filename}-${networkLine}`,
        category: 'secret_exfiltration',
        rule_id: 'SEC-EXFIL-001',
        severity: 'CRITICAL',
        title: 'Suspicious secret/credential access paired with outbound network transfer',
        description: `File accesses sensitive credentials or environment variables (\`${secretSnippet.slice(0, 60)}\`) and transmits data over an outbound network connection (\`${networkSnippet.slice(0, 60)}\`).`,
        file: cf.filename,
        line: networkLine,
        snippet: `${secretSnippet}  -->  ${networkSnippet}`,
        remediation:
          'Block PR immediately. Rotate any potentially exposed secrets/tokens and remove unauthorized outbound telemetry or credential harvesting code.',
        suggested_patch: `# REMOVED CREDENTIAL EXFILTRATION PATTERN\n# Line ${secretLine}: ${secretSnippet}\n# Line ${networkLine}: ${networkSnippet}`
      });
    }
  }

  return findings;
}

module.exports = { runStaticRules };
