const DANGEROUS_APIS = [
  /\beval\s*\(/g,
  /\bexec\s*\(/g,
  /\bcompile\s*\(/g,
  /\b__import__\s*\(/g,
  /subprocess\.(?:Popen|call|run|check_output)/g,
  /os\.(?:system|popen|execl|execve|dup2)/g,
  /child_process\.(?:exec|execSync|spawn|spawnSync)/g,
  /new\s+Function\s*\(/g
];

const NETWORK_INDICATORS = [
  /requests\.(?:post|put|get)/gi,
  /urllib\.request\.urlopen/gi,
  /httpx\.(?:post|get|AsyncClient)/gi,
  /https?\.(?:request|get)/gi,
  /fetch\s*\(/gi,
  /socket\.socket/gi,
  /\bcurl\s+/gi,
  /\bwget\s+/gi,
  /\/dev\/tcp\//gi,
  /\bnc\s+-e/gi
];

const SECRET_INDICATORS = [
  /os\.environ/g,
  /os\.getenv/g,
  /process\.env/g,
  /\.ssh\/id_rsa/g,
  /\.aws\/credentials/g,
  /\.npmrc/g,
  /\.env\b/g,
  /secrets\./g,
  /PRIVATE_KEY/g,
  /SECRET_KEY/g,
  /AWS_SECRET/g,
  /GITHUB_TOKEN/g
];

const OBFUSCATION_INDICATORS = [
  /base64\.b64decode/g,
  /Buffer\.from\([^,]+,\s*['"]base64['"]\)/g,
  /\batob\s*\(/g,
  /zlib\.decompress/g,
  /marshal\.loads/g,
  /bytes\.fromhex/g,
  /-Enc\b/g,
  /_0x[0-9a-fA-F]+/g
];

const WORKFLOW_RISK_INDICATORS = [
  /pull_request_target/i,
  /permissions\s*:\s*write-all/i,
  /toJSON\s*\(\s*secrets\s*\)/i,
  /chmod\s+\+x/i
];

function countMatches(text, regexList) {
  let count = 0;
  for (const rx of regexList) {
    const matches = text.match(rx);
    if (matches) count += matches.length;
  }
  return count;
}

function extractFeatures(changedFiles) {
  const allAddedLines = [];
  const fileTypes = new Set();
  let dependencyChange = false;
  let workflowPermissionChange = false;

  for (const cf of changedFiles) {
    fileTypes.add(cf.file_type);
    if (
      cf.file_type === 'npm_manifest' ||
      cf.file_type === 'python_manifest' ||
      cf.filename.endsWith('setup.py')
    ) {
      dependencyChange = true;
    }
    for (const line of cf.added_lines) {
      allAddedLines.push(String(line.content));
    }
    if (cf.file_type === 'github_workflow' || cf.filename.includes('.github/workflows')) {
      const wfText = cf.added_lines.map(l => l.content).join('\n');
      if (WORKFLOW_RISK_INDICATORS.some(rx => rx.test(wfText))) {
        workflowPermissionChange = true;
      }
    }
  }

  const diffText = allAddedLines.join('\n');
  const dangerousApiCount = countMatches(diffText, DANGEROUS_APIS);
  const networkActivityCount = countMatches(diffText, NETWORK_INDICATORS);
  const secretAccessCount = countMatches(diffText, SECRET_INDICATORS);
  const obfuscationCount = countMatches(diffText, OBFUSCATION_INDICATORS);

  return {
    diff_text: diffText,
    changed_file_types: Array.from(fileTypes).sort(),
    dependency_change: dependencyChange,
    dangerous_api_count: dangerousApiCount,
    network_activity: networkActivityCount > 0,
    network_activity_count: networkActivityCount,
    secret_access_count: secretAccessCount,
    obfuscation_indicators: obfuscationCount,
    workflow_permission_change: workflowPermissionChange,
    total_added_lines: allAddedLines.length
  };
}

module.exports = { extractFeatures };
