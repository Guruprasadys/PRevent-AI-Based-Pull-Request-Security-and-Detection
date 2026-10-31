function detectFileType(filename) {
  const lower = (filename || '').toLowerCase().replace(/\\/g, '/');
  if (
    (lower.startsWith('.github/workflows/') && (lower.endsWith('.yml') || lower.endsWith('.yaml'))) ||
    lower.endsWith('.gitlab-ci.yml')
  ) {
    return 'github_workflow';
  }
  if (
    lower.endsWith('package.json') ||
    lower.endsWith('package-lock.json') ||
    lower.endsWith('yarn.lock') ||
    lower.endsWith('pnpm-lock.yaml')
  ) {
    return 'npm_manifest';
  }
  if (
    lower.endsWith('requirements.txt') ||
    lower.endsWith('pyproject.toml') ||
    lower.endsWith('setup.py') ||
    lower.endsWith('pipfile') ||
    lower.endsWith('poetry.lock')
  ) {
    return 'python_manifest';
  }
  if (lower.endsWith('pom.xml') || lower.endsWith('build.gradle') || lower.endsWith('build.gradle.kts')) {
    return 'maven_manifest';
  }
  if (lower.endsWith('go.mod') || lower.endsWith('go.sum')) {
    return 'go_manifest';
  }
  if (lower.endsWith('cargo.toml') || lower.endsWith('cargo.lock')) {
    return 'rust_manifest';
  }
  if (lower.includes('dockerfile') || lower.endsWith('docker-compose.yml') || lower.endsWith('docker-compose.yaml')) {
    return 'dockerfile';
  }
  const extMap = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.go': 'go',
    '.java': 'java',
    '.rs': 'rust',
    '.yml': 'yaml',
    '.yaml': 'yaml',
    '.json': 'json',
    '.sh': 'shell',
    '.md': 'markdown'
  };
  for (const [ext, ftype] of Object.entries(extMap)) {
    if (lower.endsWith(ext)) return ftype;
  }
  return 'other';
}

function parsePatch(filename, patch = '', status = 'modified') {
  const fileType = detectFileType(filename);
  const addedLines = [];
  const removedLines = [];
  let additions = 0;
  let deletions = 0;

  let currentNewLine = 1;
  let currentOldLine = 1;

  const hunkHeaderRe = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;
  const rawLines = (patch || '').split(/\r?\n/);
  const hasDiffPrefixes = rawLines.some(
    l => l.startsWith('+') || l.startsWith('-') || l.startsWith('@@')
  );

  for (const rawLine of rawLines) {
    const m = rawLine.match(hunkHeaderRe);
    if (m) {
      currentOldLine = parseInt(m[1], 10);
      currentNewLine = parseInt(m[2], 10);
      continue;
    }
    if (rawLine.startsWith('+++') || rawLine.startsWith('---')) {
      continue;
    }
    if (rawLine.startsWith('+')) {
      addedLines.push({ line_number: currentNewLine, content: rawLine.slice(1) });
      additions += 1;
      currentNewLine += 1;
    } else if (rawLine.startsWith('-')) {
      removedLines.push({ line_number: currentOldLine, content: rawLine.slice(1) });
      deletions += 1;
      currentOldLine += 1;
    } else if (!hasDiffPrefixes && rawLine.trim()) {
      addedLines.push({ line_number: currentNewLine, content: rawLine });
      additions += 1;
      currentNewLine += 1;
    } else {
      currentOldLine += 1;
      currentNewLine += 1;
    }
  }

  return {
    filename,
    status,
    additions,
    deletions,
    patch,
    file_type: fileType,
    added_lines: addedLines,
    removed_lines: removedLines
  };
}

module.exports = { detectFileType, parsePatch };
