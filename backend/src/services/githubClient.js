const GITHUB_PR_RE = /github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/i;

function getCleanGithubToken() {
  return String(process.env.GITHUB_TOKEN || '')
    .replace(/^GITHUB_TOKEN\s*=\s*/i, '')
    .replace(/^['"]|['"]$/g, '')
    .trim();
}

function getGithubHeaders(includeToken = true) {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'PRevent-MERN-SupplyChain-Scanner/1.0'
  };
  if (includeToken) {
    const token = getCleanGithubToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }
  return headers;
}

async function githubFetch(url) {
  const hasToken = Boolean(getCleanGithubToken());
  let resp = await fetch(url, { headers: getGithubHeaders(true) });
  // If a fine-grained or expired token returns 401/403 on a public repo, retry cleanly without token
  if ((resp.status === 401 || resp.status === 403) && hasToken) {
    const retryResp = await fetch(url, { headers: getGithubHeaders(false) });
    if (retryResp.ok) {
      return retryResp;
    }
  }
  return resp;
}

function parseGithubPrUrl(prUrl) {
  const m = String(prUrl || '').trim().match(GITHUB_PR_RE);
  if (!m) {
    throw new Error(
      'Invalid GitHub PR URL. Expected format: https://github.com/<owner>/<repo>/pull/<number>'
    );
  }
  return {
    owner: m[1],
    repo: m[2],
    prNumber: parseInt(m[3], 10)
  };
}

async function fetchGithubPr(prUrl) {
  const { owner, repo, prNumber } = parseGithubPrUrl(prUrl);

  const prApiUrl = `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}`;
  const filesApiUrl = `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100`;

  const prResp = await githubFetch(prApiUrl);
  if (!prResp.ok) {
    const errText = await prResp.text();
    throw new Error(`GitHub API returned ${prResp.status}: ${errText.slice(0, 180)}`);
  }

  const filesResp = await githubFetch(filesApiUrl);
  if (!filesResp.ok) {
    const errText = await filesResp.text();
    throw new Error(`GitHub Files API returned ${filesResp.status}: ${errText.slice(0, 180)}`);
  }

  const prData = await prResp.json();
  const filesData = await filesResp.json();

  const changedFiles = (filesData || []).map(f => ({
    filename: f.filename || 'unknown',
    status: f.status || 'modified',
    additions: f.additions || 0,
    deletions: f.deletions || 0,
    patch: f.patch || ''
  }));

  return {
    pr_url: `https://github.com/${owner}/${repo}/pull/${prNumber}`,
    repository: `${owner}/${repo}`,
    pr_number: prNumber,
    title: prData.title || `PR #${prNumber}`,
    author: (prData.user && prData.user.login) || 'unknown',
    created_at: prData.created_at || '',
    state: prData.state || 'open',
    files: changedFiles
  };
}

/**
 * Fetch live open Pull Requests from any public GitHub repository (e.g. "expressjs/express")
 */
async function fetchOpenPullRequestsFromRepo(repoFullName = 'expressjs/express') {
  const cleanRepo = String(repoFullName || 'expressjs/express')
    .replace(/^https?:\/\/github\.com\//i, '')
    .replace(/\/+$/, '')
    .trim();
  const parts = cleanRepo.split('/');
  if (parts.length < 2) {
    throw new Error('Expected repository in format: owner/repo (e.g. expressjs/express)');
  }
  const owner = parts[0];
  const repo = parts[1];

  const url = `https://api.github.com/repos/${owner}/${repo}/pulls?state=open&per_page=6`;
  const resp = await githubFetch(url);
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`GitHub API (${resp.status}): ${errText.slice(0, 160)}`);
  }
  const list = await resp.json();
  return (list || []).map(pr => {
    const canonicalUrl = pr.html_url || `https://github.com/${owner}/${repo}/pull/${pr.number}`;
    return {
      pr_number: pr.number,
      title: pr.title,
      author: (pr.user && pr.user.login) || 'unknown',
      pr_url: canonicalUrl,
      html_url: canonicalUrl,
      created_at: pr.created_at,
      updated_at: pr.updated_at || pr.created_at,
      repository: `${owner}/${repo}`
    };
  });
}

module.exports = {
  parseGithubPrUrl,
  fetchGithubPr,
  fetchOpenPullRequestsFromRepo,
  getCleanGithubToken
};
