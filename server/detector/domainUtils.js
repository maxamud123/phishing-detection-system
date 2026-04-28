'use strict';

function extractDomain(url) {
  try {
    let u = url.trim();
    if (!u.match(/^https?:\/\//i)) u = 'http://' + u;
    return new URL(u).hostname.toLowerCase();
  } catch {
    const m = url.match(/(?:https?:\/\/)?([^/\s:?#]+)/i);
    return m ? m[1].toLowerCase() : url.toLowerCase();
  }
}

// Levenshtein distance — used for typosquatting detection
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}

module.exports = { extractDomain, levenshtein };
