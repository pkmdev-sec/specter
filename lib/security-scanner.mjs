/**
 * SPECTER — Security Scanner
 * Scans outputs for security vulnerabilities, secrets, and injection patterns.
 */

const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/g, severity: 'critical' },
  { name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}/g, severity: 'critical' },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g, severity: 'critical' },
  { name: 'GitHub Personal Access Token', pattern: /github_pat_[A-Za-z0-9_]{22,255}/g, severity: 'critical' },
  { name: 'Generic API Key', pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}/gi, severity: 'high' },
  { name: 'Generic Secret', pattern: /(?:secret|SECRET)\s*[=:]\s*["']?[A-Za-z0-9_\-]{16,}/g, severity: 'high' },
  { name: 'Generic Token', pattern: /(?:token|TOKEN)\s*[=:]\s*["']?[A-Za-z0-9_.\-]{20,}/g, severity: 'high' },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g, severity: 'critical' },
  { name: 'Google API Key', pattern: /AIza[A-Za-z0-9_\\-]{35}/g, severity: 'critical' },
  { name: 'Slack Token', pattern: /xox[boaprs]-[A-Za-z0-9-]+/g, severity: 'critical' },
  { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, severity: 'high' },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'high' },
  { name: 'Password in URL', pattern: /[a-zA-Z]+:\/\/[^:\s]+:[^@\s]+@/g, severity: 'critical' },
  { name: 'Basic Auth Header', pattern: /Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}/gi, severity: 'high' },
  { name: 'Bearer Token', pattern: /Authorization:\s*Bearer\s+[A-Za-z0-9_.\-]{20,}/gi, severity: 'high' },
  { name: 'Stripe Key', pattern: /sk_(?:live|test)_[A-Za-z0-9]{20,}/g, severity: 'critical' },
  { name: 'SendGrid Key', pattern: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g, severity: 'critical' },
  { name: 'Twilio Key', pattern: /SK[a-f0-9]{32}/g, severity: 'high' },
  { name: 'Database URL', pattern: /(?:mysql|postgres|mongodb|redis):\/\/[^\s"']+:[^\s"']+@[^\s"']+/gi, severity: 'critical' },
  { name: 'SSH Private Key', pattern: /-----BEGIN\s+(?:OPENSSH|EC|DSA)\s+PRIVATE\s+KEY-----/g, severity: 'critical' }
];

// OWASP Top 10 category mapping
const OWASP_CATEGORIES = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable and Outdated Components',
  A07: 'Identification and Authentication Failures',
  A08: 'Software and Data Integrity Failures',
  A09: 'Security Logging and Monitoring Failures',
  A10: 'Server-Side Request Forgery (SSRF)'
};

const INJECTION_PATTERNS = [
  // SQL Injection (A03)
  { name: 'SQL Injection — String Concat', pattern: /["'`]\s*\+\s*(?:req|request|params|query|body|input|user)\b.*\+\s*["'`]/gi, severity: 'critical', type: 'sqli', owasp: 'A03' },
  { name: 'SQL Injection — Template Literal', pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION)\b[^;]*\$\{/gi, severity: 'critical', type: 'sqli', owasp: 'A03' },
  { name: 'SQL Injection — f-string', pattern: /f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^"']*\{/gi, severity: 'critical', type: 'sqli', owasp: 'A03' },
  { name: 'SQL Injection — format()', pattern: /\.format\s*\([^)]*\).*(?:SELECT|INSERT|UPDATE|DELETE|DROP)/gi, severity: 'critical', type: 'sqli', owasp: 'A03' },

  // XSS (A03)
  { name: 'XSS — innerHTML', pattern: /\.innerHTML\s*=\s*(?!['"`]<)/g, severity: 'high', type: 'xss', owasp: 'A03' },
  { name: 'XSS — document.write', pattern: /document\.write\s*\(/g, severity: 'high', type: 'xss', owasp: 'A03' },
  { name: 'XSS — dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g, severity: 'medium', type: 'xss', owasp: 'A03' },
  { name: 'XSS — eval()', pattern: /\beval\s*\(\s*(?!['"`])/g, severity: 'critical', type: 'xss', owasp: 'A03' },
  { name: 'XSS — Unescaped Output', pattern: /\{\{\s*\w+\s*\}\}(?!\s*\|)/g, severity: 'low', type: 'xss', owasp: 'A03' },

  // Command Injection (A03)
  { name: 'Command Injection — exec()', pattern: /(?:child_process|exec|execSync|spawn|spawnSync)\s*\(\s*(?:.*\+|.*\$\{|.*`)/g, severity: 'critical', type: 'cmdi', owasp: 'A03' },
  { name: 'Command Injection — os.system', pattern: /os\.(?:system|popen)\s*\(\s*(?:f['"]|.*\+|.*\.format)/g, severity: 'critical', type: 'cmdi', owasp: 'A03' },
  { name: 'Command Injection — subprocess', pattern: /subprocess\.(?:call|run|Popen|check_output)\s*\(\s*(?:f['"]|.*\+|.*\.format)/g, severity: 'critical', type: 'cmdi', owasp: 'A03' },
  { name: 'Command Injection — shell=True', pattern: /subprocess\.\w+\s*\([^)]*shell\s*=\s*True/g, severity: 'high', type: 'cmdi', owasp: 'A03' },

  // Path Traversal (A01 - Broken Access Control)
  { name: 'Path Traversal', pattern: /(?:\.\.\/|\.\.\\)/g, severity: 'medium', type: 'path_traversal', owasp: 'A01' },

  // SSRF Detection (A10)
  { name: 'SSRF Risk — Dynamic URL', pattern: /(?:fetch|axios|request|http\.get|urllib\.request|requests\.(?:get|post))\s*\(\s*(?:.*\+|.*\$\{|.*\.format|f['"])/g, severity: 'high', type: 'ssrf', owasp: 'A10' },
  { name: 'SSRF Risk — URL from Input', pattern: /(?:fetch|axios|http\.get|urllib\.request)\s*\(\s*(?:req|request|params|query|input|user)[\w.[\]]+/g, severity: 'high', type: 'ssrf', owasp: 'A10' },

  // Prototype Pollution (A08 - Software and Data Integrity Failures)
  { name: 'Prototype Pollution — __proto__', pattern: /\b__proto__\b/g, severity: 'high', type: 'prototype_pollution', owasp: 'A08' },
  { name: 'Prototype Pollution — constructor.prototype', pattern: /\bconstructor\s*\.\s*prototype\b/g, severity: 'high', type: 'prototype_pollution', owasp: 'A08' },

  // Insecure Randomness (A02 - Cryptographic Failures)
  { name: 'Insecure Randomness — Math.random()', pattern: /Math\.random\(\)/g, severity: 'medium', type: 'insecure_randomness', owasp: 'A02' },
  { name: 'Insecure Randomness — random module', pattern: /\brandom\.(?:random|randint|choice)\s*\(/g, severity: 'medium', type: 'insecure_randomness', owasp: 'A02' },

  // Deserialization (A08)
  { name: 'Unsafe Deserialization — pickle', pattern: /pickle\.loads?\s*\(/g, severity: 'high', type: 'deserialization', owasp: 'A08' },
  { name: 'Unsafe Deserialization — yaml', pattern: /yaml\.(?:load|unsafe_load)\s*\(/g, severity: 'high', type: 'deserialization', owasp: 'A08' },
  { name: 'Unsafe Deserialization — unserialize', pattern: /\bunserialize\s*\(/g, severity: 'high', type: 'deserialization', owasp: 'A08' },

  // Hardcoded IPs/URLs (A05 - Security Misconfiguration)
  { name: 'Hardcoded IP Address', pattern: /(?:['"`]|=\s*)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:['"`]|[:\s])/g, severity: 'low', type: 'hardcoded_ip', owasp: 'A05' },

  // Weak Crypto (A02)
  { name: 'Weak Hash Algorithm — MD5', pattern: /\b(?:md5|MD5|hashlib\.md5)\b/g, severity: 'medium', type: 'weak_crypto', owasp: 'A02' },
  { name: 'Weak Hash Algorithm — SHA1', pattern: /\b(?:sha1|SHA1|hashlib\.sha1)\b/g, severity: 'medium', type: 'weak_crypto', owasp: 'A02' },

  // Open Redirect (A01)
  { name: 'Open Redirect Risk', pattern: /(?:redirect|location\.href|window\.location)\s*=\s*(?:req|request|params|query)\./g, severity: 'high', type: 'open_redirect', owasp: 'A01' }
];

const HARDCODED_CRED_PATTERNS = [
  { name: 'Hardcoded Password', pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/gi, severity: 'high' },
  { name: 'Hardcoded Secret', pattern: /(?:secret|SECRET_KEY)\s*[:=]\s*["'][^"']{8,}["']/gi, severity: 'high' },
  { name: 'Hardcoded Database Password', pattern: /(?:DB_PASS|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*[:=]\s*["'][^"']+["']/gi, severity: 'critical' },
  { name: 'Hardcoded API Key Assignment', pattern: /(?:api_key|API_KEY|apiKey)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/gi, severity: 'high' },
  { name: 'Hardcoded Connection String', pattern: /(?:connection_string|CONN_STR|DATABASE_URL)\s*[:=]\s*["'][^"']+["']/gi, severity: 'high' }
];

/**
 * Scan text for exposed secrets and tokens.
 * @param {string} text - Text to scan
 * @returns {{ found: boolean, findings: Array<{ type: string, match: string, severity: string, line: number }> }}
 */
export function scanForSecrets(text) {
  const findings = [];
  const lines = text.split('\n');

  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    // Reset lastIndex for global regex
    pattern.lastIndex = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip comment-only lines that look like examples/docs
      const trimmed = line.trim();
      if (trimmed.startsWith('//') && trimmed.includes('example')) continue;
      if (trimmed.startsWith('#') && trimmed.includes('example')) continue;

      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(line)) !== null) {
        const masked = maskSecret(match[0]);
        findings.push({ type: name, match: masked, severity, line: i + 1 });
      }
    }
  }

  return { found: findings.length > 0, findings };
}

/**
 * Scan code for injection vulnerabilities.
 * @param {string} code - Source code to scan
 * @returns {{ found: boolean, findings: Array<{ type: string, name: string, severity: string, line: number, snippet: string, owasp?: string, owaspCategory?: string }> }}
 */
export function scanForInjection(code) {
  const findings = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

    for (const { name, pattern, severity, type, owasp } of INJECTION_PATTERNS) {
      pattern.lastIndex = 0;

      // Special handling for path traversal: exclude import/require contexts
      if (type === 'path_traversal') {
        // Skip if line contains import or require statements
        if (/\b(?:import|require|from)\s+/.test(line) || /['"](\.\.\/|\.\.\\).*['"]\s*[;,)]/.test(line)) {
          continue;
        }
      }

      // Special handling for insecure randomness: only flag if clearly used in security contexts
      if (type === 'insecure_randomness') {
        // Only flag if line contains security-related keywords
        const securityContext = /\b(?:token|key|secret|password|pwd|salt|nonce|session|crypto|auth|secure|random(?:bytes|int|string)|uuid|guid|id(?:entifier)?)\b/i.test(line);
        // Exclude if line contains UI/animation/delay keywords
        const uiContext = /\b(?:animation|delay|timeout|interval|jitter|offset|position|color|style)\b/i.test(line);
        if (!securityContext || uiContext) continue;
      }

      // Special handling for hardcoded IPs: exclude localhost and common non-security contexts
      if (type === 'hardcoded_ip') {
        if (/127\.0\.0\.1|0\.0\.0\.0|localhost/i.test(line)) continue;
        if (/example|test|demo|comment/i.test(line)) continue;
      }

      // Special handling for weak crypto: reduce false positives
      if (type === 'weak_crypto') {
        // Skip if in comments or documentation
        if (/\/\/|#|\/\*|\*|example/i.test(trimmed)) continue;
      }

      if (pattern.test(line)) {
        findings.push({
          type,
          name,
          severity,
          line: i + 1,
          snippet: trimmed.substring(0, 120),
          owasp: owasp || 'N/A',
          owaspCategory: owasp ? OWASP_CATEGORIES[owasp] : undefined
        });
      }
    }
  }

  return { found: findings.length > 0, findings };
}

/**
 * Find hardcoded credentials in source code.
 * @param {string} code - Source code to scan
 * @returns {{ found: boolean, findings: Array<{ type: string, severity: string, line: number, match: string }> }}
 */
export function scanForHardcodedCreds(code) {
  const findings = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments and obvious placeholder values
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

    for (const { name, pattern, severity } of HARDCODED_CRED_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(line)) !== null) {
        // Skip placeholder/example values
        const value = match[0];
        if (/(?:example|placeholder|your[_-]|change[_-]?me|xxx|todo|fixme|\*{3,}|\.{3,})/i.test(value)) {
          continue;
        }
        // Skip env var references
        if (/(?:process\.env|os\.environ|os\.getenv|ENV\[)/i.test(line)) {
          continue;
        }

        findings.push({
          type: name,
          severity,
          line: i + 1,
          match: maskSecret(value)
        });
      }
    }
  }

  return { found: findings.length > 0, findings };
}

/**
 * Compute a composite security safety score.
 * @param {string} text - Text/code to assess
 * @returns {{ score: number, breakdown: { secrets: number, injection: number, credentials: number }, summary: string }}
 */
export function getSecurityScore(text) {
  const secrets = scanForSecrets(text);
  const injection = scanForInjection(text);
  const creds = scanForHardcodedCreds(text);

  // Penalty calculation
  let secretsPenalty = 0;
  for (const f of secrets.findings) {
    secretsPenalty += f.severity === 'critical' ? 30 : f.severity === 'high' ? 20 : f.severity === 'medium' ? 10 : 5;
  }

  let injectionPenalty = 0;
  for (const f of injection.findings) {
    injectionPenalty += f.severity === 'critical' ? 25 : f.severity === 'high' ? 15 : f.severity === 'medium' ? 8 : 3;
  }

  let credsPenalty = 0;
  for (const f of creds.findings) {
    credsPenalty += f.severity === 'critical' ? 25 : f.severity === 'high' ? 15 : 5;
  }

  const secretsScore = Math.max(0, 100 - secretsPenalty);
  const injectionScore = Math.max(0, 100 - injectionPenalty);
  const credsScore = Math.max(0, 100 - credsPenalty);

  const composite = Math.round((secretsScore * 0.35) + (injectionScore * 0.40) + (credsScore * 0.25));

  const totalFindings = secrets.findings.length + injection.findings.length + creds.findings.length;
  let summary;
  if (composite >= 90) summary = 'Excellent — no significant security concerns detected';
  else if (composite >= 70) summary = 'Good — minor security issues found';
  else if (composite >= 50) summary = 'Fair — moderate security issues require attention';
  else summary = 'Poor — critical security issues detected, do not ship';

  return {
    score: composite,
    breakdown: {
      secrets: secretsScore,
      injection: injectionScore,
      credentials: credsScore
    },
    totalFindings,
    summary
  };
}

/**
 * Get severity level for a finding.
 * @param {{ severity: string }} finding - A security finding
 * @returns {'critical' | 'high' | 'medium' | 'low'}
 */
export function getSeverity(finding) {
  const levels = ['critical', 'high', 'medium', 'low'];
  return levels.includes(finding.severity) ? finding.severity : 'low';
}

/**
 * Get findings grouped by OWASP Top 10 category.
 * @param {string} code - Source code to scan
 * @returns {{ categories: object, summary: Array<{ category: string, count: number, highestSeverity: string }> }}
 */
export function getFindingsByOWASP(code) {
  const injection = scanForInjection(code);
  const categories = {};

  // Initialize categories
  for (const [key, name] of Object.entries(OWASP_CATEGORIES)) {
    categories[key] = { name, findings: [], count: 0 };
  }

  // Group findings by OWASP category
  for (const finding of injection.findings) {
    const owaspKey = finding.owasp || 'N/A';
    if (categories[owaspKey]) {
      categories[owaspKey].findings.push(finding);
      categories[owaspKey].count++;
    }
  }

  // Create summary
  const summary = Object.entries(categories)
    .filter(([key, data]) => data.count > 0)
    .map(([key, data]) => {
      const severities = data.findings.map(f => f.severity);
      const highestSeverity = severities.includes('critical') ? 'critical' :
                              severities.includes('high') ? 'high' :
                              severities.includes('medium') ? 'medium' : 'low';
      return {
        category: `${key}: ${data.name}`,
        count: data.count,
        highestSeverity
      };
    })
    .sort((a, b) => b.count - a.count);

  return { categories, summary };
}

/**
 * Mask a secret value for safe display.
 */
function maskSecret(value) {
  if (value.length <= 8) return '*'.repeat(value.length);
  return value.substring(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.substring(value.length - 4);
}

export default {
  scanForSecrets,
  scanForInjection,
  scanForHardcodedCreds,
  getSecurityScore,
  getSeverity,
  getFindingsByOWASP,
  OWASP_CATEGORIES
};
