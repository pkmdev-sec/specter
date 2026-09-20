#!/usr/bin/env node
// Example: Scan a code snippet for quality issues
import { checkJavaScript } from '../lib/syntax-checker.mjs';
import { scanForSecrets, scanForInjection, getSecurityScore } from '../lib/security-scanner.mjs';
import { scoreOutput } from '../lib/quality-scorer.mjs';

const snippet = `
function fetchUser(id) {
  const query = "SELECT * FROM users WHERE id = " + id;
  const token = "ghp_abc123secrettoken456";
  return eval(query);
}
`;

console.log('=== Specter Code Scan ===\n');
console.log('Scanning snippet for issues...\n');

// Check syntax
const syntaxResult = checkJavaScript(snippet);
console.log('Syntax:', syntaxResult.valid ? 'OK' : 'Issues found');
if (syntaxResult.errors?.length) {
  syntaxResult.errors.forEach(e => console.log(`  - Line ${e.line}: ${e.message}`));
}

// Scan for secrets
const secretsResult = scanForSecrets(snippet);
console.log('\nSecrets Detected:', secretsResult.found ? 'YES' : 'NO');
if (secretsResult.findings.length > 0) {
  secretsResult.findings.forEach(f =>
    console.log(`  [${f.severity}] ${f.type}: ${f.match} (line ${f.line})`)
  );
}

// Scan for injection vulnerabilities
const injectionResult = scanForInjection(snippet);
console.log('\nInjection Vulnerabilities:', injectionResult.found ? 'YES' : 'NO');
if (injectionResult.findings.length > 0) {
  injectionResult.findings.forEach(f =>
    console.log(`  [${f.severity}] ${f.name} (${f.owasp}): ${f.snippet.substring(0, 60)}...`)
  );
}

// Overall security score
const secScore = getSecurityScore(snippet);
console.log(`\nSecurity Score: ${secScore.score}/100`);
console.log('Breakdown:', JSON.stringify(secScore.breakdown, null, 2));
console.log('Summary:', secScore.summary);

// Overall quality score
const qualityResult = scoreOutput(snippet, { language: 'javascript' });
console.log(`\nOverall Quality Score: ${qualityResult.score}/100 (${qualityResult.grade})`);
console.log('Passed:', qualityResult.passed ? 'YES' : 'NO');
console.log('\nDimension Scores:');
for (const [dim, data] of Object.entries(qualityResult.dimensions)) {
  console.log(`  ${dim}: ${data.score}/100 (weight: ${(data.weight * 100).toFixed(0)}%)`);
}
