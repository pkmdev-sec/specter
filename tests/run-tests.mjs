/**
 * SPECTER — Test Runner
 * Comprehensive tests for all modules.
 */

import { checkJavaScript, checkTypeScript, checkPython, checkGo, checkRust, checkJSON, checkMarkdown, detectLanguage } from '../lib/syntax-checker.mjs';
import { scanForSecrets, scanForInjection, scanForHardcodedCreds, getSecurityScore, getSeverity } from '../lib/security-scanner.mjs';
import { checkCompleteness, checkConsistency, detectRegressions, scoreAlignment } from '../lib/consistency-checker.mjs';
import { scoreOutput, getBreakdown, shouldBlock, generateReport } from '../lib/quality-scorer.mjs';
import { fixTrailingWhitespace, fixImports, fixFormatting, suggestFixes } from '../lib/auto-fixer.mjs';

let passed = 0;
let failed = 0;
let total = 0;
const failures = [];

function assert(condition, testName) {
  total++;
  if (condition) {
    passed++;
    process.stdout.write(`  ✓ ${testName}\n`);
  } else {
    failed++;
    failures.push(testName);
    process.stdout.write(`  ✗ ${testName}\n`);
  }
}

function assertEqual(actual, expected, testName) {
  total++;
  if (actual === expected) {
    passed++;
    process.stdout.write(`  ✓ ${testName}\n`);
  } else {
    failed++;
    failures.push(`${testName} (expected: ${JSON.stringify(expected)}, got: ${JSON.stringify(actual)})`);
    process.stdout.write(`  ✗ ${testName} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}\n`);
  }
}

function section(name) {
  process.stdout.write(`\n━━━ ${name} ━━━\n`);
}

// ═══════════════════════════════════════
// SYNTAX CHECKER TESTS
// ═══════════════════════════════════════

section('Syntax Checker — JavaScript');

(() => {
  const valid = checkJavaScript('function hello() {\n  return "world";\n}');
  assert(valid.valid === true, 'Valid JS function');
  assertEqual(valid.errors.length, 0, 'No errors for valid JS');
})();

(() => {
  const result = checkJavaScript('function hello() {\n  return "world";\n');
  assert(result.valid === false, 'Missing closing brace detected');
  assert(result.errors.length > 0, 'Reports unclosed brace error');
})();

(() => {
  const result = checkJavaScript('const x = "unterminated string');
  assert(result.valid === false, 'Unterminated string detected');
})();

(() => {
  const result = checkJavaScript('const arr = [1, 2, 3)');
  assert(result.valid === false, 'Mismatched bracket detected');
})();

(() => {
  const result = checkJavaScript('if (x = 5) { }');
  assert(result.errors.some(e => e.message.includes('assignment')), 'Warns about assignment in condition');
})();

(() => {
  const valid = checkJavaScript('const fn = async () => {\n  await fetch("/api");\n};');
  assert(valid.valid === true, 'Valid async arrow function');
})();

(() => {
  const result = checkJavaScript('/* unclosed comment');
  assert(result.valid === false, 'Detects unterminated block comment');
})();

section('Syntax Checker — Python');

(() => {
  const valid = checkPython('def hello():\n    return "world"');
  assert(valid.valid === true, 'Valid Python function');
})();

(() => {
  const result = checkPython('def hello()\n    return "world"');
  assert(result.valid === false, 'Missing colon after def detected');
})();

(() => {
  const result = checkPython('class Foo:\ndef method(self):');
  assert(result.valid === false, 'Missing indentation after class detected');
})();

(() => {
  const valid = checkPython('if True:\n    pass\n\nfor i in range(10):\n    print(i)');
  assert(valid.valid === true, 'Valid multi-block Python');
})();

section('Syntax Checker — JSON');

(() => {
  const valid = checkJSON('{"key": "value", "num": 42}');
  assert(valid.valid === true, 'Valid JSON object');
})();

(() => {
  const result = checkJSON('{"key": "value",}');
  assert(result.valid === false, 'Trailing comma in JSON detected');
})();

(() => {
  const result = checkJSON('{key: "value"}');
  assert(result.valid === false, 'Unquoted key in JSON detected');
})();

(() => {
  const valid = checkJSON('[1, 2, 3]');
  assert(valid.valid === true, 'Valid JSON array');
})();

section('Syntax Checker — Markdown');

(() => {
  const valid = checkMarkdown('# Title\n\nSome text\n\n## Subtitle\n\nMore text');
  assert(valid.valid === true, 'Valid Markdown structure');
})();

(() => {
  const result = checkMarkdown('# Title\n\n### Skipped Level');
  assert(result.errors.some(e => e.message.includes('skipped')), 'Heading level skip detected');
})();

(() => {
  const result = checkMarkdown('```js\nconst x = 1;\n');
  assert(result.valid === false, 'Unterminated code block detected');
})();

section('Syntax Checker — Language Detection');

(() => {
  const result = detectLanguage('function hello() {\n  const x = 42;\n  return x;\n}');
  assertEqual(result.language, 'javascript', 'Detects JavaScript');
  assert(result.confidence > 0, 'Has positive confidence');
})();

(() => {
  const result = detectLanguage('def hello():\n    import os\n    return os.getcwd()');
  assertEqual(result.language, 'python', 'Detects Python');
})();

(() => {
  const result = detectLanguage('{"name": "test"}');
  assertEqual(result.language, 'json', 'Detects JSON');
})();

(() => {
  const result = detectLanguage('hello world');
  assertEqual(result.language, 'unknown', 'Returns unknown for plain text');
})();

// ═══════════════════════════════════════
// SECURITY SCANNER TESTS
// ═══════════════════════════════════════

section('Security Scanner — Secrets');

(() => {
  const result = scanForSecrets('const key = "AKIAIOSFODNN7EXAMPLE";');
  assert(result.found === true, 'Detects AWS access key');
  assert(result.findings.length > 0, 'Has findings for AWS key');
})();

(() => {
  const result = scanForSecrets('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234');
  assert(result.found === true, 'Detects GitHub token');
})();

(() => {
  const result = scanForSecrets('-----BEGIN RSA PRIVATE KEY-----');
  assert(result.found === true, 'Detects private key');
})();

(() => {
  const result = scanForSecrets('const greeting = "hello world";');
  assert(result.found === false, 'No false positives on clean code');
})();

(() => {
  const result = scanForSecrets('sk_live_abcdefghijklmnopqrstuvwxyz');
  assert(result.found === true, 'Detects Stripe key');
})();

section('Security Scanner — Injection');

(() => {
  const result = scanForInjection('const query = "SELECT * FROM users WHERE id = " + req.params.id + "";');
  assert(result.found === true, 'Detects SQL injection via concat');
})();

(() => {
  const result = scanForInjection('element.innerHTML = userInput;');
  assert(result.found === true, 'Detects XSS via innerHTML');
})();

(() => {
  const result = scanForInjection('eval(userCode);');
  assert(result.found === true, 'Detects eval injection');
})();

(() => {
  const result = scanForInjection('subprocess.call(cmd, shell=True)');
  assert(result.found === true, 'Detects command injection shell=True');
})();

(() => {
  const result = scanForInjection('const x = 1 + 2;');
  assert(result.found === false, 'No false positives on safe code');
})();

section('Security Scanner — Hardcoded Credentials');

(() => {
  const result = scanForHardcodedCreds('password = "super_secret_123"');
  assert(result.found === true, 'Detects hardcoded password');
})();

(() => {
  const result = scanForHardcodedCreds('password = process.env.DB_PASS');
  assert(result.found === false, 'Allows env var references');
})();

(() => {
  const result = scanForHardcodedCreds('API_KEY = "your_key_here"');
  assert(result.found === false, 'Skips placeholder values');
})();

section('Security Scanner — Scoring');

(() => {
  const result = getSecurityScore('const x = 1;\nconst y = 2;');
  assertEqual(result.score, 100, 'Perfect score for safe code');
})();

(() => {
  const result = getSecurityScore('const key = "AKIAIOSFODNN7EXAMPLE";\neval(userInput);');
  assert(result.score < 85, 'Lower score for unsafe code');
  assert(result.totalFindings > 0, 'Reports findings');
})();

(() => {
  const sev = getSeverity({ severity: 'critical' });
  assertEqual(sev, 'critical', 'getSeverity returns correct level');
})();

(() => {
  const sev = getSeverity({ severity: 'unknown' });
  assertEqual(sev, 'low', 'getSeverity defaults to low');
})();

// ═══════════════════════════════════════
// CONSISTENCY CHECKER TESTS
// ═══════════════════════════════════════

section('Consistency Checker — Completeness');

(() => {
  const result = checkCompleteness(
    'Add a login function and a logout function',
    'function login() { ... }\nfunction logout() { ... }'
  );
  assert(result.complete === true, 'All requirements addressed');
  assert(result.score >= 80, 'High completeness score');
})();

(() => {
  const result = checkCompleteness(
    '1. Add login\n2. Add logout\n3. Add password reset',
    'function login() { ... }'
  );
  assert(result.complete === false, 'Detects missed requirements');
  assert(result.missed.length > 0, 'Lists missed items');
})();

section('Consistency Checker — Consistency');

(() => {
  const result = checkConsistency(
    'function old() { return 1; }',
    'function renamed() { return 1; }',
    'Rename the function from old to renamed'
  );
  assert(result.score >= 0, 'Returns a score for rename');
  assert(result.observations.length >= 0, 'Provides observations');
})();

(() => {
  const result = checkConsistency(
    'function hello() { return 1; }',
    'function hello() { return 1; }',
    'Fix the bug'
  );
  assert(result.consistent === false, 'Detects no changes made');
})();

section('Consistency Checker — Regressions');

(() => {
  const diff = `--- a/file.js
+++ b/file.js
-try {
-  doSomething();
-} catch (e) {
-  handleError(e);
-}
+doSomething();`;
  const result = detectRegressions(diff);
  assert(result.hasRegressions === true, 'Detects removed error handling');
  assert(result.regressions.some(r => r.type === 'error_handling_removed'), 'Identifies error handling regression');
})();

(() => {
  const diff = `--- a/file.js
+++ b/file.js
-const x = 1;
+const x = 2;`;
  const result = detectRegressions(diff);
  assert(result.hasRegressions === false, 'No regression for simple value change');
})();

(() => {
  const diff = `--- a/file.js
+++ b/file.js
-validateInput(data);
-sanitize(html);
+processData(data);`;
  const result = detectRegressions(diff);
  assert(result.hasRegressions === true, 'Detects removed validation');
})();

section('Consistency Checker — Alignment');

(() => {
  const result = scoreAlignment(
    'Create a function that adds two numbers',
    'function add(a, b) {\n  return a + b;\n}'
  );
  assert(result.score > 0, 'Positive alignment score');
  assert(result.details.completeness >= 0, 'Has completeness detail');
})();

// ═══════════════════════════════════════
// QUALITY SCORER TESTS
// ═══════════════════════════════════════

section('Quality Scorer — scoreOutput');

(() => {
  const result = scoreOutput('function hello() {\n  return "world";\n}', { request: 'Write a hello function' });
  assert(result.score > 0, 'Returns positive score');
  assert(['A', 'B', 'C', 'D', 'F'].includes(result.grade), 'Returns valid grade');
  assert(typeof result.passed === 'boolean', 'Returns pass/fail boolean');
})();

(() => {
  const result = scoreOutput('{"name": "test"}', { language: 'json' });
  assert(result.score >= 70, 'Good score for valid JSON');
  assertEqual(result.language, 'json', 'Uses specified language');
})();

section('Quality Scorer — getBreakdown');

(() => {
  const result = getBreakdown('const x = 1;\nconst y = 2;');
  assert(result.syntax !== undefined, 'Has syntax breakdown');
  assert(result.security !== undefined, 'Has security breakdown');
  assert(result.syntax.score >= 0, 'Syntax score is non-negative');
})();

section('Quality Scorer — shouldBlock');

(() => {
  const result = shouldBlock(80, 60);
  assertEqual(result.blocked, false, 'Does not block above threshold');
})();

(() => {
  const result = shouldBlock(40, 60);
  assertEqual(result.blocked, true, 'Blocks below threshold');
  assert(result.reason.length > 0, 'Provides block reason');
})();

(() => {
  const result = shouldBlock(20, 60);
  assert(result.reason.includes('Critical'), 'Critical failure message for very low scores');
})();

section('Quality Scorer — generateReport');

(() => {
  const result = generateReport([
    { output: 'function a() { return 1; }', context: { request: 'Write function a' } },
    { output: 'function b() { return 2; }', context: { request: 'Write function b' } },
    { output: '{"valid": true}', context: { language: 'json' } }
  ]);
  assert(result.averageScore > 0, 'Report has positive average');
  assert(['improving', 'declining', 'stable'].includes(result.trend), 'Report has valid trend');
  assertEqual(result.report.totalOutputs, 3, 'Report counts all outputs');
})();

(() => {
  const result = generateReport([]);
  assertEqual(result.trend, 'no_data', 'Empty report returns no_data');
})();

// ═══════════════════════════════════════
// AUTO-FIXER TESTS
// ═══════════════════════════════════════

section('Auto-Fixer — Whitespace');

(() => {
  const result = fixTrailingWhitespace('hello   \nworld  \nclean');
  assertEqual(result.changes, 2, 'Fixes 2 trailing whitespace lines');
  assert(!result.fixed.includes('   \n'), 'Trailing whitespace removed');
})();

(() => {
  const result = fixTrailingWhitespace('clean\ncode\nhere');
  assertEqual(result.changes, 0, 'No changes for clean code');
})();

section('Auto-Fixer — Imports');

(() => {
  const code = "import z from 'z-lib';\nimport a from 'a-lib';\nimport a from 'a-lib';\n\nconst x = 1;";
  const result = fixImports(code, 'javascript');
  assert(result.changes > 0, 'Deduplicates and sorts JS imports');
})();

(() => {
  const code = "import os\nimport sys\nimport os\n\nprint('hello')";
  const result = fixImports(code, 'python');
  assert(result.changes > 0, 'Deduplicates Python imports');
})();

section('Auto-Fixer — Formatting');

(() => {
  const result = fixFormatting('hello\n\n\n\n\nworld', 'javascript');
  assert(result.changes > 0, 'Reduces excessive blank lines');
})();

(() => {
  const result = fixFormatting('no newline at end', 'javascript');
  assert(result.fixed.endsWith('\n'), 'Adds trailing newline');
})();

(() => {
  const result = fixFormatting('x = 1;', 'python');
  assert(!result.fixed.includes(';'), 'Removes Python trailing semicolons');
})();

section('Auto-Fixer — Suggest Fixes');

(() => {
  const suggestions = suggestFixes([
    { type: 'sqli', name: 'SQL Injection — Concat', line: 10, severity: 'critical' },
    { type: 'xss', name: 'XSS — innerHTML', line: 20, severity: 'high' }
  ]);
  assert(suggestions.length >= 2, 'Suggests fixes for multiple findings');
  assertEqual(suggestions[0].priority, 'critical', 'Critical items first');
})();

(() => {
  const suggestions = suggestFixes([
    { type: 'AWS Access Key', severity: 'critical', line: 5 }
  ]);
  assert(suggestions.some(s => s.suggestion.includes('environment')), 'Suggests env vars for secrets');
})();

// ═══════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════

console.log(`\n${'═'.repeat(50)}`);
console.log(`  SPECTER Test Results`);
console.log(`${'═'.repeat(50)}`);
console.log(`  Total:  ${total}`);
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);

if (failures.length > 0) {
  console.log(`\n  Failures:`);
  for (const f of failures) {
    console.log(`    ✗ ${f}`);
  }
}

console.log(`${'═'.repeat(50)}\n`);

process.exit(failed > 0 ? 1 : 0);
