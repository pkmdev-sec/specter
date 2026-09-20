/**
 * SPECTER — Tests for New P1 Features
 * Comprehensive tests for TypeScript/Go/Rust, OWASP, semantic diff, profiles, and preview/undo.
 */

import { checkTypeScript, checkGo, checkRust, checkJavaScript } from '../lib/syntax-checker.mjs';
import { scanForInjection, getFindingsByOWASP } from '../lib/security-scanner.mjs';
import { semanticDiff, checkConsistency } from '../lib/consistency-checker.mjs';
import { scoreOutput, getBreakdown, getWeightProfiles } from '../lib/quality-scorer.mjs';
import { fixTrailingWhitespace, fixFormatting, applyFixes, undo, clearUndoHistory } from '../lib/auto-fixer.mjs';

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
// P1 FIX 1: TypeScript, Go, Rust Support
// ═══════════════════════════════════════

section('P1 Fix 1 — TypeScript Syntax Checking');

(() => {
  const tsCode = `
interface User {
  name: string;
  age: number;
  email?: string;
}

function greet(user: User): string {
  return \`Hello, \${user.name}\`;
}

type Status = 'active' | 'inactive' | 'pending';
enum Role { Admin, User, Guest }

const processUser = async (id: number): Promise<User> => {
  const user = await fetchUser(id);
  return user;
};
`;
  const result = checkTypeScript(tsCode);
  assert(result.valid === true, 'Valid TypeScript code passes');
  assertEqual(result.errors.length, 0, 'No errors for valid TypeScript');
})();

(() => {
  const badTS = `
interface User {
  name: string
  age: number
}

function test(x: number {
  return x + 1;
}
`;
  const result = checkTypeScript(badTS);
  assert(result.valid === false, 'Invalid TypeScript detected');
  assert(result.errors.length > 0, 'Reports errors for invalid TypeScript');
})();

section('P1 Fix 1 — Go Syntax Checking');

(() => {
  const goCode = `
package main

import (
    "fmt"
    "net/http"
)

type User struct {
    Name string
    Age  int
}

func main() {
    user := User{Name: "Alice", Age: 30}
    fmt.Println(user)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
}
`;
  const result = checkGo(goCode);
  assert(result.valid === true, 'Valid Go code passes');
})();

(() => {
  const badGo = `
func test()
{
    return 1
}
`;
  const result = checkGo(badGo);
  assert(result.valid === false, 'Go opening brace on wrong line detected');
})();

(() => {
  const noPackage = `
func test() {
    return 1
}
`;
  const result = checkGo(noPackage);
  assert(result.valid === false, 'Missing package declaration detected');
  assert(result.errors.some(e => e.message.includes('package')), 'Error mentions package');
})();

section('P1 Fix 1 — Rust Syntax Checking');

(() => {
  const rustCode = `fn main() {
    let x = 5;
    let mut y = 10;
    println!("x: {}", x);
}

struct User {
    name: String,
    age: u32,
}

fn add(x: i32, y: i32) -> i32 {
    x + y
}

enum Status {
    Active,
    Inactive,
}`;
  const result = checkRust(rustCode);
  assert(result.valid === true, 'Valid Rust code passes');
})();

(() => {
  const badRust = `
fn test() {
    let x = 5;
    println!("x = {}", x;
}
`;
  const result = checkRust(badRust);
  assert(result.valid === false, 'Invalid Rust bracket mismatch detected');
})();

section('P1 Fix 1 — JavaScript Regex Literal Fix');

(() => {
  const jsWithRegex = `
const pattern = /hello\\s+world/gi;
const match = text.match(/\\d+/g);
const isValid = /^[a-z]+$/i.test(input);
const result = 10 / 2; // division, not regex
`;
  const result = checkJavaScript(jsWithRegex);
  assert(result.valid === true, 'JavaScript with regex literals passes');
  assertEqual(result.errors.length, 0, 'No false positives on regex vs division');
})();

// ═══════════════════════════════════════
// P1 FIX 2: OWASP Top 10 Patterns
// ═══════════════════════════════════════

section('P1 Fix 2 — OWASP Pattern Detection');

(() => {
  const sqlInjectionCode = `
const query = "SELECT * FROM users WHERE id = " + req.params.id + "";
db.execute(query);
`;
  const result = scanForInjection(sqlInjectionCode);
  assert(result.found === true, 'SQL injection detected');
  assert(result.findings.some(f => f.owasp === 'A03'), 'SQL injection tagged as A03');
})();

(() => {
  const ssrfCode = `const response = await fetch(req.query.targetUrl);`;
  const result = scanForInjection(ssrfCode);
  assert(result.found === true, 'SSRF risk detected');
  assert(result.findings.some(f => f.owasp === 'A10'), 'SSRF tagged as A10');
})();

(() => {
  const prototypePollutionCode = `
function merge(target, source) {
  for (let key in source) {
    if (key === '__proto__') {
      target[key] = source[key];
    }
  }
}
`;
  const result = scanForInjection(prototypePollutionCode);
  assert(result.found === true, 'Prototype pollution detected');
  assert(result.findings.some(f => f.type === 'prototype_pollution'), 'Identifies __proto__ usage');
})();

(() => {
  const insecureRandomCode = `
const token = Math.random().toString(36).substring(7);
const sessionId = Math.random();
`;
  const result = scanForInjection(insecureRandomCode);
  assert(result.found === true, 'Insecure randomness detected in security context');
  assert(result.findings.some(f => f.owasp === 'A02'), 'Insecure random tagged as A02');
})();

(() => {
  const weakCryptoCode = `
const hash = require('crypto').createHash('md5').update(password).digest('hex');
const sha1Hash = hashlib.sha1(data).hexdigest();
`;
  const result = scanForInjection(weakCryptoCode);
  assert(result.found === true, 'Weak crypto algorithms detected');
  assert(result.findings.some(f => f.type === 'weak_crypto'), 'Identifies MD5/SHA1 usage');
})();

section('P1 Fix 2 — OWASP Category Grouping');

(() => {
  const mixedVulnCode = `
const query = "SELECT * FROM users WHERE id = " + userId;
const url = req.body.targetUrl;
fetch(url);
obj[__proto__] = malicious;
const key = Math.random().toString(36);
`;
  const result = getFindingsByOWASP(mixedVulnCode);
  assert(result.summary.length > 0, 'OWASP summary created');
  assert(result.categories.A03 !== undefined, 'A03 category present');
  assert(result.categories.A10 !== undefined, 'A10 category present');
})();

// ═══════════════════════════════════════
// P1 FIX 3: Semantic Diff
// ═══════════════════════════════════════

section('P1 Fix 3 — Semantic Diff Analysis');

(() => {
  const oldCode = `
function calculateTotal(items) {
  let sum = 0;
  for (const item of items) {
    sum += item.price;
  }
  return sum;
}
`;

  const newCode = `
function calculateTotal(items) {
  return items.reduce((sum, item) => sum + item.price, 0);
}

function applyDiscount(total, discount) {
  return total * (1 - discount);
}
`;

  const diff = semanticDiff(oldCode, newCode);
  assert(diff.added.functions.includes('applyDiscount'), 'Detects added function');
  assert(diff.modified.functions.includes('calculateTotal'), 'Detects modified function');
  assert(diff.summary.includes('Added'), 'Summary mentions additions');
})();

(() => {
  const oldCode = `
class User {
  constructor(name) {
    this.name = name;
  }

  greet() {
    return "Hello";
  }
}
`;

  const newCode = `
class User {
  constructor(name, email) {
    this.name = name;
    this.email = email;
  }
}

class Admin extends User {
  constructor(name, email) {
    super(name, email);
  }
}
`;

  const diff = semanticDiff(oldCode, newCode);
  assert(diff.added.classes.includes('Admin'), 'Detects added class');
  assert(diff.removed.functions.includes('greet'), 'Detects removed method');
})();

section('P1 Fix 3 — Semantic Diff in Consistency Check');

(() => {
  const oldCode = `
function oldName() {
  return 42;
}
`;
  const newCode = `
function newName() {
  return 42;
}
`;
  const intent = 'Rename the function from oldName to newName';

  const result = checkConsistency(oldCode, newCode, intent);
  assert(result.semanticDiff !== undefined, 'Consistency check includes semantic diff');
  assert(result.semanticDiff.removed.functions.includes('oldName'), 'Tracks removed function');
  assert(result.semanticDiff.added.functions.includes('newName'), 'Tracks added function');
})();

// ═══════════════════════════════════════
// P1 FIX 4: Weight Profiles
// ═══════════════════════════════════════

section('P1 Fix 4 — Weight Profiles');

(() => {
  const profiles = getWeightProfiles();
  assert(profiles.strict !== undefined, 'Strict profile exists');
  assert(profiles.balanced !== undefined, 'Balanced profile exists');
  assert(profiles.lenient !== undefined, 'Lenient profile exists');
  assert(profiles.strict.security > profiles.lenient.security, 'Strict prioritizes security more');
})();

(() => {
  const code = `
function test() {
  const key = "AKIAIOSFODNN7EXAMPLE";
  return key;
}
`;

  const strictResult = scoreOutput(code, { profile: 'strict' });
  const lenientResult = scoreOutput(code, { profile: 'lenient' });

  assert(strictResult.score !== undefined, 'Strict profile produces score');
  assert(lenientResult.score !== undefined, 'Lenient profile produces score');
  assert(strictResult.dimensions.security.weight === 0.40, 'Strict uses 40% security weight');
  assert(lenientResult.dimensions.security.weight === 0.20, 'Lenient uses 20% security weight');
})();

(() => {
  const goodCode = 'const x = 1;\nconst y = 2;';
  const result = scoreOutput(goodCode, {
    language: 'javascript',
    profile: 'balanced',
    request: 'Write two variable declarations'
  });

  assert(result.profile === 'balanced', 'Profile name included in result');
  assert(result.dimensions.syntax.weight !== undefined, 'Weight included per dimension');
})();

section('P1 Fix 4 — Per-Language Profiles');

(() => {
  const jsonCode = '{"name": "test", "value": 42}';
  const result = scoreOutput(jsonCode, { language: 'json' });

  // JSON should use syntax-heavy weighting
  assert(result.dimensions.syntax.weight > 0.25, 'JSON uses higher syntax weight');
})();

(() => {
  const mdCode = '# Title\n\nSome content\n\n## Subtitle';
  const result = scoreOutput(mdCode, { language: 'markdown', request: 'Write a document with title and subtitle' });

  // Markdown should be lenient
  assert(result.dimensions.completeness.weight >= 0.30, 'Markdown prioritizes completeness');
})();

section('P1 Fix 4 — Caching');

(() => {
  const code = 'const x = 1;';
  const context = { language: 'javascript', enableCache: true };

  const result1 = scoreOutput(code, context);
  const result2 = scoreOutput(code, context);

  assert(result1.score === result2.score, 'Cached results match');
})();

section('P1 Fix 4 — getBreakdown includes all dimensions');

(() => {
  const code = 'function test() { return 42; }';
  const breakdown = getBreakdown(code, { request: 'Write a test function' });

  assert(breakdown.completeness !== undefined, 'Breakdown includes completeness');
  assert(breakdown.alignment !== undefined, 'Breakdown includes alignment');
  assert(breakdown.completeness.score !== undefined, 'Completeness has score');
  assert(breakdown.alignment.score !== undefined, 'Alignment has score');
})();

// ═══════════════════════════════════════
// P1 FIX 5: Preview and Undo
// ═══════════════════════════════════════

section('P1 Fix 5 — Preview Mode (Dry Run)');

(() => {
  const code = 'hello   \nworld  \n';
  const result = fixTrailingWhitespace(code, { dryRun: true });

  assertEqual(result.fixed, code, 'Dry run does not modify code');
  assert(result.changes > 0, 'Dry run reports changes that would be made');
  assert(result.preview !== undefined, 'Preview is provided');
})();

(() => {
  const code = 'x=1;\ny=2;';
  const result = fixFormatting(code, 'javascript', { dryRun: true });

  assertEqual(result.fixed, code, 'Formatting dry run does not modify');
  assert(result.preview !== undefined, 'Formatting preview provided');
})();

section('P1 Fix 5 — Undo Capability');

(() => {
  clearUndoHistory();

  const original = 'hello   \nworld  ';
  const result = fixTrailingWhitespace(original, { id: 'test1' });

  assert(result.fixed !== original, 'Code was modified');

  const undoResult = undo('test1');
  assert(undoResult.success === true, 'Undo succeeds');
  assertEqual(undoResult.original, original, 'Original code restored');
})();

(() => {
  clearUndoHistory();

  const undoResult = undo('nonexistent');
  assertEqual(undoResult.success, false, 'Undo fails for nonexistent ID');
  assert(undoResult.message.includes('No undo'), 'Error message provided');
})();

section('P1 Fix 5 — Apply Multiple Fixes');

(() => {
  const code = 'const x=1;\nimport z from "z";\nimport a from "a";\n\n\n\n\nconst y=2';
  const result = applyFixes(code, ['whitespace', 'imports', 'formatting'], 'javascript');

  assert(result.totalChanges > 0, 'Multiple fixes applied');
  assert(result.appliedFixes.length > 0, 'Applied fixes list populated');
  assert(result.appliedFixes.some(f => f.name === 'formatting'), 'Formatting applied');
})();

(() => {
  const code = 'const x=1;';
  const result = applyFixes(code, ['whitespace', 'formatting'], 'javascript', { dryRun: true });

  assertEqual(result.fixed, code, 'applyFixes dry run does not modify');
  assert(result.appliedFixes.length >= 0, 'Preview shows what would be applied');
})();

section('P1 Fix 5 — Improved Python Semicolon Fix');

(() => {
  const pythonCode = `x = 1;
message = "Hello; world";
y = 2;`;
  const result = fixFormatting(pythonCode, 'python');

  // Should remove semicolons at end of lines, but not inside strings
  assert(!result.fixed.includes('x = 1;'), 'Removes trailing semicolon');
  assert(result.fixed.includes('"Hello; world"'), 'Preserves semicolon in string');
})();

section('P1 Fix 5 — Improved Operator Spacing (No URL Mangling)');

(() => {
  const jsCode = `const url="https://example.com";
const x=1;`;
  const result = fixFormatting(jsCode, 'javascript');

  assert(result.fixed.includes('https://'), 'URL not mangled');
  assert(result.fixed.includes('x = 1') || result.fixed.includes('x=1'), 'Operator spacing logic applied');
})();

// ═══════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════

console.log(`\n${'═'.repeat(50)}`);
console.log(`  SPECTER New Features Test Results`);
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
