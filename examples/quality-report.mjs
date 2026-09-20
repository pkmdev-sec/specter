#!/usr/bin/env node
// Example: Generate a quality report for multiple files
import { scoreOutput, generateReport } from '../lib/quality-scorer.mjs';
import { suggestFixes } from '../lib/auto-fixer.mjs';
import { scanForSecrets, scanForInjection } from '../lib/security-scanner.mjs';

// Sample code snippets to analyze
const snippets = [
  {
    name: 'auth.js',
    code: `
function authenticate(user, pass) {
  const query = "SELECT * FROM users WHERE username='" + user + "'";
  return db.query(query);
}
`,
    context: { request: 'Write an authentication function' }
  },
  {
    name: 'config.js',
    code: `
const config = {
  apiKey: process.env.API_KEY,
  dbPassword: process.env.DB_PASSWORD,
  endpoint: "https://api.example.com"
};
export default config;
`,
    context: { request: 'Create a configuration file' }
  },
  {
    name: 'utils.js',
    code: `
function formatDate(date) {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return months[date.getMonth()] + ' ' + date.getDate() + ', ' + date.getFullYear();
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}
`,
    context: { request: 'Create utility functions for date formatting and string capitalization' }
  }
];

console.log('=== Specter Quality Report ===\n');

// Analyze each snippet individually
const results = [];
for (const snippet of snippets) {
  console.log(`\nAnalyzing: ${snippet.name}`);
  console.log('─'.repeat(60));

  const result = scoreOutput(snippet.code, {
    language: 'javascript',
    ...snippet.context
  });

  results.push({
    output: snippet.code,
    context: snippet.context,
    timestamp: new Date().toISOString()
  });

  console.log(`Score: ${result.score}/100 (${result.grade})  |  Status: ${result.passed ? 'PASS' : 'FAIL'}`);

  // Show dimension breakdown
  console.log('\nDimension Breakdown:');
  const dimensions = [
    ['Syntax', result.dimensions.syntax],
    ['Security', result.dimensions.security],
    ['Completeness', result.dimensions.completeness],
    ['Alignment', result.dimensions.alignment]
  ];

  for (const [name, data] of dimensions) {
    const bar = '█'.repeat(Math.floor(data.score / 5)) + '░'.repeat(20 - Math.floor(data.score / 5));
    console.log(`  ${name.padEnd(12)} [${bar}] ${data.score}/100`);
  }

  // Collect all findings for suggestions
  const allFindings = [];

  // Get security findings
  const secrets = scanForSecrets(snippet.code);
  const injection = scanForInjection(snippet.code);

  if (secrets.findings.length > 0) {
    allFindings.push(...secrets.findings);
  }
  if (injection.findings.length > 0) {
    allFindings.push(...injection.findings);
  }

  // Generate suggestions
  if (allFindings.length > 0) {
    const suggestions = suggestFixes(allFindings);

    if (suggestions.length > 0) {
      console.log('\nSuggestions:');
      suggestions.slice(0, 3).forEach((s, i) => {
        console.log(`  ${i + 1}. [${s.priority.toUpperCase()}] ${s.suggestion}`);
      });
    }
  }
}

// Generate aggregate report
console.log('\n\n=== Aggregate Report ===');
console.log('─'.repeat(60));

const report = generateReport(results);

console.log(`\nTotal Files Analyzed: ${report.report.totalOutputs}`);
console.log(`Average Quality Score: ${report.averageScore}/100`);
console.log(`Pass Rate: ${report.report.passRate}%`);
console.log(`Trend: ${report.trend.toUpperCase()}`);

console.log('\nGrade Distribution:');
for (const [grade, count] of Object.entries(report.report.gradeDistribution)) {
  const bar = '█'.repeat(count);
  console.log(`  ${grade}: ${bar} (${count})`);
}

console.log('\nDimension Averages:');
for (const [dim, score] of Object.entries(report.report.dimensionAverages)) {
  console.log(`  ${dim.padEnd(12)}: ${score}/100`);
}

console.log('\nHighest Score:', `${report.report.highest.score} (entry #${report.report.highest.index})`);
console.log('Lowest Score: ', `${report.report.lowest.score} (entry #${report.report.lowest.index})`);

// Summary table
console.log('\n\n=== Summary Table ===');
console.log('─'.repeat(60));
console.log('File          | Score | Grade | Syntax | Security | Status');
console.log('─'.repeat(60));

for (let i = 0; i < snippets.length; i++) {
  const entry = report.report.entries[i];
  const name = snippets[i].name.padEnd(12);
  const score = String(entry.score).padStart(5);
  const grade = entry.grade.padEnd(5);
  const syntax = String(entry.dimensions.syntax.score).padStart(6);
  const security = String(entry.dimensions.security.score).padStart(8);
  const status = entry.passed ? ' PASS' : ' FAIL';

  console.log(`${name} | ${score} | ${grade} | ${syntax} | ${security} | ${status}`);
}

console.log('─'.repeat(60));
