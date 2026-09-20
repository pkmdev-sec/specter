# Specter architecture

Specter has a JavaScript library and an optional Python hook. They share a goal but do not run the same checks.

## JavaScript library

```text
content + request
  |
  +--> syntax checker
  +--> security scanner
  +--> consistency checker
  |
  v
quality scorer --> report or block decision
  |
  v
fix suggestions
```

### Syntax checker

[`lib/syntax-checker.mjs`](../../lib/syntax-checker.mjs) applies language-specific structural checks for JavaScript, TypeScript, Python, Go, Rust, JSON, and Markdown.

### Security scanner

[`lib/security-scanner.mjs`](../../lib/security-scanner.mjs) searches for credential-shaped strings, injection patterns, unsafe deserialization, weak cryptography, path traversal, and related patterns. It returns severity-tagged findings and a security score.

### Consistency checker

[`lib/consistency-checker.mjs`](../../lib/consistency-checker.mjs) compares a request with an output or diff. It estimates completeness, alignment, and regression risk.

### Quality scorer

[`lib/quality-scorer.mjs`](../../lib/quality-scorer.mjs) combines syntax, security, completeness, and alignment scores. Callers can select a profile, threshold, language, or custom weights through its JavaScript API.

### Auto-fixer

[`lib/auto-fixer.mjs`](../../lib/auto-fixer.mjs) fixes trailing whitespace and some import or formatting issues. It can also generate fix suggestions. The quality scorer does not apply fixes automatically.

## Claude Code hook

```text
PostToolUse input
  |
  v
extract content --> secret scan + injection scan --> security score --> pass or block
```

[`hooks/specter-gate.py`](../../hooks/specter-gate.py) handles `Write`, `Edit`, `NotebookEdit`, and `Bash`. It runs only its embedded secret and injection scans. The selected rule profile supplies the security threshold and critical-finding policy.

The hook does not call the JavaScript syntax, consistency, quality, or auto-fix modules.

## Limits

All checks are pattern-based heuristics. A passing result does not prove that code is secure or correct. A finding can be a false positive and needs review.
