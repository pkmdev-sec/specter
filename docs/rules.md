# Specter Rule Reference

This document enumerates all security and syntax rules enforced by SPECTER's scanning modules.

## Table of Contents
- [Secret Detection Rules](#secret-detection-rules)
- [Injection Vulnerability Rules](#injection-vulnerability-rules)
- [Hardcoded Credential Rules](#hardcoded-credential-rules)
- [Syntax Rules](#syntax-rules)

---

## Secret Detection Rules

These rules scan for exposed secrets, tokens, and API keys in code and text outputs.

| Rule ID | Category | What It Checks | Severity | OWASP Mapping |
|---------|----------|----------------|----------|---------------|
| `aws-access-key` | Secrets | AWS Access Keys matching pattern `AKIA[A-Z0-9]{16}` or `ASIA[A-Z0-9]{16}` | Critical | A02: Cryptographic Failures |
| `aws-secret-key` | Secrets | AWS Secret Access Keys (40 character base64) | Critical | A02: Cryptographic Failures |
| `github-token` | Secrets | GitHub OAuth tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) | Critical | A02: Cryptographic Failures |
| `github-pat` | Secrets | GitHub Personal Access Tokens (`github_pat_`) | Critical | A02: Cryptographic Failures |
| `generic-api-key` | Secrets | Generic API key assignments (`api_key=`, `apikey=`) | High | A05: Security Misconfiguration |
| `generic-secret` | Secrets | Generic secret assignments (`secret=`, `SECRET=`) | High | A05: Security Misconfiguration |
| `generic-token` | Secrets | Generic token assignments (`token=`, `TOKEN=`) | High | A05: Security Misconfiguration |
| `private-key` | Secrets | RSA private key headers (`-----BEGIN PRIVATE KEY-----`) | Critical | A02: Cryptographic Failures |
| `google-api-key` | Secrets | Google API keys (`AIza[A-Za-z0-9_-]{35}`) | Critical | A02: Cryptographic Failures |
| `slack-token` | Secrets | Slack tokens (`xox[boaprs]-`) | Critical | A02: Cryptographic Failures |
| `slack-webhook` | Secrets | Slack webhook URLs | High | A05: Security Misconfiguration |
| `jwt-token` | Secrets | JSON Web Tokens (JWT format) | High | A02: Cryptographic Failures |
| `password-in-url` | Secrets | Passwords embedded in URLs (`user:pass@host`) | Critical | A07: Identification and Authentication Failures |
| `basic-auth-header` | Secrets | Basic authentication headers | High | A07: Identification and Authentication Failures |
| `bearer-token` | Secrets | Bearer tokens in Authorization headers | High | A07: Identification and Authentication Failures |
| `stripe-key` | Secrets | Stripe API keys (`sk_live_`, `sk_test_`) | Critical | A02: Cryptographic Failures |
| `sendgrid-key` | Secrets | SendGrid API keys | Critical | A02: Cryptographic Failures |
| `twilio-key` | Secrets | Twilio API keys (`SK[a-f0-9]{32}`) | High | A02: Cryptographic Failures |
| `database-url` | Secrets | Database connection strings with embedded credentials | Critical | A07: Identification and Authentication Failures |
| `ssh-private-key` | Secrets | SSH private key headers (OpenSSH, EC, DSA) | Critical | A02: Cryptographic Failures |

---

## Injection Vulnerability Rules

These rules detect common injection attack patterns and vulnerable code constructs.

### SQL Injection (OWASP A03)

| Rule ID | Category | What It Checks | Severity | OWASP Mapping |
|---------|----------|----------------|----------|---------------|
| `sqli-string-concat` | Injection | SQL queries built with string concatenation using user input | Critical | A03: Injection |
| `sqli-template-literal` | Injection | SQL keywords in template literals with variable interpolation | Critical | A03: Injection |
| `sqli-f-string` | Injection | SQL queries in Python f-strings with variable interpolation | Critical | A03: Injection |
| `sqli-format` | Injection | SQL queries using `.format()` with user data | Critical | A03: Injection |

### Cross-Site Scripting (XSS) (OWASP A03)

| Rule ID | Category | What It Checks | Severity | OWASP Mapping |
|---------|----------|----------------|----------|---------------|
| `xss-innerhtml` | Injection | Direct assignment to `.innerHTML` (non-literal) | High | A03: Injection |
| `xss-document-write` | Injection | Use of `document.write()` | High | A03: Injection |
| `xss-dangerously-set` | Injection | React's `dangerouslySetInnerHTML` attribute | Medium | A03: Injection |
| `xss-eval` | Injection | Use of `eval()` with non-literal arguments | Critical | A03: Injection |
| `xss-unescaped-output` | Injection | Template variables without escaping filters | Low | A03: Injection |

### Command Injection (OWASP A03)

| Rule ID | Category | What It Checks | Severity | OWASP Mapping |
|---------|----------|----------------|----------|---------------|
| `cmdi-exec` | Injection | Node.js `exec`, `spawn` with string concatenation | Critical | A03: Injection |
| `cmdi-os-system` | Injection | Python `os.system` or `os.popen` with string formatting | Critical | A03: Injection |
| `cmdi-subprocess` | Injection | Python `subprocess` calls with string formatting | Critical | A03: Injection |
| `cmdi-shell-true` | Injection | Python subprocess with `shell=True` parameter | High | A03: Injection |

### Other Injection Types

| Rule ID | Category | What It Checks | Severity | OWASP Mapping |
|---------|----------|----------------|----------|---------------|
| `path-traversal` | Injection | Path traversal patterns (`../`, `..\`) | Medium | A01: Broken Access Control |
| `ssrf-dynamic-url` | Injection | HTTP requests with dynamically constructed URLs | High | A10: Server-Side Request Forgery |
| `ssrf-url-from-input` | Injection | HTTP requests with URLs from user input | High | A10: Server-Side Request Forgery |
| `prototype-pollution-proto` | Injection | Use of `__proto__` accessor | High | A08: Software and Data Integrity Failures |
| `prototype-pollution-constructor` | Injection | Access to `constructor.prototype` | High | A08: Software and Data Integrity Failures |

---

## Cryptographic and Security Weaknesses

| Rule ID | Category | What It Checks | Severity | OWASP Mapping |
|---------|----------|----------------|----------|---------------|
| `insecure-random-mathrand` | Crypto | Use of `Math.random()` for security purposes | Medium | A02: Cryptographic Failures |
| `insecure-random-python` | Crypto | Use of Python `random` module for security | Medium | A02: Cryptographic Failures |
| `weak-hash-md5` | Crypto | Use of MD5 hash algorithm | Medium | A02: Cryptographic Failures |
| `weak-hash-sha1` | Crypto | Use of SHA1 hash algorithm | Medium | A02: Cryptographic Failures |
| `unsafe-deserialize-pickle` | Deserialization | Use of Python `pickle.load/loads` | High | A08: Software and Data Integrity Failures |
| `unsafe-deserialize-yaml` | Deserialization | Use of `yaml.load` or `yaml.unsafe_load` | High | A08: Software and Data Integrity Failures |
| `unsafe-deserialize-php` | Deserialization | Use of PHP `unserialize()` | High | A08: Software and Data Integrity Failures |

---

## Configuration and Miscellaneous

| Rule ID | Category | What It Checks | Severity | OWASP Mapping |
|---------|----------|----------------|----------|---------------|
| `hardcoded-ip` | Configuration | Hardcoded IP addresses (excluding localhost) | Low | A05: Security Misconfiguration |
| `open-redirect` | Vulnerability | Unvalidated redirects using user input | High | A01: Broken Access Control |

---

## Hardcoded Credential Rules

These rules detect hardcoded credentials and secrets in variable assignments.

| Rule ID | Category | What It Checks | Severity | OWASP Mapping |
|---------|----------|----------------|----------|---------------|
| `hardcoded-password` | Credentials | Hardcoded password assignments (`password=`, `passwd=`, `pwd=`) | High | A07: Identification and Authentication Failures |
| `hardcoded-secret` | Credentials | Hardcoded secret key assignments | High | A07: Identification and Authentication Failures |
| `hardcoded-db-password` | Credentials | Database password environment variables with hardcoded values | Critical | A07: Identification and Authentication Failures |
| `hardcoded-api-key` | Credentials | API key variable assignments with literal values | High | A05: Security Misconfiguration |
| `hardcoded-connection-string` | Credentials | Database connection strings with embedded credentials | High | A07: Identification and Authentication Failures |

---

## Syntax Rules

These rules validate code structure and syntax correctness across multiple languages.

### JavaScript/TypeScript

| Rule ID | Category | What It Checks | Severity |
|---------|----------|----------------|----------|
| `js-bracket-mismatch` | Syntax | Mismatched brackets, braces, or parentheses | High |
| `js-unclosed-bracket` | Syntax | Unclosed opening brackets | High |
| `js-unexpected-closer` | Syntax | Closing bracket without matching opener | High |
| `js-unterminated-string` | Syntax | String literals without closing quote | High |
| `js-unterminated-template` | Syntax | Template literals without closing backtick | High |
| `js-unterminated-comment` | Syntax | Block comments without closing `*/` | Medium |
| `js-assignment-in-condition` | Syntax | Assignment operator `=` in if condition (likely typo) | Medium |
| `js-double-semicolon` | Syntax | Double semicolons `;;` | Low |
| `ts-interface-missing-brace` | Syntax | Interface declaration without opening brace | High |
| `ts-type-missing-assignment` | Syntax | Type alias without `=` assignment | High |
| `ts-enum-missing-brace` | Syntax | Enum declaration without opening brace | High |

### Python

| Rule ID | Category | What It Checks | Severity |
|---------|----------|----------------|----------|
| `py-mixed-indent` | Syntax | Mixed tabs and spaces in indentation | High |
| `py-indent-mismatch` | Syntax | Indentation level doesn't match any outer level | High |
| `py-expected-indent` | Syntax | Expected indented block after compound statement | High |
| `py-missing-colon` | Syntax | Compound statement (def, if, for, etc.) without colon | High |
| `py-bracket-mismatch` | Syntax | More closing brackets than opening brackets | Medium |
| `py-unterminated-multiline-string` | Syntax | Multiline string (`"""` or `'''`) without closing | High |

### Go

| Rule ID | Category | What It Checks | Severity |
|---------|----------|----------------|----------|
| `go-missing-package` | Syntax | Go file without `package` declaration | High |
| `go-brace-newline` | Syntax | Opening brace on new line (violates Go convention) | Medium |
| `go-bracket-mismatch` | Syntax | Mismatched brackets or braces | High |
| `go-unclosed-bracket` | Syntax | Unclosed opening bracket | High |

### Rust

| Rule ID | Category | What It Checks | Severity |
|---------|----------|----------------|----------|
| `rust-bracket-mismatch` | Syntax | Mismatched brackets or braces | High |
| `rust-unclosed-bracket` | Syntax | Unclosed opening bracket | High |

### JSON

| Rule ID | Category | What It Checks | Severity |
|---------|----------|----------------|----------|
| `json-invalid` | Syntax | Invalid JSON structure (parse error) | High |
| `json-trailing-comma` | Syntax | Trailing comma before closing brace or bracket | High |
| `json-invalid-start` | Syntax | JSON doesn't start with valid value | High |

### Markdown

| Rule ID | Category | What It Checks | Severity |
|---------|----------|----------------|----------|
| `md-unterminated-code-block` | Syntax | Code block without closing ` ``` ` | Medium |
| `md-heading-no-blank-line` | Syntax | Heading not preceded by blank line | Low |
| `md-heading-level-skip` | Syntax | Heading level skip (e.g., H1 to H3) | Low |
| `md-empty-link` | Syntax | Link with empty URL | Medium |
| `md-empty-image` | Syntax | Image with empty URL | Medium |

---

## Severity levels

| Severity | Review priority |
|---|---|
| **Critical** | Investigate before using the output |
| **High** | Investigate promptly |
| **Medium** | Review in context |
| **Low** | Review when relevant |

---

## Hook profiles

The Python hook loads `rules/default.json` or `rules/strict.json` from the repository. These files set only the security score threshold and the critical-finding policy. Use `SPECTER_PROFILE=default` or `SPECTER_PROFILE=strict` to select one.

The JavaScript modules accept their own documented options through function arguments. They do not read the hook profile files.

---

## OWASP Top 10 Mapping

SPECTER's security rules are mapped to the OWASP Top 10 2021:

- **A01: Broken Access Control** - Path traversal, open redirects
- **A02: Cryptographic Failures** - Exposed secrets, weak crypto, insecure randomness
- **A03: Injection** - SQL injection, XSS, command injection
- **A05: Security Misconfiguration** - Hardcoded IPs, exposed tokens
- **A07: Identification and Authentication Failures** - Hardcoded credentials, passwords in URLs
- **A08: Software and Data Integrity Failures** - Prototype pollution, unsafe deserialization
- **A10: Server-Side Request Forgery (SSRF)** - Dynamic URL construction from user input

---

Pattern matches can be false positives. Review the matched line and its surrounding code before acting on a finding.
