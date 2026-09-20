#!/usr/bin/env python3
"""
SPECTER — PostToolUse Quality Gate Hook
Validates every tool output before it reaches the user.
Runs as a Claude Code hook (PostToolUse).

Configuration in ~/.claude/settings.json:
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit|Bash|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /absolute/path/to/specter/hooks/specter-gate.py"
          }
        ]
      }
    ]
  }
}
"""

import json
import sys
import os
import re
import subprocess
from pathlib import Path

SPECTER_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = SPECTER_DIR / "rules"

# ─── Secret Patterns ───
SECRET_PATTERNS = [
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "AWS Access Key", "critical"),
    (r"gh[pousr]_[A-Za-z0-9_]{36,255}", "GitHub Token", "critical"),
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "Private Key", "critical"),
    (r"sk_(?:live|test)_[A-Za-z0-9]{20,}", "Stripe Key", "critical"),
    (r"AIza[A-Za-z0-9_\\-]{35}", "Google API Key", "critical"),
    (r"xox[boaprs]-[A-Za-z0-9-]+", "Slack Token", "critical"),
    (r"(?:api[_-]?key|apikey)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{20,}", "Generic API Key", "high"),
    (r"(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{4,}[\"']", "Hardcoded Password", "high"),
    (r"(?:secret|SECRET)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{16,}", "Generic Secret", "high"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token", "high"),
]

# ─── Injection Patterns ───
INJECTION_PATTERNS = [
    (r"[\"'`]\s*\+\s*(?:req|request|params|query|body|input|user)\b", "SQL Injection — Concat", "critical"),
    (r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^;]*\$\{", "SQL Injection — Template", "critical"),
    (r"\.innerHTML\s*=\s*(?!['\"`]<)", "XSS — innerHTML", "high"),
    (r"\beval\s*\(\s*(?!['\"`])", "XSS — eval()", "critical"),
    (r"document\.write\s*\(", "XSS — document.write", "high"),
    (r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True", "Command Injection — shell=True", "high"),
]


def load_rules(profile="default"):
    """Load quality rules from JSON."""
    rules_path = RULES_DIR / f"{profile}.json"
    if rules_path.exists():
        with open(rules_path) as f:
            return json.load(f)
    return {"thresholds": {"security": 70}, "blocking": {"blockOnCriticalSecurity": True}}


def scan_secrets(text):
    """Scan text for exposed secrets."""
    findings = []
    for pattern, name, severity in SECRET_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            # Skip examples/placeholders
            line_start = text.rfind("\n", 0, match.start()) + 1
            line = text[line_start:text.find("\n", match.end())]
            if re.search(r"example|placeholder|your[_-]|xxx|todo", line, re.IGNORECASE):
                continue
            findings.append({
                "type": name,
                "severity": severity,
                "position": match.start(),
            })
    return findings


def scan_injection(text):
    """Scan for injection vulnerabilities."""
    findings = []
    lines = text.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern, name, severity in INJECTION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "type": name,
                    "severity": severity,
                    "line": i + 1,
                })
    return findings


def compute_score(secret_findings, injection_findings):
    """Compute security score 0-100."""
    penalty = 0
    for f in secret_findings:
        penalty += 30 if f["severity"] == "critical" else 15
    for f in injection_findings:
        penalty += 25 if f["severity"] == "critical" else 10
    return max(0, 100 - penalty)


def format_findings(findings, label):
    """Format findings for stderr output."""
    if not findings:
        return ""
    lines = [f"\n  ⚠ {label}:"]
    for f in findings[:5]:
        severity = f["severity"].upper()
        ftype = f["type"]
        extra = f" (line {f['line']})" if "line" in f else ""
        lines.append(f"    [{severity}] {ftype}{extra}")
    if len(findings) > 5:
        lines.append(f"    ... and {len(findings) - 5} more")
    return "\n".join(lines)


def extract_content(hook_input):
    """Extract scannable content from a supported PostToolUse payload."""
    tool_name = hook_input.get("tool_name", "")
    if tool_name not in {"Write", "Edit", "NotebookEdit", "Bash"}:
        return ""

    tool_response = hook_input.get("tool_response", "")
    if isinstance(tool_response, str):
        content = tool_response
    elif isinstance(tool_response, dict):
        content = json.dumps(tool_response)
    else:
        content = ""

    tool_input = hook_input.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return content

    input_fields = {
        "Write": "content",
        "Edit": "new_string",
        "NotebookEdit": "new_source",
        "Bash": "command",
    }
    input_content = tool_input.get(input_fields[tool_name], "")
    if isinstance(input_content, str):
        content += "\n" + input_content

    return content


def main():
    """Main gate logic — reads hook input from stdin."""
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, Exception):
        # If no valid JSON input, silently pass through
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    content = extract_content(hook_input)

    if not content.strip():
        sys.exit(0)

    # Load rules
    profile = os.environ.get("SPECTER_PROFILE", "default")
    rules = load_rules(profile)

    # Run scans
    secret_findings = scan_secrets(content)
    injection_findings = scan_injection(content)
    score = compute_score(secret_findings, injection_findings)

    all_findings = secret_findings + injection_findings
    has_critical = any(f["severity"] == "critical" for f in all_findings)

    # Determine if we should block
    should_block = False
    block_reason = ""

    if rules.get("blocking", {}).get("blockOnCriticalSecurity") and has_critical:
        should_block = True
        block_reason = "Critical security issue detected"

    security_threshold = rules.get("thresholds", {}).get("security", 70)
    if score < security_threshold:
        should_block = True
        block_reason = f"Security score {score} below threshold {security_threshold}"

    # Output results
    if all_findings:
        report = f"\n{'='*50}"
        report += f"\n  SPECTER Quality Gate — {tool_name}"
        report += f"\n  Security Score: {score}/100"
        report += format_findings(secret_findings, "Secrets/Tokens")
        report += format_findings(injection_findings, "Injection Risks")
        report += f"\n{'='*50}"
        sys.stderr.write(report + "\n")

    if should_block:
        # Exit with non-zero to signal the hook should block
        sys.stderr.write(f"\n  ✖ BLOCKED: {block_reason}\n")
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
