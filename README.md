![Specter banner](assets/banner.svg)

# Specter

[![CI](https://github.com/pkmdev-sec/specter/actions/workflows/ci.yml/badge.svg)](https://github.com/pkmdev-sec/specter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933.svg)](package.json)

Specter is a zero-dependency JavaScript toolkit for syntax checks, security pattern scans, response consistency checks, quality scoring, and suggested fixes.

It also includes an optional Claude Code hook. The hook is intentionally narrower than the library: it scans content from `Write`, `Edit`, `NotebookEdit`, and `Bash` for secret and injection patterns. It does not run syntax, completeness, alignment, regression, or auto-fix checks.

## Install

```bash
git clone https://github.com/pkmdev-sec/specter.git
cd specter
npm test
```

Specter requires Node.js 18 or newer. The optional hook requires Python 3.9 or newer.

## Use the library

The package exports each checker separately:

```javascript
import { checkJavaScript } from '@pkmdev-sec/specter/syntax';
import {
  scanForSecrets,
  scanForInjection,
  getSecurityScore,
} from '@pkmdev-sec/specter/security';
import {
  checkCompleteness,
  detectRegressions,
  scoreAlignment,
} from '@pkmdev-sec/specter/consistency';
import {
  scoreOutput,
  shouldBlock,
  generateReport,
} from '@pkmdev-sec/specter/quality';
import {
  fixTrailingWhitespace,
  fixImports,
  suggestFixes,
} from '@pkmdev-sec/specter/fixer';

const syntax = checkJavaScript('function hello() { return "world"; }');
const secrets = scanForSecrets(source);
const injections = scanForInjection(source);
const security = getSecurityScore(source);
const quality = scoreOutput(source, {
  request: 'Write a hello function',
  threshold: 60,
});
```

The checkers use deterministic heuristics. Review findings before treating them as security or correctness conclusions.

## Configure the Claude Code hook

Add the hook explicitly to your Claude Code settings. Replace the command path with the absolute path to your clone.

```json
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
```

Select a profile with `SPECTER_PROFILE`:

```bash
export SPECTER_PROFILE=strict
```

| Profile | Security threshold | Critical findings |
|---|---:|---|
| `default` | 70 | Block |
| `strict` | 90 | Block |

Both profiles scan the same security patterns. The strict profile blocks at a higher security score.

## How the hook decides

For a supported tool, the hook:

1. reads string content from the tool output and relevant `Write` or `Edit` input;
2. scans for secret and injection patterns;
3. subtracts severity-based penalties from a score of 100;
4. blocks critical findings when the profile requires it;
5. blocks when the security score is below the profile threshold.

Invalid, empty, or unsupported hook input passes through without a scan.

## Examples

```bash
node examples/scan-code.mjs
node examples/quality-report.mjs
```

The examples use placeholders and environment-variable reads. They do not contain working credentials.

## Documentation

- [Architecture](docs/core-concepts/architecture.md)
- [Security and syntax rule reference](docs/rules.md)

## Test

```bash
npm test
```

The test command runs the original module suite and the newer feature suite. CI runs both suites on Node.js 18, 20, and 22, then compiles and smoke-tests the Python hook.

## Project layout

```text
specter/
├── .github/              # CI and issue template
├── assets/               # Repository banner
├── docs/                 # Architecture and rule reference
├── examples/             # Runnable library examples
├── hooks/                # Optional Claude Code hook
├── lib/                  # JavaScript modules
├── rules/                # Hook security thresholds
└── tests/                # JavaScript test suites
```

## License

[MIT](LICENSE) © pkmdev-sec
