/**
 * SPECTER — Syntax Checker
 * Validates code syntax across multiple languages.
 */

const JS_KEYWORDS = new Set([
  'break', 'case', 'catch', 'continue', 'debugger', 'default', 'delete',
  'do', 'else', 'finally', 'for', 'function', 'if', 'in', 'instanceof',
  'new', 'return', 'switch', 'this', 'throw', 'try', 'typeof', 'var',
  'void', 'while', 'with', 'class', 'const', 'enum', 'export', 'extends',
  'import', 'super', 'implements', 'interface', 'let', 'package', 'private',
  'protected', 'public', 'static', 'yield', 'async', 'await', 'of', 'from'
]);

const LANGUAGE_SIGNATURES = {
  javascript: {
    patterns: [/\bfunction\s+\w+\s*\(/, /\bconst\s+/, /\blet\s+/, /\b=>\s*[{(]/, /\brequire\s*\(/, /\bmodule\.exports/],
    extensions: ['.js', '.mjs', '.cjs', '.jsx']
  },
  python: {
    patterns: [/\bdef\s+\w+\s*\(/, /\bimport\s+\w+/, /\bfrom\s+\w+\s+import/, /\bclass\s+\w+.*:/, /\bif\s+.*:\s*$/, /\bprint\s*\(/],
    extensions: ['.py', '.pyw']
  },
  json: {
    patterns: [/^\s*[{\[]/, /"\w+"\s*:/],
    extensions: ['.json']
  },
  markdown: {
    patterns: [/^#{1,6}\s+/, /^\s*[-*+]\s+/, /\[.*\]\(.*\)/, /```\w*/],
    extensions: ['.md', '.markdown']
  },
  typescript: {
    patterns: [/:\s*(string|number|boolean|void|any)\b/, /\binterface\s+\w+/, /\btype\s+\w+\s*=/, /<\w+>/, /\benum\s+\w+/, /\bas\s+\w+\b/],
    extensions: ['.ts', '.tsx']
  },
  go: {
    patterns: [/\bfunc\s+\w+\s*\(/, /\bpackage\s+\w+/, /\btype\s+\w+\s+struct/, /\bimport\s+\(/, /\bgo\s+func/, /\bdefer\s+/],
    extensions: ['.go']
  },
  rust: {
    patterns: [/\bfn\s+\w+/, /\blet\s+mut\s+/, /\bimpl\s+/, /\bpub\s+fn/, /\bmatch\s+\w+\s*\{/, /<'[a-z]+>/],
    extensions: ['.rs']
  },
  html: {
    patterns: [/<html/i, /<div/i, /<head/i, /<!DOCTYPE/i],
    extensions: ['.html', '.htm']
  },
  css: {
    patterns: [/\{[\s\S]*?[\w-]+\s*:.*;\s*\}/, /@media\s/, /\.\w+\s*\{/, /#\w+\s*\{/],
    extensions: ['.css', '.scss', '.less']
  },
  sql: {
    patterns: [/\bSELECT\b.*\bFROM\b/i, /\bINSERT\s+INTO\b/i, /\bCREATE\s+TABLE\b/i, /\bALTER\s+TABLE\b/i],
    extensions: ['.sql']
  },
  shell: {
    patterns: [/^#!\/bin\/(ba)?sh/, /\becho\s+/, /\bfi\b/, /\bdone\b/, /\bif\s+\[/],
    extensions: ['.sh', '.bash', '.zsh']
  }
};

/**
 * Validate JavaScript syntax.
 * @param {string} code - JavaScript source code
 * @returns {{ valid: boolean, errors: Array<{ line: number, message: string }> }}
 */
export function checkJavaScript(code) {
  const errors = [];
  const lines = code.split('\n');

  // Bracket/paren/brace matching
  const stack = [];
  const pairs = { '(': ')', '[': ']', '{': '}' };
  const closers = new Set([')', ']', '}']);
  let inString = false;
  let stringChar = '';
  let inComment = false;
  let inLineComment = false;
  let inTemplateLiteral = false;
  let inRegex = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    inLineComment = false;

    for (let j = 0; j < line.length; j++) {
      const ch = line[j];
      const next = line[j + 1];

      if (inLineComment) break;

      if (inComment) {
        if (ch === '*' && next === '/') {
          inComment = false;
          j++;
        }
        continue;
      }

      if (inString) {
        if (ch === '\\') { j++; continue; }
        if (ch === stringChar) inString = false;
        continue;
      }

      if (inTemplateLiteral) {
        if (ch === '\\') { j++; continue; }
        if (ch === '`') inTemplateLiteral = false;
        continue;
      }

      if (inRegex) {
        if (ch === '\\') { j++; continue; }
        if (ch === '/') inRegex = false;
        continue;
      }

      if (ch === '/' && next === '/') { inLineComment = true; continue; }
      if (ch === '/' && next === '*') { inComment = true; j++; continue; }
      if (ch === '"' || ch === "'") { inString = true; stringChar = ch; continue; }
      if (ch === '`') { inTemplateLiteral = true; continue; }

      // Detect regex literal: / after =, (, [, {, :, ;, !, &, |, ?, ,, return, or at start
      // Fixed: improved detection to handle more edge cases
      if (ch === '/' && next !== '/' && next !== '*' && next !== '=') {
        const before = line.substring(0, j);
        const prevNonSpace = before.trimEnd().slice(-1);
        const prevToken = before.trim().split(/\s+/).pop() || '';

        // Regex context: after operators, keywords, or at start
        const afterOperator = ['=', '(', '[', '{', ':', ';', '!', '&', '|', '?', ',', '%'].includes(prevNonSpace);
        const afterKeyword = ['return', 'if', 'while', 'match', 'case', 'throw', 'typeof'].includes(prevToken);
        const atStart = j === 0 || before.trim() === '';

        // Not regex context: after identifiers, numbers, closing brackets (likely division)
        const afterIdentifier = /[a-zA-Z0-9_$]$/.test(prevNonSpace);
        const afterCloser = [')', ']', '}'].includes(prevNonSpace);

        if ((afterOperator || afterKeyword || atStart) && !afterIdentifier && !afterCloser) {
          inRegex = true;
          continue;
        }
      }

      if (pairs[ch]) {
        stack.push({ char: ch, line: i + 1, col: j + 1 });
      } else if (closers.has(ch)) {
        if (stack.length === 0) {
          errors.push({ line: i + 1, message: `Unexpected '${ch}' with no matching opener` });
        } else {
          const top = stack.pop();
          if (pairs[top.char] !== ch) {
            errors.push({ line: i + 1, message: `Mismatched '${ch}', expected '${pairs[top.char]}' to close '${top.char}' from line ${top.line}` });
          }
        }
      }
    }
  }

  if (inComment) {
    errors.push({ line: lines.length, message: 'Unterminated block comment' });
  }
  if (inString) {
    errors.push({ line: lines.length, message: `Unterminated string literal` });
  }
  if (inTemplateLiteral) {
    errors.push({ line: lines.length, message: 'Unterminated template literal' });
  }

  for (const item of stack) {
    errors.push({ line: item.line, message: `Unclosed '${item.char}' at column ${item.col}` });
  }

  // Check for common syntax errors
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();

    // Detect = in conditions (common mistake)
    const ifMatch = trimmed.match(/^if\s*\(\s*(\w+)\s*=\s*(?!=)/);
    if (ifMatch) {
      errors.push({ line: i + 1, message: `Possible assignment '=' in condition, did you mean '===' ?` });
    }

    // Detect duplicate semicolons
    if (/;;(?!\s*\))/.test(trimmed)) {
      errors.push({ line: i + 1, message: 'Double semicolon detected' });
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate Python syntax (indentation, colons, structure).
 * @param {string} code - Python source code
 * @returns {{ valid: boolean, errors: Array<{ line: number, message: string }> }}
 */
export function checkPython(code) {
  const errors = [];
  const lines = code.split('\n');
  const indentStack = [0];
  let inMultilineString = false;
  let multilineChar = '';
  let prevLineNeedsIndent = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Handle multiline strings
    if (inMultilineString) {
      if (line.includes(multilineChar)) {
        inMultilineString = false;
      }
      continue;
    }

    if (trimmed.includes('"""') || trimmed.includes("'''")) {
      const tripleQuote = trimmed.includes('"""') ? '"""' : "'''";
      const count = (trimmed.match(new RegExp(tripleQuote.replace(/'/g, "\\'"), 'g')) || []).length;
      if (count === 1) {
        inMultilineString = true;
        multilineChar = tripleQuote;
      }
    }

    // Skip empty lines and comments
    if (trimmed === '' || trimmed.startsWith('#')) {
      continue;
    }

    // Check indentation consistency (spaces vs tabs)
    const leadingWhitespace = line.match(/^(\s*)/)[1];
    if (leadingWhitespace && leadingWhitespace.includes('\t') && leadingWhitespace.includes(' ')) {
      errors.push({ line: i + 1, message: 'Mixed tabs and spaces in indentation' });
    }

    // Check indentation level
    const indent = line.match(/^(\s*)/)[1].length;

    if (prevLineNeedsIndent && indent <= indentStack[indentStack.length - 1]) {
      errors.push({ line: i + 1, message: 'Expected an indented block' });
    }
    prevLineNeedsIndent = false;

    // Track indent levels
    if (indent > indentStack[indentStack.length - 1]) {
      indentStack.push(indent);
    } else {
      while (indentStack.length > 1 && indent < indentStack[indentStack.length - 1]) {
        indentStack.pop();
      }
      if (indent !== indentStack[indentStack.length - 1]) {
        errors.push({ line: i + 1, message: `Indentation level ${indent} does not match any outer level` });
      }
    }

    // Compound statements must end with colon
    const compoundMatch = trimmed.match(/^(def|class|if|elif|else|for|while|with|try|except|finally|async\s+def|async\s+for|async\s+with)\b/);
    if (compoundMatch) {
      const stripped = trimmed.replace(/#.*$/, '').trimEnd();
      if (!stripped.endsWith(':') && !stripped.endsWith('\\')) {
        errors.push({ line: i + 1, message: `'${compoundMatch[1]}' statement should end with a colon` });
      } else if (stripped.endsWith(':')) {
        prevLineNeedsIndent = true;
      }
    }

    // Check for mismatched brackets
    const opens = (trimmed.match(/[(\[{]/g) || []).length;
    const closes = (trimmed.match(/[)\]}]/g) || []).length;
    if (opens < closes) {
      errors.push({ line: i + 1, message: 'More closing brackets than opening brackets' });
    }
  }

  if (inMultilineString) {
    errors.push({ line: lines.length, message: 'Unterminated multiline string' });
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate TypeScript syntax (extends JavaScript checking with TS-specific checks).
 * @param {string} code - TypeScript source code
 * @returns {{ valid: boolean, errors: Array<{ line: number, message: string }> }}
 */
export function checkTypeScript(code) {
  // Start with base JavaScript checking
  const jsResult = checkJavaScript(code);
  const errors = [...jsResult.errors];
  const lines = code.split('\n');

  // TypeScript-specific checks
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments and strings
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

    // Check for missing type annotations in function params (common issue)
    const funcMatch = trimmed.match(/function\s+\w+\s*\(([^)]*)\)/);
    if (funcMatch && funcMatch[1] && funcMatch[1].length > 0) {
      const params = funcMatch[1];
      // If params exist but no colons (type annotations), warn
      if (!params.includes(':') && !params.includes('...') && params.trim() !== '') {
        const hasAny = /:\s*any/.test(params);
        if (!hasAny && !/^[\s,]*$/.test(params)) {
          // This is a warning, not a hard error
          // errors.push({ line: i + 1, message: 'Function parameters missing type annotations' });
        }
      }
    }

    // Check for interface/type without proper structure
    const interfaceMatch = trimmed.match(/^interface\s+\w+\s*$/);
    if (interfaceMatch && !trimmed.endsWith('{')) {
      errors.push({ line: i + 1, message: 'Interface declaration should be followed by opening brace' });
    }

    const typeMatch = trimmed.match(/^type\s+\w+\s*$/);
    if (typeMatch && !trimmed.endsWith('=')) {
      errors.push({ line: i + 1, message: 'Type alias declaration should include assignment with =' });
    }

    // Check for enum without braces
    const enumMatch = trimmed.match(/^enum\s+\w+\s*$/);
    if (enumMatch && !trimmed.endsWith('{')) {
      errors.push({ line: i + 1, message: 'Enum declaration should be followed by opening brace' });
    }

    // Check for generic type brackets balance
    const genericOpens = (line.match(/<(?![=<])/g) || []).length;
    const genericCloses = (line.match(/(?<![=>])>/g) || []).length;
    if (genericOpens > genericCloses + 1) {
      // Might span multiple lines, so only warn if very unbalanced
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate Go syntax.
 * @param {string} code - Go source code
 * @returns {{ valid: boolean, errors: Array<{ line: number, message: string }> }}
 */
export function checkGo(code) {
  const errors = [];
  const lines = code.split('\n');
  let hasPackage = false;

  // Bracket/brace matching
  const stack = [];
  const pairs = { '(': ')', '[': ']', '{': '}' };
  const closers = new Set([')', ']', '}']);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments
    if (trimmed.startsWith('//')) continue;

    // Check for package declaration (should be at top)
    if (trimmed.startsWith('package ')) {
      hasPackage = true;
    }

    // Go requires opening brace on same line for func, if, for, etc.
    const controlMatch = trimmed.match(/^(func|if|for|switch|select)\s+/);
    if (controlMatch && !trimmed.includes('{') && !trimmed.endsWith('{')) {
      // Check next line
      if (i + 1 < lines.length) {
        const nextTrimmed = lines[i + 1].trim();
        if (nextTrimmed === '{') {
          errors.push({ line: i + 1, message: `Opening brace for '${controlMatch[1]}' must be on same line in Go` });
        }
      }
    }

    // Simple bracket matching
    for (const ch of line) {
      if (pairs[ch]) {
        stack.push({ char: ch, line: i + 1 });
      } else if (closers.has(ch)) {
        if (stack.length === 0) {
          errors.push({ line: i + 1, message: `Unexpected '${ch}' with no matching opener` });
        } else {
          const top = stack.pop();
          if (pairs[top.char] !== ch) {
            errors.push({ line: i + 1, message: `Mismatched '${ch}', expected '${pairs[top.char]}'` });
          }
        }
      }
    }
  }

  // Check for package declaration
  if (!hasPackage && lines.some(l => l.trim() !== '' && !l.trim().startsWith('//'))) {
    errors.push({ line: 1, message: 'Go files must start with a package declaration' });
  }

  // Check unclosed brackets
  for (const item of stack) {
    errors.push({ line: item.line, message: `Unclosed '${item.char}'` });
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate Rust syntax.
 * @param {string} code - Rust source code
 * @returns {{ valid: boolean, errors: Array<{ line: number, message: string }> }}
 */
export function checkRust(code) {
  const errors = [];
  const lines = code.split('\n');

  // Bracket/brace matching (excluding angle brackets for generics)
  const stack = [];
  const pairs = { '(': ')', '[': ']', '{': '}' };
  const closers = new Set([')', ']', '}']);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments
    if (trimmed.startsWith('//')) continue;

    // Check for lifetime annotations syntax
    const lifetimePattern = /<'[^']+>/;
    if (lifetimePattern.test(line)) {
      // Valid lifetime annotation
    }

    // Simple bracket matching
    let inString = false;
    let stringChar = '';
    let inComment = false;

    for (let j = 0; j < line.length; j++) {
      const ch = line[j];
      const next = line[j + 1];

      if (inComment) {
        if (ch === '*' && next === '/') {
          inComment = false;
          j++;
        }
        continue;
      }

      if (inString) {
        if (ch === '\\') { j++; continue; }
        if (ch === stringChar) inString = false;
        continue;
      }

      if (ch === '/' && next === '/') break;
      if (ch === '/' && next === '*') { inComment = true; j++; continue; }
      if (ch === '"' || ch === "'") { inString = true; stringChar = ch; continue; }

      // Track structural brackets only (not angle brackets for generics)
      if (ch === '(' || ch === '[' || ch === '{') {
        stack.push({ char: ch, line: i + 1 });
      } else if (closers.has(ch)) {
        if (stack.length === 0) {
          errors.push({ line: i + 1, message: `Unexpected '${ch}' with no matching opener` });
        } else {
          const top = stack.pop();
          const expectedClose = pairs[top.char];
          if (expectedClose !== ch) {
            errors.push({ line: i + 1, message: `Mismatched '${ch}', expected '${expectedClose}'` });
          }
        }
      }
    }
  }

  // Check unclosed brackets
  for (const item of stack) {
    errors.push({ line: item.line, message: `Unclosed '${item.char}'` });
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate JSON.
 * @param {string} code - JSON string
 * @returns {{ valid: boolean, errors: Array<{ line: number, message: string }> }}
 */
export function checkJSON(code) {
  const errors = [];

  try {
    JSON.parse(code);
  } catch (e) {
    const match = e.message.match(/position\s+(\d+)/i);
    let line = 1;
    if (match) {
      const pos = parseInt(match[1], 10);
      line = code.substring(0, pos).split('\n').length;
    }
    errors.push({ line, message: e.message });
  }

  // Additional checks
  const trimmed = code.trim();
  if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[') && !trimmed.startsWith('"') && !/^(true|false|null|-?\d)/.test(trimmed)) {
    errors.push({ line: 1, message: 'JSON must start with a valid value' });
  }

  // Check for trailing commas (common JSON error)
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const stripped = lines[i].replace(/"(?:[^"\\]|\\.)*"/g, '""').trim();
    if (/,\s*[}\]]/.test(stripped)) {
      errors.push({ line: i + 1, message: 'Trailing comma detected' });
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate Markdown structure.
 * @param {string} code - Markdown source
 * @returns {{ valid: boolean, errors: Array<{ line: number, message: string }> }}
 */
export function checkMarkdown(code) {
  const errors = [];
  const lines = code.split('\n');
  let inCodeBlock = false;
  let codeBlockStart = 0;
  let headingLevels = [];
  let prevBlank = true;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Track code blocks
    if (trimmed.startsWith('```')) {
      if (inCodeBlock) {
        inCodeBlock = false;
      } else {
        inCodeBlock = true;
        codeBlockStart = i + 1;
      }
      continue;
    }

    if (inCodeBlock) continue;

    // Heading validation
    const headingMatch = trimmed.match(/^(#{1,6})\s+(.+)/);
    if (headingMatch) {
      const level = headingMatch[1].length;

      // Headings should have a blank line before them (except first line)
      if (i > 0 && !prevBlank) {
        errors.push({ line: i + 1, message: 'Heading should be preceded by a blank line' });
      }

      // Check for heading level skip (e.g., # -> ###)
      if (headingLevels.length > 0) {
        const lastLevel = headingLevels[headingLevels.length - 1];
        if (level > lastLevel + 1) {
          errors.push({ line: i + 1, message: `Heading level skipped from h${lastLevel} to h${level}` });
        }
      }
      headingLevels.push(level);
    }

    // Check for broken links
    const linkPattern = /\[([^\]]*)\]\(([^)]*)\)/g;
    let linkMatch;
    while ((linkMatch = linkPattern.exec(trimmed)) !== null) {
      const url = linkMatch[2];
      if (url === '' || url === '#') {
        errors.push({ line: i + 1, message: `Empty link URL for text "${linkMatch[1]}"` });
      }
    }

    // Check for broken images
    const imgPattern = /!\[([^\]]*)\]\(([^)]*)\)/g;
    let imgMatch;
    while ((imgMatch = imgPattern.exec(trimmed)) !== null) {
      if (imgMatch[2] === '') {
        errors.push({ line: i + 1, message: `Empty image URL for alt text "${imgMatch[1]}"` });
      }
    }

    prevBlank = trimmed === '';
  }

  if (inCodeBlock) {
    errors.push({ line: codeBlockStart, message: 'Unterminated code block' });
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Detect the programming language of a code snippet.
 * @param {string} code - Source code
 * @returns {{ language: string, confidence: number }}
 */
export function detectLanguage(code) {
  const scores = {};

  for (const [lang, sig] of Object.entries(LANGUAGE_SIGNATURES)) {
    let matches = 0;
    for (const pattern of sig.patterns) {
      if (pattern.test(code)) {
        matches++;
      }
    }
    if (matches > 0) {
      scores[lang] = matches / sig.patterns.length;
    }
  }

  // Shebang detection
  const shebangMatch = code.match(/^#!\s*\/.*\/(python|node|bash|sh|ruby|perl)/);
  if (shebangMatch) {
    const lang = shebangMatch[1] === 'node' ? 'javascript' : shebangMatch[1];
    scores[lang] = (scores[lang] || 0) + 0.5;
  }

  const entries = Object.entries(scores).sort((a, b) => b[1] - a[1]);

  if (entries.length === 0) {
    return { language: 'unknown', confidence: 0 };
  }

  return {
    language: entries[0][0],
    confidence: Math.min(Math.round(entries[0][1] * 100), 100)
  };
}

export default {
  checkJavaScript,
  checkTypeScript,
  checkPython,
  checkGo,
  checkRust,
  checkJSON,
  checkMarkdown,
  detectLanguage
};
