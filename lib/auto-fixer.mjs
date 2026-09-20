/**
 * SPECTER — Auto-Fixer
 * Automatically fix common quality issues in code outputs.
 */

// Undo history storage
const undoHistory = new Map();

/**
 * Remove trailing whitespace from all lines.
 * @param {string} code - Source code
 * @param {{ dryRun?: boolean, id?: string }} options - Fix options
 * @returns {{ fixed: string, changes: number, preview?: string }}
 */
export function fixTrailingWhitespace(code, options = {}) {
  // Input validation
  if (code === null || code === undefined) {
    return { fixed: '', changes: 0 };
  }
  if (typeof code !== 'string') {
    return { fixed: String(code), changes: 0 };
  }

  const { dryRun = false, id } = options;

  try {
    const lines = code.split('\n');
    let changes = 0;
    const changedLines = [];

    const fixed = lines.map((line, idx) => {
      const trimmed = line.replace(/[ \t]+$/, '');
      if (trimmed !== line) {
        changes++;
        changedLines.push({ line: idx + 1, old: line, new: trimmed });
      }
      return trimmed;
    }).join('\n');

    // Generate preview
    const preview = changedLines.length > 0
      ? changedLines.slice(0, 5).map(c => `Line ${c.line}: "${c.old}" → "${c.new}"`).join('\n')
      : 'No changes needed';

    // Store original for undo if not dry run and ID provided
    if (!dryRun && id && changes > 0) {
      undoHistory.set(id, code);
    }

    return { fixed: dryRun ? code : fixed, changes, preview };
  } catch (error) {
    console.error('Error in fixTrailingWhitespace:', error);
    return { fixed: code, changes: 0 };
  }
}

/**
 * Sort and deduplicate imports.
 * @param {string} code - Source code
 * @param {string} language - Programming language
 * @param {{ dryRun?: boolean, id?: string }} options - Fix options
 * @returns {{ fixed: string, changes: number, preview?: string }}
 */
export function fixImports(code, language = 'javascript', options = {}) {
  // Input validation
  if (code === null || code === undefined) {
    return { fixed: '', changes: 0 };
  }
  if (typeof code !== 'string') {
    return { fixed: String(code), changes: 0 };
  }

  const { dryRun = false, id } = options;

  try {
    const lines = code.split('\n');
    let result;

    if (language === 'javascript' || language === 'typescript') {
      result = fixJSImports(lines);
    } else if (language === 'python') {
      result = fixPythonImports(lines);
    } else {
      return { fixed: code, changes: 0 };
    }

    const preview = result.changes > 0
      ? `Deduplicated and sorted ${result.changes} import statement(s)`
      : 'No import changes needed';

    // Store original for undo if not dry run and ID provided
    if (!dryRun && id && result.changes > 0) {
      undoHistory.set(id, code);
    }

    return {
      fixed: dryRun ? code : result.fixed,
      changes: result.changes,
      preview
    };
  } catch (error) {
    console.error('Error in fixImports:', error);
    return { fixed: code, changes: 0 };
  }
}

function fixJSImports(lines) {
  const importLines = [];
  const importIndices = [];
  const otherLines = [];
  let changes = 0;
  let inImportBlock = true;
  let pastFirstNonEmpty = false;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();

    if (!pastFirstNonEmpty && trimmed === '') {
      otherLines.push(lines[i]);
      continue;
    }
    pastFirstNonEmpty = true;

    if (inImportBlock && (trimmed.startsWith('import ') || trimmed.startsWith('const ') && trimmed.includes('require('))) {
      importLines.push(trimmed);
      importIndices.push(i);
    } else if (inImportBlock && trimmed === '') {
      // blank line in import block — might be separator
      if (importLines.length > 0) {
        inImportBlock = false;
        otherLines.push(lines[i]);
      } else {
        otherLines.push(lines[i]);
      }
    } else {
      inImportBlock = false;
      otherLines.push(lines[i]);
    }
  }

  if (importLines.length === 0) return { fixed: lines.join('\n'), changes: 0 };

  // Deduplicate
  const seen = new Set();
  const deduped = importLines.filter(line => {
    const key = line.replace(/\s+/g, ' ');
    if (seen.has(key)) {
      changes++;
      return false;
    }
    seen.add(key);
    return true;
  });

  // Sort: node builtins first, then packages, then relative
  const builtins = new Set(['fs', 'path', 'os', 'url', 'http', 'https', 'crypto', 'util', 'stream', 'events', 'child_process', 'cluster', 'net', 'dns', 'tls', 'zlib', 'buffer', 'querystring', 'assert']);

  const categorize = (line) => {
    const fromMatch = line.match(/from\s+['"]([^'"]+)['"]/);
    const requireMatch = line.match(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/);
    const mod = fromMatch?.[1] || requireMatch?.[1] || '';

    if (mod.startsWith('.')) return 2; // relative
    if (builtins.has(mod) || mod.startsWith('node:')) return 0; // builtin
    return 1; // package
  };

  const sorted = [...deduped].sort((a, b) => {
    const catA = categorize(a);
    const catB = categorize(b);
    if (catA !== catB) return catA - catB;
    return a.localeCompare(b);
  });

  // Check if sort changed anything
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i] !== deduped[i]) { changes++; break; }
  }

  const result = [...sorted, '', ...otherLines.filter((l, i) => i > 0 || l.trim() !== '')].join('\n');
  return { fixed: result, changes };
}

function fixPythonImports(lines) {
  const importLines = [];
  const fromImportLines = [];
  const otherLines = [];
  let changes = 0;
  let inImportBlock = true;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();

    if (inImportBlock && trimmed.startsWith('import ') && !trimmed.includes('(')) {
      importLines.push(trimmed);
    } else if (inImportBlock && trimmed.startsWith('from ')) {
      fromImportLines.push(trimmed);
    } else if (inImportBlock && trimmed === '' && (importLines.length > 0 || fromImportLines.length > 0)) {
      inImportBlock = false;
      otherLines.push(lines[i]);
    } else {
      inImportBlock = false;
      otherLines.push(lines[i]);
    }
  }

  // Deduplicate
  const seen = new Set();
  const dedupedImports = importLines.filter(line => {
    if (seen.has(line)) { changes++; return false; }
    seen.add(line);
    return true;
  });
  const dedupedFromImports = fromImportLines.filter(line => {
    if (seen.has(line)) { changes++; return false; }
    seen.add(line);
    return true;
  });

  // Sort
  const sortedImports = [...dedupedImports].sort();
  const sortedFromImports = [...dedupedFromImports].sort();

  const allImports = [...sortedImports, ...sortedFromImports];
  if (allImports.length === 0) return { fixed: lines.join('\n'), changes: 0 };

  const result = [...allImports, '', ...otherLines].join('\n');
  return { fixed: result, changes };
}

/**
 * Apply basic formatting fixes.
 * @param {string} code - Source code
 * @param {string} language - Programming language
 * @param {{ dryRun?: boolean, id?: string }} options - Fix options
 * @returns {{ fixed: string, changes: number, preview?: string }}
 */
export function fixFormatting(code, language = 'javascript', options = {}) {
  // Input validation
  if (code === null || code === undefined) {
    return { fixed: '', changes: 0 };
  }
  if (typeof code !== 'string') {
    return { fixed: String(code), changes: 0 };
  }

  const { dryRun = false, id } = options;

  try {
    let fixed = code;
    let changes = 0;
    const changesList = [];

    // Fix multiple blank lines (reduce to max 2)
    const multiBlankFixed = fixed.replace(/\n{4,}/g, '\n\n\n');
    if (multiBlankFixed !== fixed) {
      changes++;
      changesList.push('Reduced excessive blank lines');
      fixed = multiBlankFixed;
    }

    // Ensure file ends with newline
    if (!fixed.endsWith('\n')) {
      fixed += '\n';
      changes++;
      changesList.push('Added trailing newline');
    }

    // Fix inconsistent indentation (tabs to spaces for JS/TS/Python)
    if (['javascript', 'typescript', 'python'].includes(language)) {
      const tabFixed = fixed.replace(/\t/g, '  ');
      if (tabFixed !== fixed) {
        changes++;
        changesList.push('Converted tabs to spaces');
        fixed = tabFixed;
      }
    }

    // Remove trailing semicolons for Python
    if (language === 'python') {
      const lines = fixed.split('\n');
      const beforeCount = changes;
      fixed = lines.map(line => {
        const trimmed = line.trimEnd();
        // Improved: Check if semicolon is not in a string by counting quotes before it
        if (trimmed.endsWith(';')) {
          const beforeSemi = trimmed.substring(0, trimmed.lastIndexOf(';'));
          const singleQuotes = (beforeSemi.match(/'/g) || []).length;
          const doubleQuotes = (beforeSemi.match(/"/g) || []).length;
          // If quotes are balanced (even count), semicolon is likely not in a string
          if (singleQuotes % 2 === 0 && doubleQuotes % 2 === 0) {
            changes++;
            return line.replace(/;\s*$/, '');
          }
        }
        return line;
      }).join('\n');
      if (changes > beforeCount) {
        changesList.push('Removed Python trailing semicolons');
      }
    }

    // Fix spacing around operators for JS/TS (improved to not mangle URLs)
    if (['javascript', 'typescript'].includes(language)) {
      const lines = fixed.split('\n');
      const beforeCount = changes;
      fixed = lines.map(line => {
        // Skip string-heavy lines, comments, URLs, and template strings
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return line;
        if (trimmed.includes('://')) return line; // Skip lines with URLs
        if (trimmed.includes('`')) return line;

        // Fix missing space around = (but not ==, ===, !=, <=, >=, =>)
        // Improved: be more careful not to touch URLs and special contexts
        let newLine = line.replace(/([a-zA-Z_$])=([a-zA-Z0-9_$"])/g, '$1 = $2');
        if (newLine !== line) changes++;
        return newLine;
      }).join('\n');
      if (changes > beforeCount) {
        changesList.push('Fixed operator spacing');
      }
    }

    const preview = changesList.length > 0
      ? changesList.join(', ')
      : 'No formatting changes needed';

    // Store original for undo if not dry run and ID provided
    if (!dryRun && id && changes > 0) {
      undoHistory.set(id, code);
    }

    return { fixed: dryRun ? code : fixed, changes, preview };
  } catch (error) {
    console.error('Error in fixFormatting:', error);
    return { fixed: code, changes: 0 };
  }
}

/**
 * Suggest fixes for detected issues.
 * @param {Array<{ type: string, name?: string, line?: number, message?: string, severity?: string }>} findings
 * @returns {Array<{ finding: string, suggestion: string, priority: string }>}
 */
export function suggestFixes(findings) {
  // Input validation
  if (!findings || !Array.isArray(findings)) {
    return [];
  }

  try {
    const suggestions = [];

    for (const finding of findings) {
      if (!finding || typeof finding !== 'object') continue;
    const type = finding.type || finding.name || '';
    const msg = finding.message || finding.description || '';
    const line = finding.line ? ` (line ${finding.line})` : '';

    // Syntax errors
    if (type === 'syntax' || msg.includes('Unclosed') || msg.includes('Unexpected')) {
      suggestions.push({
        finding: `${msg}${line}`,
        suggestion: `Check bracket/brace matching near line ${finding.line || 'unknown'}. Ensure all openers have corresponding closers.`,
        priority: 'high'
      });
    }

    // Security: secrets
    if (type.includes('Key') || type.includes('Token') || type.includes('Secret') || type.includes('Password')) {
      suggestions.push({
        finding: `${type} detected${line}`,
        suggestion: 'Move this value to environment variables or a secrets manager. Use process.env.VAR_NAME or os.environ["VAR_NAME"] instead.',
        priority: 'critical'
      });
    }

    // Injection
    if (type === 'sqli') {
      suggestions.push({
        finding: `SQL Injection risk${line}: ${finding.name || ''}`,
        suggestion: 'Use parameterized queries or prepared statements instead of string concatenation for SQL queries.',
        priority: 'critical'
      });
    }

    if (type === 'xss') {
      suggestions.push({
        finding: `XSS risk${line}: ${finding.name || ''}`,
        suggestion: 'Sanitize user input before rendering. Use textContent instead of innerHTML, or use a sanitization library.',
        priority: 'high'
      });
    }

    if (type === 'cmdi') {
      suggestions.push({
        finding: `Command Injection risk${line}: ${finding.name || ''}`,
        suggestion: 'Avoid passing user input to shell commands. Use parameterized APIs (e.g., execFile with args array) instead.',
        priority: 'critical'
      });
    }

    // Regressions
    if (type === 'error_handling_removed') {
      suggestions.push({
        finding: msg || 'Error handling removed',
        suggestion: 'Ensure removed error handling is replaced with equivalent or better error handling logic.',
        priority: 'high'
      });
    }

    if (type === 'validation_removed') {
      suggestions.push({
        finding: msg || 'Validation removed',
        suggestion: 'Verify that input validation is still performed, either at this location or at a higher level.',
        priority: 'high'
      });
    }

    if (type === 'security_removed') {
      suggestions.push({
        finding: msg || 'Security measure removed',
        suggestion: 'Security-related code should not be removed without an equivalent replacement. Review this change carefully.',
        priority: 'critical'
      });
    }

    // Indentation issues
    if (msg.includes('indent') || msg.includes('Mixed tabs')) {
      suggestions.push({
        finding: `${msg}${line}`,
        suggestion: 'Standardize indentation. Use spaces (2 or 4) consistently. Configure your editor to convert tabs to spaces.',
        priority: 'medium'
      });
    }

      // Generic fallback
      if (suggestions.length === 0 || suggestions[suggestions.length - 1].finding !== `${msg}${line}`) {
        if (msg && !suggestions.some(s => s.finding.includes(msg))) {
          suggestions.push({
            finding: `${type}: ${msg}${line}`,
            suggestion: `Review and address this ${finding.severity || 'medium'}-severity issue.`,
            priority: finding.severity || 'medium'
          });
        }
      }
    }

    // Sort by priority
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    suggestions.sort((a, b) => (priorityOrder[a.priority] ?? 3) - (priorityOrder[b.priority] ?? 3));

    return suggestions;
  } catch (error) {
    console.error('Error in suggestFixes:', error);
    return [];
  }
}

/**
 * Apply multiple fixes to code with preview capability.
 * @param {string} code - Source code
 * @param {Array<string>} fixes - Array of fix names to apply ('whitespace', 'imports', 'formatting')
 * @param {string} language - Programming language
 * @param {{ dryRun?: boolean, id?: string }} options - Fix options
 * @returns {{ fixed: string, totalChanges: number, appliedFixes: Array<{ name: string, changes: number, preview: string }> }}
 */
export function applyFixes(code, fixes, language = 'javascript', options = {}) {
  if (!code || typeof code !== 'string') {
    return { fixed: code, totalChanges: 0, appliedFixes: [] };
  }
  if (!fixes || !Array.isArray(fixes)) {
    return { fixed: code, totalChanges: 0, appliedFixes: [] };
  }

  const { dryRun = false, id } = options;
  let current = code;
  let totalChanges = 0;
  const appliedFixes = [];

  // Store original if ID provided and not dry run
  if (!dryRun && id) {
    undoHistory.set(id, code);
  }

  for (const fix of fixes) {
    let result;

    switch (fix.toLowerCase()) {
      case 'whitespace':
      case 'trailing-whitespace':
        result = fixTrailingWhitespace(current, { dryRun: true });
        if (!dryRun && result.changes > 0) {
          current = result.fixed;
        }
        break;

      case 'imports':
        result = fixImports(current, language, { dryRun: true });
        if (!dryRun && result.changes > 0) {
          current = result.fixed;
        }
        break;

      case 'formatting':
        result = fixFormatting(current, language, { dryRun: true });
        if (!dryRun && result.changes > 0) {
          current = result.fixed;
        }
        break;

      default:
        continue;
    }

    if (result && result.changes > 0) {
      totalChanges += result.changes;
      appliedFixes.push({
        name: fix,
        changes: result.changes,
        preview: result.preview || 'No preview available'
      });
    }
  }

  return {
    fixed: dryRun ? code : current,
    totalChanges,
    appliedFixes
  };
}

/**
 * Undo a previous fix by ID.
 * @param {string} id - Unique identifier for the fix to undo
 * @returns {{ success: boolean, original?: string, message: string }}
 */
export function undo(id) {
  if (!id) {
    return { success: false, message: 'No ID provided' };
  }

  if (undoHistory.has(id)) {
    const original = undoHistory.get(id);
    undoHistory.delete(id);
    return {
      success: true,
      original,
      message: 'Successfully restored original code'
    };
  }

  return {
    success: false,
    message: 'No undo history found for this ID'
  };
}

/**
 * Clear all undo history.
 */
export function clearUndoHistory() {
  undoHistory.clear();
}

/**
 * Get the number of items in undo history.
 * @returns {number}
 */
export function getUndoHistorySize() {
  return undoHistory.size;
}

export default {
  fixTrailingWhitespace,
  fixImports,
  fixFormatting,
  suggestFixes,
  applyFixes,
  undo,
  clearUndoHistory,
  getUndoHistorySize
};
