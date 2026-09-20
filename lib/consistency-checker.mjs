/**
 * SPECTER — Consistency Checker
 * Verifies output matches intent and detects regressions.
 */

// Configurable thresholds
const DEFAULT_THRESHOLDS = {
  keywordCoverageMin: 0.4,
  relevanceMin: 0.2,
  relevanceGood: 0.5
};

/**
 * Tokenize text into normalized words for comparison.
 */
function tokenize(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 1);
}

/**
 * Compute term frequency map.
 */
function termFrequency(tokens) {
  const freq = {};
  for (const t of tokens) {
    freq[t] = (freq[t] || 0) + 1;
  }
  return freq;
}

/**
 * Cosine similarity between two term frequency maps.
 */
function cosineSimilarity(tfA, tfB) {
  const allTerms = new Set([...Object.keys(tfA), ...Object.keys(tfB)]);
  let dotProduct = 0;
  let magA = 0;
  let magB = 0;

  for (const term of allTerms) {
    const a = tfA[term] || 0;
    const b = tfB[term] || 0;
    dotProduct += a * b;
    magA += a * a;
    magB += b * b;
  }

  if (magA === 0 || magB === 0) return 0;
  return dotProduct / (Math.sqrt(magA) * Math.sqrt(magB));
}

/**
 * Extract key topics / requirements from a request.
 */
function extractRequirements(text) {
  const requirements = [];
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);

  for (const line of lines) {
    // Numbered items
    if (/^\d+[.)]\s+/.test(line)) {
      requirements.push(line.replace(/^\d+[.)]\s+/, ''));
    }
    // Bullet items
    else if (/^[-*+]\s+/.test(line)) {
      requirements.push(line.replace(/^[-*+]\s+/, ''));
    }
    // "should", "must", "need to" phrases
    else if (/\b(should|must|need\s+to|has\s+to|require|implement|add|create|fix|update|write|build)\b/i.test(line)) {
      requirements.push(line);
    }
  }

  // If no structured requirements found, treat entire text as one requirement
  if (requirements.length === 0 && text.trim()) {
    requirements.push(text.trim());
  }

  return requirements;
}

/**
 * Check if a response addresses all parts of a request.
 * @param {string} request - The original request/instruction
 * @param {string} response - The generated response/output
 * @param {{ thresholds?: object }} options - Optional configuration
 * @returns {{ complete: boolean, score: number, addressed: string[], missed: string[] }}
 */
export function checkCompleteness(request, response, options = {}) {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...options.thresholds };
  const requirements = extractRequirements(request);
  const responseTokens = new Set(tokenize(response));
  const responseLower = response.toLowerCase();

  const addressed = [];
  const missed = [];

  for (const req of requirements) {
    const reqTokens = tokenize(req);
    const keyWords = reqTokens.filter(t => t.length > 3);

    if (keyWords.length === 0) {
      addressed.push(req);
      continue;
    }

    // Check what fraction of key terms appear in the response
    const found = keyWords.filter(w => responseTokens.has(w) || responseLower.includes(w));
    const coverage = found.length / keyWords.length;

    if (coverage >= thresholds.keywordCoverageMin) {
      addressed.push(req);
    } else {
      missed.push(req);
    }
  }

  const total = requirements.length || 1;
  const score = Math.round((addressed.length / total) * 100);

  return {
    complete: missed.length === 0,
    score,
    addressed,
    missed
  };
}

/**
 * Extract semantic concepts from code (function names, variables, key operations).
 * @param {string} code - Source code
 * @returns {{ functions: string[], classes: string[], variables: string[], operations: string[] }}
 */
function extractConcepts(code) {
  const concepts = {
    functions: [],
    classes: [],
    variables: [],
    operations: []
  };

  const lines = code.split('\n');

  for (const line of lines) {
    // Function declarations
    const funcMatch = line.match(/(?:function|def|fn|func)\s+([a-zA-Z_]\w*)/);
    if (funcMatch) concepts.functions.push(funcMatch[1]);

    // Arrow functions and const functions
    const arrowMatch = line.match(/(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>/);
    if (arrowMatch) concepts.functions.push(arrowMatch[1]);

    // Method declarations (e.g., greet() { ... })
    const methodMatch = line.match(/^\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{/);
    if (methodMatch) concepts.functions.push(methodMatch[1]);

    // Class declarations
    const classMatch = line.match(/(?:class|struct|type)\s+([A-Z]\w*)/);
    if (classMatch) concepts.classes.push(classMatch[1]);

    // Variable declarations
    const varMatch = line.match(/(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=/);
    if (varMatch && !arrowMatch) concepts.variables.push(varMatch[1]);

    // Key operations
    if (/\b(?:if|while|for|switch|match)\b/.test(line)) concepts.operations.push('conditional');
    if (/\b(?:try|catch|except|rescue)\b/.test(line)) concepts.operations.push('error_handling');
    if (/\b(?:return|yield)\b/.test(line)) concepts.operations.push('return');
    if (/\b(?:import|require|from.*import)\b/.test(line)) concepts.operations.push('import');
    if (/\b(?:async|await|promise|then)\b/i.test(line)) concepts.operations.push('async');
  }

  return concepts;
}

/**
 * Compute semantic diff between two code snippets.
 * @param {string} oldCode - Original code
 * @param {string} newCode - Modified code
 * @returns {{ added: object, removed: object, modified: object, summary: string }}
 */
export function semanticDiff(oldCode, newCode) {
  const oldConcepts = extractConcepts(oldCode);
  const newConcepts = extractConcepts(newCode);

  const added = {
    functions: newConcepts.functions.filter(f => !oldConcepts.functions.includes(f)),
    classes: newConcepts.classes.filter(c => !oldConcepts.classes.includes(c)),
    variables: newConcepts.variables.filter(v => !oldConcepts.variables.includes(v))
  };

  const removed = {
    functions: oldConcepts.functions.filter(f => !newConcepts.functions.includes(f)),
    classes: oldConcepts.classes.filter(c => !newConcepts.classes.includes(c)),
    variables: oldConcepts.variables.filter(v => !newConcepts.variables.includes(v))
  };

  const modified = {
    functions: oldConcepts.functions.filter(f => newConcepts.functions.includes(f)),
    classes: oldConcepts.classes.filter(c => newConcepts.classes.includes(c))
  };

  // Build summary
  const parts = [];
  if (added.functions.length > 0) parts.push(`Added ${added.functions.length} function(s): ${added.functions.join(', ')}`);
  if (removed.functions.length > 0) parts.push(`Removed ${removed.functions.length} function(s): ${removed.functions.join(', ')}`);
  if (added.classes.length > 0) parts.push(`Added ${added.classes.length} class(es): ${added.classes.join(', ')}`);
  if (removed.classes.length > 0) parts.push(`Removed ${removed.classes.length} class(es): ${removed.classes.join(', ')}`);
  if (modified.functions.length > 0) parts.push(`Modified ${modified.functions.length} existing function(s)`);

  const summary = parts.length > 0 ? parts.join('; ') : 'Minor changes without structural modifications';

  return { added, removed, modified, summary };
}

/**
 * Check if code changes are consistent with the stated intent.
 * @param {string} oldCode - Original code
 * @param {string} newCode - Modified code
 * @param {string} intent - Description of what the change should do
 * @param {{ thresholds?: object }} options - Optional configuration
 * @returns {{ consistent: boolean, score: number, observations: string[], semanticDiff?: object }}
 */
export function checkConsistency(oldCode, newCode, intent, options = {}) {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...options.thresholds };
  const observations = [];
  const intentLower = intent.toLowerCase();
  const intentTokens = new Set(tokenize(intent));

  // Compute semantic diff
  const semDiff = semanticDiff(oldCode, newCode);

  // Compute line-level diff
  const oldLines = oldCode.split('\n');
  const newLines = newCode.split('\n');
  const oldSet = new Set(oldLines);
  const newSet = new Set(newLines);

  const added = newLines.filter(l => !oldSet.has(l) && l.trim());
  const removed = oldLines.filter(l => !newSet.has(l) && l.trim());

  // Check if semantic changes relate to intent
  const semanticChangeText = [
    ...semDiff.added.functions,
    ...semDiff.removed.functions,
    ...semDiff.added.classes,
    ...semDiff.removed.classes
  ].join(' ');

  const changedText = [...added, ...removed, semanticChangeText].join(' ');
  const changedTokens = new Set(tokenize(changedText));
  const overlap = [...intentTokens].filter(t => changedTokens.has(t));
  const relevance = intentTokens.size > 0 ? overlap.length / intentTokens.size : 0;

  if (relevance < thresholds.relevanceMin) {
    observations.push('Changes appear unrelated to the stated intent');
  } else if (relevance > thresholds.relevanceGood) {
    observations.push('Changes are well-aligned with the stated intent');
  }

  // Add semantic observations
  if (semDiff.added.functions.length > 0 || semDiff.removed.functions.length > 0) {
    observations.push(semDiff.summary);
  }

  // Size analysis
  if (removed.length > added.length * 3 && !intentLower.includes('remove') && !intentLower.includes('delete') && !intentLower.includes('clean')) {
    observations.push(`Significant code removal detected (${removed.length} lines removed vs ${added.length} added) — verify this is intentional`);
  }

  if (added.length > oldLines.length * 2) {
    observations.push(`Code size more than tripled — verify scope of changes`);
  }

  // Check for accidental changes
  if (oldCode === newCode) {
    observations.push('No changes were made to the code');
    return { consistent: false, score: 0, observations };
  }

  // Intent-specific checks
  if (intentLower.includes('fix') || intentLower.includes('bug')) {
    if (removed.length === 0 && added.length > 20) {
      observations.push('Bug fix added many lines but removed none — this might be a feature addition rather than a fix');
    }
  }

  if (intentLower.includes('refactor')) {
    const sizeDiff = Math.abs(newLines.length - oldLines.length);
    if (sizeDiff > oldLines.length * 0.5) {
      observations.push('Refactoring changed code size significantly — verify the scope');
    }
  }

  if (intentLower.includes('rename')) {
    if (added.length < 1 || removed.length < 1) {
      observations.push('Rename intent but changes do not show consistent find-and-replace pattern');
    }
  }

  // Score: combination of relevance and structural reasonableness
  let score = Math.round(relevance * 60);

  // Bonus for reasonable change size
  const changeRatio = (added.length + removed.length) / Math.max(oldLines.length, 1);
  if (changeRatio > 0 && changeRatio < 2) score += 20;
  else if (changeRatio >= 2) score += 5;

  // Bonus for having both additions and context
  if (added.length > 0) score += 10;
  if (observations.every(o => !o.includes('unrelated') && !o.includes('No changes'))) score += 10;

  score = Math.min(100, Math.max(0, score));

  return {
    consistent: score >= 50,
    score,
    observations,
    semanticDiff: semDiff
  };
}

/**
 * Detect potential regressions in a diff.
 * @param {string} diff - Unified diff or old/new pair description
 * @returns {{ hasRegressions: boolean, regressions: Array<{ type: string, description: string, severity: string }> }}
 */
export function detectRegressions(diff) {
  const regressions = [];
  const lines = diff.split('\n');
  const removedLines = [];
  const addedLines = [];

  for (const line of lines) {
    if (line.startsWith('-') && !line.startsWith('---')) {
      removedLines.push(line.substring(1).trim());
    } else if (line.startsWith('+') && !line.startsWith('+++')) {
      addedLines.push(line.substring(1).trim());
    }
  }

  const addedText = addedLines.join('\n').toLowerCase();

  // Check for removed error handling
  for (const removed of removedLines) {
    const lower = removed.toLowerCase();

    if (/\b(try|catch|except|finally|on\s*error)\b/.test(removed) && !addedText.includes(lower)) {
      regressions.push({
        type: 'error_handling_removed',
        description: `Error handling removed: "${removed.substring(0, 80)}"`,
        severity: 'high'
      });
    }

    // Check for removed validation
    if (/\b(validate|sanitize|check|verify|assert|ensure)\b/i.test(removed) && !addedText.includes(lower)) {
      regressions.push({
        type: 'validation_removed',
        description: `Validation logic removed: "${removed.substring(0, 80)}"`,
        severity: 'high'
      });
    }

    // Check for removed security measures
    if (/\b(auth|permission|csrf|xss|sanitize|escape|encrypt|hash)\b/i.test(removed) && !addedText.includes(lower)) {
      regressions.push({
        type: 'security_removed',
        description: `Security measure removed: "${removed.substring(0, 80)}"`,
        severity: 'critical'
      });
    }

    // Check for removed tests
    if (/\b(test|it|describe|expect|assert|should)\b/i.test(removed) && !addedText.includes(lower)) {
      regressions.push({
        type: 'test_removed',
        description: `Test code removed: "${removed.substring(0, 80)}"`,
        severity: 'medium'
      });
    }

    // Check for removed logging/monitoring
    if (/\b(log|logger|console\.(log|warn|error)|monitoring|metrics)\b/i.test(removed) && !addedText.includes(lower)) {
      regressions.push({
        type: 'logging_removed',
        description: `Logging/monitoring removed: "${removed.substring(0, 80)}"`,
        severity: 'low'
      });
    }
  }

  // Check for removed function/method definitions
  const removedFunctions = removedLines.filter(l =>
    /\b(function|def|class|method|const\s+\w+\s*=\s*(?:async\s*)?\()\b/.test(l)
  );
  const addedFunctions = addedLines.filter(l =>
    /\b(function|def|class|method|const\s+\w+\s*=\s*(?:async\s*)?\()\b/.test(l)
  );

  if (removedFunctions.length > addedFunctions.length) {
    const netRemoved = removedFunctions.length - addedFunctions.length;
    regressions.push({
      type: 'function_removed',
      description: `${netRemoved} function/class definition(s) were removed without replacement`,
      severity: 'medium'
    });
  }

  // Check for removed imports
  const removedImports = removedLines.filter(l => /\b(import|require|from)\b/.test(l));
  const addedImports = addedLines.filter(l => /\b(import|require|from)\b/.test(l));
  if (removedImports.length > addedImports.length + 2) {
    regressions.push({
      type: 'imports_removed',
      description: `Multiple imports removed — ensure no needed dependencies were dropped`,
      severity: 'medium'
    });
  }

  return {
    hasRegressions: regressions.length > 0,
    regressions
  };
}

/**
 * Score how well a response aligns with a request.
 * @param {string} request - The original request
 * @param {string} response - The response to evaluate
 * @returns {{ score: number, details: { topicOverlap: number, completeness: number, verbosity: number } }}
 */
export function scoreAlignment(request, response) {
  // Topic overlap via cosine similarity
  const reqTokens = tokenize(request);
  const resTokens = tokenize(response);
  const reqTF = termFrequency(reqTokens);
  const resTF = termFrequency(resTokens);
  const topicOverlap = Math.round(cosineSimilarity(reqTF, resTF) * 100);

  // Completeness
  const { score: completeness } = checkCompleteness(request, response);

  // Verbosity penalty — response should not be excessively long relative to request
  const ratio = resTokens.length / Math.max(reqTokens.length, 1);
  let verbosity;
  if (ratio < 0.5) verbosity = 40; // Too short
  else if (reqTokens.length >= 10 && ratio > 50) verbosity = 60; // Very verbose (only if request has substance)
  else if (reqTokens.length >= 10 && ratio > 20) verbosity = 75;
  else verbosity = 100; // Reasonable

  // Composite score
  const score = Math.round(topicOverlap * 0.3 + completeness * 0.5 + verbosity * 0.2);

  return {
    score: Math.min(100, Math.max(0, score)),
    details: {
      topicOverlap,
      completeness,
      verbosity
    }
  };
}

export default {
  checkCompleteness,
  checkConsistency,
  detectRegressions,
  scoreAlignment,
  semanticDiff
};
