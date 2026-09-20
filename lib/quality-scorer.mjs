/**
 * SPECTER — Quality Scorer
 * Composite quality assessment engine.
 */

import { checkJavaScript, checkTypeScript, checkPython, checkGo, checkRust, checkJSON, checkMarkdown, detectLanguage } from './syntax-checker.mjs';
import { getSecurityScore } from './security-scanner.mjs';
import { checkCompleteness, scoreAlignment } from './consistency-checker.mjs';

// Weight profiles for different quality standards
const WEIGHT_PROFILES = {
  strict: {
    syntax: 0.30,
    security: 0.40,
    completeness: 0.20,
    alignment: 0.10,
    description: 'High quality bar — prioritizes security and correctness'
  },
  balanced: {
    syntax: 0.25,
    security: 0.30,
    completeness: 0.25,
    alignment: 0.20,
    description: 'Balanced approach — equal weight on all dimensions'
  },
  lenient: {
    syntax: 0.20,
    security: 0.20,
    completeness: 0.30,
    alignment: 0.30,
    description: 'Permissive — focuses on completeness and alignment over strict correctness'
  }
};

// Per-language quality profiles (optional overrides)
const LANGUAGE_PROFILES = {
  javascript: { defaultProfile: 'balanced' },
  typescript: { defaultProfile: 'strict' },
  python: { defaultProfile: 'balanced' },
  go: { defaultProfile: 'strict' },
  rust: { defaultProfile: 'strict' },
  json: { defaultProfile: 'strict', weights: { syntax: 0.60, security: 0.20, completeness: 0.10, alignment: 0.10 } },
  markdown: { defaultProfile: 'lenient', weights: { syntax: 0.15, security: 0.10, completeness: 0.40, alignment: 0.35 } }
};

// Simple cache for repeated evaluations
const evaluationCache = new Map();

/**
 * Run syntax check for the detected or specified language.
 */
function runSyntaxCheck(code, language) {
  switch (language) {
    case 'javascript':
      return checkJavaScript(code);
    case 'typescript':
      return checkTypeScript(code);
    case 'python':
      return checkPython(code);
    case 'go':
      return checkGo(code);
    case 'rust':
      return checkRust(code);
    case 'json':
      return checkJSON(code);
    case 'markdown':
      return checkMarkdown(code);
    default:
      return { valid: true, errors: [] };
  }
}

/**
 * Compute a composite quality score for an output.
 * @param {string} output - The output text/code
 * @param {{ request?: string, language?: string, threshold?: number, profile?: string, weights?: object, enableCache?: boolean }} context - Context for scoring
 * @returns {{ score: number, grade: string, passed: boolean, dimensions: object, profile?: string }}
 */
export function scoreOutput(output, context = {}) {
  const { request = '', language: explicitLang, threshold = 60, profile: profileName, weights: customWeights, enableCache = false } = context;

  // Check cache if enabled
  const cacheKey = enableCache ? `${output.substring(0, 100)}_${profileName}_${request}` : null;
  if (enableCache && cacheKey && evaluationCache.has(cacheKey)) {
    return evaluationCache.get(cacheKey);
  }

  // Detect language if not specified
  const detected = detectLanguage(output);
  const language = explicitLang || detected.language;

  // Determine weights based on profile and language
  let weights;
  if (customWeights) {
    weights = customWeights;
  } else {
    const langProfile = LANGUAGE_PROFILES[language];
    if (langProfile && langProfile.weights) {
      weights = langProfile.weights;
    } else {
      const defaultProfileName = profileName || (langProfile ? langProfile.defaultProfile : 'balanced');
      weights = WEIGHT_PROFILES[defaultProfileName] || WEIGHT_PROFILES.balanced;
    }
  }

  // Dimension 1: Syntax
  const syntaxResult = runSyntaxCheck(output, language);
  const syntaxScore = syntaxResult.valid ? 100 : Math.max(0, 100 - syntaxResult.errors.length * 15);

  // Dimension 2: Security
  const secResult = getSecurityScore(output);
  const securityScore = secResult.score;

  // Dimension 3: Completeness
  let completenessScore = 70; // Neutral score when no request provided
  if (request) {
    const compResult = checkCompleteness(request, output);
    completenessScore = compResult.score;
  }

  // Dimension 4: Consistency/Alignment
  let alignmentScore = 70; // Neutral score when no request provided
  if (request) {
    const alignResult = scoreAlignment(request, output);
    alignmentScore = alignResult.score;
  }

  // Weighted composite
  const composite = Math.round(
    syntaxScore * weights.syntax +
    securityScore * weights.security +
    completenessScore * weights.completeness +
    alignmentScore * weights.alignment
  );

  // Grade
  let grade;
  if (composite >= 90) grade = 'A';
  else if (composite >= 80) grade = 'B';
  else if (composite >= 70) grade = 'C';
  else if (composite >= 60) grade = 'D';
  else grade = 'F';

  const result = {
    score: composite,
    grade,
    passed: composite >= threshold,
    language,
    profile: profileName || (LANGUAGE_PROFILES[language] ? LANGUAGE_PROFILES[language].defaultProfile : 'balanced'),
    dimensions: {
      syntax: { score: syntaxScore, weight: weights.syntax, errors: syntaxResult.errors.length },
      security: { score: securityScore, weight: weights.security, findings: secResult.totalFindings },
      completeness: { score: completenessScore, weight: weights.completeness },
      alignment: { score: alignmentScore, weight: weights.alignment }
    }
  };

  // Cache the result if enabled
  if (enableCache && cacheKey) {
    evaluationCache.set(cacheKey, result);
    // Keep cache size reasonable (max 100 entries)
    if (evaluationCache.size > 100) {
      const firstKey = evaluationCache.keys().next().value;
      evaluationCache.delete(firstKey);
    }
  }

  return result;
}

/**
 * Get detailed per-dimension score breakdown.
 * @param {string} output - The output text/code
 * @param {{ request?: string, language?: string }} context - Optional context for completeness/alignment
 * @returns {{ language: string, syntax: object, security: object, completeness: object, alignment: object }}
 */
export function getBreakdown(output, context = {}) {
  const { request = '', language: explicitLang } = context;
  const detected = detectLanguage(output);
  const language = explicitLang || detected.language;

  const syntaxResult = runSyntaxCheck(output, language);
  const secResult = getSecurityScore(output);

  // Completeness dimension
  let completenessScore = 70;
  let completenessDetails = { score: 70, note: 'No request provided for comparison' };
  if (request) {
    const compResult = checkCompleteness(request, output);
    completenessScore = compResult.score;
    completenessDetails = {
      score: compResult.score,
      complete: compResult.complete,
      addressed: compResult.addressed.length,
      addressedItems: compResult.addressed,
      missed: compResult.missed.length,
      missedItems: compResult.missed
    };
  }

  // Alignment dimension
  let alignmentScore = 70;
  let alignmentDetails = { score: 70, note: 'No request provided for comparison' };
  if (request) {
    const alignResult = scoreAlignment(request, output);
    alignmentScore = alignResult.score;
    alignmentDetails = {
      score: alignResult.score,
      topicOverlap: alignResult.details.topicOverlap,
      completeness: alignResult.details.completeness,
      verbosity: alignResult.details.verbosity
    };
  }

  return {
    language,
    syntax: {
      valid: syntaxResult.valid,
      errorCount: syntaxResult.errors.length,
      errors: syntaxResult.errors.slice(0, 10),
      score: syntaxResult.valid ? 100 : Math.max(0, 100 - syntaxResult.errors.length * 15)
    },
    security: {
      score: secResult.score,
      breakdown: secResult.breakdown,
      totalFindings: secResult.totalFindings,
      summary: secResult.summary
    },
    completeness: completenessDetails,
    alignment: alignmentDetails
  };
}

/**
 * Determine if output should be blocked based on quality score.
 * @param {number} score - Quality score (0-100)
 * @param {number} threshold - Minimum acceptable score (default 60)
 * @returns {{ blocked: boolean, reason: string }}
 */
export function shouldBlock(score, threshold = 60) {
  if (score >= threshold) {
    return { blocked: false, reason: 'Score meets threshold' };
  }

  let reason;
  if (score < 30) reason = `Critical quality failure (score: ${score}). Output contains severe issues.`;
  else if (score < 50) reason = `Low quality score (${score}). Output has significant issues requiring attention.`;
  else reason = `Below threshold (${score} < ${threshold}). Output needs improvement before delivery.`;

  return { blocked: true, reason };
}

/**
 * Generate a quality trend report from multiple outputs.
 * @param {Array<{ output: string, context?: object, timestamp?: string }>} outputs
 * @returns {{ averageScore: number, trend: string, report: object }}
 */
export function generateReport(outputs) {
  if (!outputs || outputs.length === 0) {
    return { averageScore: 0, trend: 'no_data', report: { entries: [] } };
  }

  const entries = outputs.map((item, idx) => {
    const result = scoreOutput(item.output, item.context || {});
    return {
      index: idx,
      timestamp: item.timestamp || new Date().toISOString(),
      score: result.score,
      grade: result.grade,
      passed: result.passed,
      dimensions: result.dimensions
    };
  });

  const scores = entries.map(e => e.score);
  const averageScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);

  // Trend detection
  let trend = 'stable';
  if (scores.length >= 3) {
    const firstHalf = scores.slice(0, Math.floor(scores.length / 2));
    const secondHalf = scores.slice(Math.floor(scores.length / 2));
    const avgFirst = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const avgSecond = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    if (avgSecond - avgFirst > 5) trend = 'improving';
    else if (avgFirst - avgSecond > 5) trend = 'declining';
  }

  // Summary stats
  const passRate = Math.round((entries.filter(e => e.passed).length / entries.length) * 100);
  const gradeDistribution = {};
  for (const e of entries) {
    gradeDistribution[e.grade] = (gradeDistribution[e.grade] || 0) + 1;
  }

  // Dimension averages
  const dimAvgs = { syntax: 0, security: 0, completeness: 0, alignment: 0 };
  for (const e of entries) {
    for (const dim of Object.keys(dimAvgs)) {
      dimAvgs[dim] += (e.dimensions[dim]?.score || 0);
    }
  }
  for (const dim of Object.keys(dimAvgs)) {
    dimAvgs[dim] = Math.round(dimAvgs[dim] / entries.length);
  }

  return {
    averageScore,
    trend,
    report: {
      totalOutputs: entries.length,
      passRate,
      gradeDistribution,
      dimensionAverages: dimAvgs,
      lowest: entries.reduce((min, e) => e.score < min.score ? e : min, entries[0]),
      highest: entries.reduce((max, e) => e.score > max.score ? e : max, entries[0]),
      entries
    }
  };
}

/**
 * Clear the evaluation cache.
 */
export function clearCache() {
  evaluationCache.clear();
}

/**
 * Get available weight profiles.
 * @returns {{ strict: object, balanced: object, lenient: object }}
 */
export function getWeightProfiles() {
  return WEIGHT_PROFILES;
}

export default {
  scoreOutput,
  getBreakdown,
  shouldBlock,
  generateReport,
  clearCache,
  getWeightProfiles,
  WEIGHT_PROFILES
};
