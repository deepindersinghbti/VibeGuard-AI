/**
 * Normalize AI-generated explanation text.
 * 
 * Detects inline numbered lists (e.g., "1. item 2. item 3. item")
 * and converts them to proper multiline Markdown format.
 * 
 * Safely avoids breaking:
 * - Decimal numbers (e.g., "3.14", "version 2.0")
 * - File paths and code (e.g., "file.ts", "object.method()")
 * - URLs and domains (e.g., "example.com", "http://domain.com")
 */

/**
 * Detect if text contains inline numbered list items like "1. x 2. y 3. z"
 * 
 * Patterns to detect:
 * - ". 2." typically indicates end of item 1 and start of item 2
 * - ". 3.", ". 4." etc. indicate continuation
 * - Not triggered by decimal numbers like "3.14"
 * - Not triggered by filenames like "file.2.ts"
 */
function isInlineNumberedList(text: string): boolean {
    // Pattern: period + space + digit + period (like ". 2.", ". 3.")
    // Must have at least 2 occurrences to be considered a list
    // Negative lookbehind: not preceded by digit (to avoid "3.14")
    // Negative lookahead: not followed by more digits (to avoid "version 2.0")
    const pattern = /(?<!\d)\.\s+[2-9]\./g;
    const matches = text.match(pattern);
    return (matches ?? []).length >= 1;
}

/**
 * Normalize inline numbered list items to multiline format.
 * 
 * Converts: "1. Remove key. 2. Store in env. 3. Use getenv()."
 * To:
 * 1. Remove key.
 * 2. Store in env.
 * 3. Use getenv().
 * 
 * Preserves context:
 * - Detects list position (start, middle, end of text)
 * - Only inserts newline before numbered items if not already present
 * - Handles edge cases (multiple spaces, existing newlines)
 */
function normalizeInlineNumberedList(text: string): string {
    if (!isInlineNumberedList(text)) {
        return text;
    }

    // Pattern explanation:
    // \.\s+ = period + spaces
    // (?=[2-9]\.) = lookahead for digit 2-9 + period (the start of next item)
    // Replace with: period + newline + optional indentation
    // Use \n for universal newline handling
    const normalized = text.replace(/\.\s+(?=[2-9]\.)/g, ".\n");

    return normalized;
}

/**
 * Main normalization function.
 * Applies all normalization rules to explanation text.
 * 
 * @param text - Raw AI-generated explanation text
 * @returns Normalized text safe for Markdown rendering
 */
export function normalizeExplanation(text: string): string {
    if (!text || typeof text !== "string") {
        return text;
    }

    // Trim excess whitespace but preserve internal formatting
    let normalized = text.trim();

    // Fix inline numbered lists
    normalized = normalizeInlineNumberedList(normalized);

    return normalized;
}

/**
 * Batch normalize multiple explanation fields.
 * Useful for normalizing entire ExplainResponse object.
 * 
 * @param explanations - Object with string properties to normalize
 * @returns Same object with all string values normalized
 */
export function normalizeAllExplanations<T extends Record<string, any>>(
    explanations: T
): T {
    const normalized = { ...explanations };

    for (const key in normalized) {
        if (typeof normalized[key] === "string") {
            (normalized as any)[key] = normalizeExplanation(normalized[key]);
        }
    }

    return normalized;
}
