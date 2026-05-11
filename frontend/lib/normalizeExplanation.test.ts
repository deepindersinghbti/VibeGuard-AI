/**
 * Test cases for normalizeExplanation function
 * Demonstrates how inline numbered lists are converted to multiline format
 */

import { normalizeExplanation } from "./normalizeExplanation";

// Test case 1: Already properly formatted (multiline) - should pass through unchanged
const testCase1Input = `1. Remove the API key from your code.
2. Store it securely in environment variables.
3. Access it using process.env.API_KEY.
4. Never commit .env files to version control.`;

const testCase1Expected = testCase1Input; // No change needed

// Test case 2: Inline numbered list - should be normalized to multiline
const testCase2Input = `1. Remove the API key immediately. 2. Store it securely in environment variables. 3. Access it using process.env.API_KEY. 4. Never commit .env files.`;

const testCase2Expected = `1. Remove the API key immediately.
2. Store it securely in environment variables.
3. Access it using process.env.API_KEY.
4. Never commit .env files.`;

// Test case 3: Should NOT break decimal numbers
const testCase3Input = `Version 2.0 fixed item 3.14 billion issues. 2. Second item.`;
const testCase3Expected = `Version 2.0 fixed item 3.14 billion issues.
2. Second item.`;

// Test case 4: Should handle edge case with multiple spaces
const testCase4Input = `1. First item.    2. Second item.   3. Third item.`;
const testCase4Expected = `1. First item.
2. Second item.
3. Third item.`;

// Test case 5: Empty or null strings should pass through safely
const testCase5Input = "";
const testCase5Expected = "";

console.log("Testing normalizeExplanation function...\n");

let passCount = 0;
let failCount = 0;

function testCase(name: string, input: string, expected: string) {
    const result = normalizeExplanation(input);
    const passed = result === expected;

    if (passed) {
        passCount++;
        console.log(`✓ ${name}`);
    } else {
        failCount++;
        console.log(`✗ ${name}`);
        console.log(`  Input:    ${JSON.stringify(input)}`);
        console.log(`  Expected: ${JSON.stringify(expected)}`);
        console.log(`  Got:      ${JSON.stringify(result)}`);
    }
}

testCase(
    "Test 1: Properly formatted multiline list (no change needed)",
    testCase1Input,
    testCase1Expected
);

testCase(
    "Test 2: Inline numbered list converted to multiline",
    testCase2Input,
    testCase2Expected
);

testCase(
    "Test 3: Does not break decimal numbers",
    testCase3Input,
    testCase3Expected
);

testCase(
    "Test 4: Handles multiple spaces between items",
    testCase4Input,
    testCase4Expected
);

testCase("Test 5: Empty string passes through safely", testCase5Input, testCase5Expected);

console.log(`\n${passCount} passed, ${failCount} failed`);
