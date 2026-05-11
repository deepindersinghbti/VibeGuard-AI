// TypeScript types for frontend.

export type Severity = "critical" | "high" | "medium" | "low";
export type Category = "secrets" | "dangerous-code" | "config" | "cors" | "exposure";

export interface Finding {
    rule_id: string;
    title: string;
    severity: Severity;
    category: Category;
    file: string;
    line: number;
    evidence: string;
    recommendation: string;
}

export interface ScanSummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    score: number;
}

export interface ScanResponse {
    summary: ScanSummary;
    findings: Finding[];
}

export interface ExplainResponse {
    explanation: string;
    attack_scenario: string;
    fix_details: string;
    error_code?: string;  // Internal error code for debugging/logging
}

export interface ScanError {
    detail: string;
}
