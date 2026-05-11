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

export interface ScanResponse {
    findings: Finding[];
}

export interface ScanError {
    detail: string;
}
