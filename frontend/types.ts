// TypeScript types for frontend.

export type Severity = "critical" | "high" | "medium" | "low";
export type Category = "secrets" | "dangerous-code" | "config" | "cors" | "exposure";
export type FileContext = "Production code" | "Test/demo file" | "Example/template file" | "Generated/dependency file";

export interface Finding {
    rule_id: string;
    title: string;
    severity: Severity;
    category: Category;
    file: string;
    line: number;
    evidence: string;
    recommendation: string;
    file_context: FileContext;
    original_severity?: Severity | null;
    adjusted_severity_reason?: string;
    score_penalty?: number;
}

export interface ScanSummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    score: number;
    risk_label: string;
    warning_message: string;
    scanned_files: number;
    ignored_files: number;
    skipped_generated_dependency_files: number;
    production_penalty: number;
    real_env_config_penalty: number;
    test_demo_penalty: number;
    documentation_template_penalty: number;
    duplicate_caps_applied: boolean;
    production_critical_count: number;
    env_critical_count: number;
    test_demo_critical_count: number;
    docs_template_critical_count: number;
    generated_dependency_critical_count: number;
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
