import { Finding, ScanSummary, Severity } from "../types";

export type ScanContext = {
    scanType: "ZIP upload" | "GitHub repository scan";
    sourceName: string;
};

const SEVERITY_PRIORITY: Record<Severity, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
};

export function formatReportDate(date: Date): string {
    return new Intl.DateTimeFormat("en", {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    }).format(date);
}

export function formatReportFileDate(date: Date): string {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");

    return `${year}-${month}-${day}`;
}

export function buildReportFilename(date: Date): string {
    return `vibeguard-security-report-${formatReportFileDate(date)}.pdf`;
}

export function getFindingReportKey(finding: Finding, index: number): string {
    return `${finding.rule_id}:${finding.file}:${finding.line}:${index}`;
}

export function buildExecutiveSummary(summary: ScanSummary, findings: Finding[]): string[] {
    if (summary.total === 0) {
        return [
            "This scan did not detect security warnings in the analyzed source.",
            "Continue reviewing secrets, environment files, generated dependencies, and deployment configuration before release.",
        ];
    }

    const highestSeverity = getHighestSeverity(findings);
    const topCategories = getTopCategories(findings);
    const riskLabel = summary.risk_label || deriveRiskLabel(summary.score);

    const sentences = [
        `This scan detected ${summary.total} potential security warning${summary.total === 1 ? "" : "s"} across the analyzed project.`,
        `The current security score is ${summary.score} / 100, classified as ${riskLabel}.`,
    ];

    if (highestSeverity) {
        sentences.push(
            `The most serious findings are ${highestSeverity} severity and should be reviewed before committing, deploying, or sharing this project.`
        );
    }

    if (topCategories.length > 0) {
        sentences.push(`The most common risk categor${topCategories.length === 1 ? "y is" : "ies are"} ${topCategories.join(", ")}.`);
    }

    return sentences.slice(0, 4);
}

function getHighestSeverity(findings: Finding[]): Severity | null {
    return findings.reduce<Severity | null>((highest, finding) => {
        if (!highest || SEVERITY_PRIORITY[finding.severity] > SEVERITY_PRIORITY[highest]) {
            return finding.severity;
        }

        return highest;
    }, null);
}

function getTopCategories(findings: Finding[]): string[] {
    const counts = findings.reduce<Record<string, number>>((current, finding) => {
        current[finding.category] = (current[finding.category] ?? 0) + 1;
        return current;
    }, {});

    return Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 2)
        .map(([category]) => category.replace(/-/g, " "));
}

function deriveRiskLabel(score: number): string {
    if (score >= 90) {
        return "Healthy";
    }
    if (score >= 71) {
        return "Low Risk";
    }
    if (score >= 46) {
        return "Moderate Risk";
    }
    if (score >= 21) {
        return "High Risk";
    }
    return "Critical Risk";
}
