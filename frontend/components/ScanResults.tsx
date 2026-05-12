"use client";

import React from "react";
import { explainFinding } from "../lib/api";
import { normalizeExplanation } from "../lib/normalizeExplanation";
import { ExplainResponse, Finding, ScanSummary, Severity } from "../types";
import { MarkdownContent } from "./MarkdownContent";

interface ScanResultsProps {
    summary: ScanSummary;
    findings: Finding[];
}

const SEVERITY_BADGE: Record<Severity, string> = {
    critical: "bg-red-100 text-red-700 ring-red-200",
    high: "bg-orange-100 text-orange-700 ring-orange-200",
    medium: "bg-yellow-100 text-yellow-800 ring-yellow-200",
    low: "bg-green-100 text-green-700 ring-green-200",
};

const SEVERITY_TEXT: Record<Severity, string> = {
    critical: "text-red-700",
    high: "text-orange-700",
    medium: "text-yellow-700",
    low: "text-green-700",
};

const SEVERITY_ACCENT: Record<Severity, string> = {
    critical: "border-red-300",
    high: "border-orange-300",
    medium: "border-yellow-300",
    low: "border-green-300",
};

function scoreColor(score: number): string {
    if (score >= 80) {
        return "bg-green-600";
    }
    if (score >= 50) {
        return "bg-yellow-500";
    }
    return "bg-red-600";
}

function riskLabel(score: number): string {
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

function summaryMessage(summary: ScanSummary): string {
    if (summary.critical > 0) {
        return "⚠️ Critical issues found. Fix immediately before deploying.";
    }

    if (summary.total > 0) {
        return "⚠️ Some issues found. Review before deploying.";
    }

    return "✅ No security issues found. Your code looks safe.";
}

function contextAwareSummaryMessage(summary: ScanSummary): string {
    return summary.warning_message || "Security issues found. Review the findings before deploying.";
}

function criticalContextLine(summary: ScanSummary): string {
    const productionCritical = summary.production_critical_count ?? 0;
    const envCritical = summary.env_critical_count ?? 0;
    const testDemoCritical = summary.test_demo_critical_count ?? 0;
    const docsTemplateCritical = summary.docs_template_critical_count ?? 0;
    const generatedCritical = summary.generated_dependency_critical_count ?? 0;
    const totalCritical = productionCritical + envCritical + testDemoCritical + docsTemplateCritical + generatedCritical;

    if (totalCritical === 0) {
        return "Critical issues: 0 total";
    }

    const parts = [
        `${totalCritical} total`,
        `${productionCritical} production`,
        `${envCritical} env/config`,
        `${testDemoCritical} test/demo`,
        `${docsTemplateCritical} docs/templates`,
    ];

    if (generatedCritical > 0) {
        parts.push(`${generatedCritical} generated/dependencies`);
    }

    return `Critical issues: ${parts.join(" · ")}`;
}

function ScanSummaryPanel({ summary }: { summary: ScanSummary }) {
    return (
        <section className="sticky top-4 z-10 mb-8 rounded-lg bg-white p-5 shadow-sm ring-1 ring-slate-200">
            <div className="grid gap-5 lg:grid-cols-[220px_1fr] lg:items-center">
                <div>
                    <p className="text-sm font-medium text-slate-500">Security Score</p>
                    <div className="mt-2 flex items-end gap-2">
                        <span className="text-5xl font-bold tracking-tight text-slate-950">
                            {summary.score}
                        </span>
                        <span className="pb-2 text-sm font-semibold text-slate-500">/ 100</span>
                    </div>
                    <p className="mt-2 text-sm font-semibold text-slate-600">
                        Security Score: {summary.score} / 100 ({summary.risk_label || riskLabel(summary.score)})
                    </p>
                    <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-200">
                        <div
                            className={`h-full rounded-full ${scoreColor(summary.score)}`}
                            style={{ width: `${summary.score}%` }}
                        />
                    </div>
                    <p className="mt-3 text-sm text-slate-500">{contextAwareSummaryMessage(summary)}</p>
                    <p className="mt-1 text-xs font-medium text-slate-500">{criticalContextLine(summary)}</p>
                </div>

                <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                    <SummaryMetric label="Total issues" value={summary.total} className="text-slate-950" />
                    <SummaryMetric label="Critical" value={summary.critical} className={SEVERITY_TEXT.critical} />
                    <SummaryMetric label="High" value={summary.high} className={SEVERITY_TEXT.high} />
                    <SummaryMetric label="Medium" value={summary.medium} className={SEVERITY_TEXT.medium} />
                    <SummaryMetric label="Low" value={summary.low} className={SEVERITY_TEXT.low} />
                </div>

                <div className="grid grid-cols-1 gap-3 border-t border-slate-100 pt-4 sm:grid-cols-3 lg:col-span-2">
                    <SummaryMetric label="Scanned files" value={summary.scanned_files ?? 0} className="text-slate-950" />
                    <SummaryMetric label="Ignored files" value={summary.ignored_files ?? 0} className="text-slate-700" />
                    <SummaryMetric
                        label="Skipped generated/dependencies"
                        value={summary.skipped_generated_dependency_files ?? 0}
                        className="text-slate-700"
                    />
                </div>

                <div className="border-t border-slate-100 pt-4 lg:col-span-2">
                    <p className="mb-3 text-xs font-medium uppercase tracking-wide text-slate-500">
                        Score breakdown
                    </p>
                    <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
                        <SummaryMetric label="Base score" value={100} className="text-slate-950" />
                        <PenaltyMetric label="Production" value={summary.production_penalty ?? 0} />
                        <PenaltyMetric label="Real env/config" value={summary.real_env_config_penalty ?? 0} />
                        <PenaltyMetric label="Test/demo" value={summary.test_demo_penalty ?? 0} />
                        <PenaltyMetric label="Docs/templates" value={summary.documentation_template_penalty ?? 0} />
                        <div className="rounded-md bg-slate-50 px-4 py-3">
                            <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Duplicate caps</p>
                            <p className="mt-1 text-lg font-bold text-slate-700">
                                {summary.duplicate_caps_applied ? "Yes" : "No"}
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}

function SummaryMetric({
    label,
    value,
    className,
}: {
    label: string;
    value: number;
    className: string;
}) {
    return (
        <div className="rounded-md bg-slate-50 px-4 py-3">
            <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
            <p className={`mt-1 text-2xl font-bold ${className}`}>{value}</p>
        </div>
    );
}

function PenaltyMetric({ label, value }: { label: string; value: number }) {
    return <SummaryMetric label={label} value={-Math.round(value)} className="text-slate-700" />;
}

function EmptyState({ summary }: { summary: ScanSummary }) {
    return (
        <div className="space-y-8">
            <ScanSummaryPanel summary={summary} />
            <section className="rounded-lg bg-white px-6 py-14 text-center shadow-sm ring-1 ring-slate-200">
                <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-100 text-2xl">
                    ✅
                </div>
                <h2 className="text-xl font-semibold text-slate-950">No security issues found</h2>
                <p className="mt-2 text-sm text-slate-600">Your code looks safe.</p>
            </section>
        </div>
    );
}

export default function ScanResults({ summary, findings }: ScanResultsProps) {
    const [explanations, setExplanations] = React.useState<Record<string, ExplainResponse>>({});
    const [loadingExplanations, setLoadingExplanations] = React.useState<Record<string, boolean>>({});
    const [openExplanations, setOpenExplanations] = React.useState<Record<string, boolean>>({});
    const [explanationErrors, setExplanationErrors] = React.useState<Record<string, string>>({});

    const findingKey = (finding: Finding, idx: number) =>
        `${finding.rule_id}:${finding.file}:${finding.line}:${idx}`;

    const handleExplain = async (finding: Finding, key: string) => {
        // Open explanation panel
        setOpenExplanations((current) => ({ ...current, [key]: true }));

        // Clear any previous error for this issue
        setExplanationErrors((current) => {
            const updated = { ...current };
            delete updated[key];
            return updated;
        });

        // Exit early if already loading
        if (loadingExplanations[key]) {
            return;
        }

        // Set loading state
        setLoadingExplanations((current) => ({ ...current, [key]: true }));
        try {
            const explanation = await explainFinding(finding);
            // Only set explanation if it's valid
            setExplanations((current) => ({ ...current, [key]: explanation }));
        } catch (error) {
            // Store error message for this specific issue
            const errorMessage = error instanceof Error ? error.message : "Couldn't generate explanation. Please try again.";
            setExplanationErrors((current) => ({ ...current, [key]: errorMessage }));
            // Do NOT set explanations state on error
        } finally {
            setLoadingExplanations((current) => ({ ...current, [key]: false }));
        }
    };

    if (findings.length === 0) {
        return <EmptyState summary={summary} />;
    }

    const groupedByFile: Record<string, Finding[]> = {};
    findings.forEach((finding) => {
        if (!groupedByFile[finding.file]) {
            groupedByFile[finding.file] = [];
        }
        groupedByFile[finding.file].push(finding);
    });

    return (
        <div>
            <ScanSummaryPanel summary={summary} />

            <section>
                <div className="mb-5 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                    <div>
                        <h2 className="text-2xl font-bold tracking-tight text-slate-950">Security Findings</h2>
                        <p className="mt-1 text-sm text-slate-600">
                            Findings are grouped by file and sorted by severity.
                        </p>
                    </div>
                    <p className="text-sm font-medium text-slate-500">
                        {findings.length} issue{findings.length !== 1 ? "s" : ""} found
                    </p>
                </div>

                <div className="space-y-8">
                    {Object.entries(groupedByFile).map(([file, fileFindings]) => (
                        <div key={file}>
                            <div className="mb-3 flex items-center justify-between gap-4">
                                <h3 className="min-w-0 flex-1 truncate text-base font-semibold text-slate-900">
                                    {file}
                                </h3>
                                <span className="shrink-0 rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-600">
                                    {fileFindings.length} issue{fileFindings.length !== 1 ? "s" : ""}
                                </span>
                            </div>

                            <div className="ml-0 space-y-3 border-l border-slate-200 pl-4 sm:ml-3 sm:pl-5">
                                {fileFindings.map((finding, idx) => {
                                    const key = findingKey(finding, idx);
                                    const explanation = explanations[key];
                                    const isLoading = loadingExplanations[key];
                                    const isOpen = openExplanations[key];
                                    const error = explanationErrors[key];
                                    const hasError = Boolean(error);

                                    return (
                                        <article
                                            key={key}
                                            className={`rounded-lg border-l-4 bg-white p-5 shadow-sm ring-1 ring-slate-200 ${SEVERITY_ACCENT[finding.severity]}`}
                                        >
                                            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                                                <div>
                                                    <div className="mb-2 flex flex-wrap items-center gap-2">
                                                        <span
                                                            className={`rounded-full px-2.5 py-1 text-xs font-bold uppercase tracking-wide ring-1 ${SEVERITY_BADGE[finding.severity]}`}
                                                        >
                                                            {finding.severity}
                                                        </span>
                                                        <span className="text-xs font-medium text-slate-500">
                                                            {finding.file}:{finding.line}
                                                        </span>
                                                        <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600">
                                                            {finding.file_context ?? "Production code"}
                                                        </span>
                                                    </div>
                                                    <h4 className="text-base font-semibold text-slate-950">
                                                        {finding.title}
                                                    </h4>
                                                </div>
                                                <div className="flex flex-col gap-2">
                                                    <button
                                                        type="button"
                                                        onClick={() => handleExplain(finding, key)}
                                                        disabled={isLoading}
                                                        className="inline-flex h-9 items-center justify-center rounded-md border border-slate-700 bg-slate-950 px-3 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-900 hover:shadow disabled:cursor-not-allowed disabled:border-slate-400 disabled:bg-slate-400"
                                                    >
                                                        {isLoading
                                                            ? "Explaining..."
                                                            : hasError
                                                                ? "Try Again"
                                                                : explanation
                                                                    ? "Regenerate"
                                                                    : "Explain"}
                                                    </button>
                                                    {hasError && (
                                                        <p className="text-xs text-red-600 flex items-center gap-1">
                                                            ⚠ {error}
                                                        </p>
                                                    )}
                                                </div>
                                            </div>

                                            <div className="mt-4 rounded-lg bg-slate-950 p-4 text-sm text-slate-100">
                                                <code className="block overflow-x-auto whitespace-pre-wrap break-words font-mono">
                                                    {finding.evidence}
                                                </code>
                                            </div>

                                            <div className="mt-4 rounded-md bg-slate-50 p-3 text-sm text-slate-700">
                                                <p className="font-semibold text-slate-900">Fix recommendation</p>
                                                <div className="mt-1">
                                                    <MarkdownContent content={normalizeExplanation(finding.recommendation)} />
                                                </div>
                                            </div>

                                            {isOpen && (
                                                <div className="mt-4 rounded-md bg-blue-50 p-4 text-sm text-slate-800 ring-1 ring-blue-100">
                                                    <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                                                        <h5 className="font-semibold text-slate-950">
                                                            AI Explanation
                                                        </h5>
                                                        <p className="text-xs font-medium text-slate-500">
                                                            AI explanation only — detection is rule-based
                                                        </p>
                                                    </div>

                                                    {isLoading && (
                                                        <p className="text-slate-600">Generating explanation...</p>
                                                    )}

                                                    {explanation && (
                                                        <div className="space-y-4">
                                                            <div>
                                                                <p className="font-semibold text-slate-900">
                                                                    Why this is dangerous
                                                                </p>
                                                                <div className="mt-1">
                                                                    <MarkdownContent
                                                                        content={normalizeExplanation(explanation.explanation)}
                                                                    />
                                                                </div>
                                                            </div>
                                                            {explanation.attack_scenario && (
                                                                <div>
                                                                    <p className="font-semibold text-slate-900">
                                                                        Attack scenario
                                                                    </p>
                                                                    <div className="mt-1">
                                                                        <MarkdownContent
                                                                            content={normalizeExplanation(explanation.attack_scenario)}
                                                                        />
                                                                    </div>
                                                                </div>
                                                            )}
                                                            {explanation.fix_details && (
                                                                <div>
                                                                    <p className="font-semibold text-slate-900">
                                                                        How to fix it
                                                                    </p>
                                                                    <div className="mt-1">
                                                                        <MarkdownContent
                                                                            content={normalizeExplanation(explanation.fix_details)}
                                                                        />
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </article>
                                    );
                                })}
                            </div>
                        </div>
                    ))}
                </div>
            </section>
        </div>
    );
}
